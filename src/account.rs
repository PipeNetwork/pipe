use crate::auth::ControlClient;
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub async fn account(client: &ControlClient) -> Result<Value> {
    client.require_login()?;
    client.get("/v1/customer/cli/account").await
}

pub async fn usage(client: &ControlClient, from: Option<u64>, to: Option<u64>) -> Result<Value> {
    client.require_login()?;
    let mut path = String::from("/v1/customer/cli/usage");
    let mut query = Vec::new();
    if let Some(value) = from {
        query.push(format!("from={value}"));
    }
    if let Some(value) = to {
        query.push(format!("to={value}"));
    }
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query.join("&"));
    }
    client.get(&path).await
}

pub async fn credentials(client: &ControlClient) -> Result<Value> {
    client.require_login()?;
    client.get("/v1/customer/cli/s3/credentials").await
}

/// Return the buckets visible to the authenticated customer account. The
/// control plane owns this inventory because the public S3 gateway intentionally
/// does not implement the global ListBuckets wire operation.
pub async fn storage_buckets(client: &ControlClient) -> Result<Value> {
    client.require_login()?;
    if std::env::var_os("PIPE_CLI_TOKEN").is_some()
        || client
            .session()?
            .is_some_and(|session| session.access_token.starts_with("pcli_a_"))
    {
        // This deployed inventory includes historical namespaces and managed
        // buckets. Platform sessions do not need the unshipped legacy route.
        return managed_storage_buckets(client).await;
    }
    // The managed workspace is the canonical account inventory for new
    // buckets. The compatibility inventory retains legacy S3 namespaces, so
    // merge both views for users migrating from the storage-only CLI.
    let managed = managed_storage_buckets(client).await;
    let legacy = client.get("/v1/customer/cli/s3/buckets?limit=100").await;

    match (managed, legacy) {
        (Ok(managed), Ok(legacy)) => merge_bucket_inventories(&managed, &legacy),
        (Ok(managed), Err(error)) if optional_inventory_error(&error) => Ok(managed),
        (Err(error), Ok(legacy)) if optional_inventory_error(&error) => Ok(legacy),
        (Err(managed), Err(legacy)) if optional_inventory_error(&legacy) => Err(managed),
        // Legacy enumeration is additive. A scoped platform credential may
        // be allowed to read managed buckets while the compatibility route is
        // unavailable or outside its grant.
        (Ok(managed), Err(_legacy)) => Ok(managed),
        (Err(managed), Ok(_legacy)) => Err(managed.context("managed bucket inventory")),
        (Err(managed), Err(legacy)) => Err(managed.context(format!(
            "managed and legacy bucket inventories failed: {legacy}"
        ))),
    }
}

async fn managed_storage_buckets(client: &ControlClient) -> Result<Value> {
    let mut items = Vec::new();
    let mut after: Option<String> = None;
    let mut pages = 0usize;
    loop {
        let path = match &after {
            Some(cursor) => format!("/v1/customer/storage/buckets?limit=100&after={cursor}"),
            None => "/v1/customer/storage/buckets?limit=100".to_owned(),
        };
        let value = client.get(&path).await?;
        if value["available"].as_bool() == Some(false) {
            return Ok(value);
        }
        let page = value["items"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("storage bucket inventory omitted items"))?;
        items.extend(page.iter().cloned());
        let next = value["next_cursor"].as_str().map(str::to_owned);
        if next.is_none() {
            return Ok(serde_json::json!({
                "available": true,
                "items": items,
                "next_cursor": null
            }));
        }
        anyhow::ensure!(pages < 100, "storage bucket inventory exceeded 100 pages");
        anyhow::ensure!(
            next != after,
            "storage bucket inventory repeated its cursor"
        );
        after = next;
        pages += 1;
    }
}

fn optional_inventory_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<crate::error::ApiError>()
        .is_some_and(|api| {
            matches!(
                api.status,
                reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::SERVICE_UNAVAILABLE
            )
        })
}

fn merge_bucket_inventories(managed: &Value, legacy: &Value) -> Result<Value> {
    let managed_available = managed["available"].as_bool().unwrap_or(false);
    let legacy_available = legacy["available"].as_bool().unwrap_or(false);
    if !managed_available && !legacy_available {
        return Ok(json!({"available": false, "items": [], "next_cursor": null}));
    }
    let mut by_name = BTreeMap::<String, Value>::new();
    for inventory in [managed, legacy] {
        if inventory["available"].as_bool() == Some(false) {
            continue;
        }
        let page = inventory["items"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("bucket inventory omitted items"))?;
        for item in page {
            let name = item["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("bucket inventory item omitted name"))?;
            by_name
                .entry(name.to_owned())
                .or_insert_with(|| item.clone());
        }
    }
    Ok(json!({
        "available": true,
        "items": by_name.into_values().collect::<Vec<_>>(),
        "next_cursor": null
    }))
}

pub async fn create_credential(
    client: &ControlClient,
    wallet: &str,
    label: &str,
    buckets: &[String],
    prefix: &str,
    permissions: &[String],
    expires_at: Option<u64>,
) -> Result<Value> {
    client.authorize_storage_writes(false).await?;
    let mut body = json!({"wallet":wallet,"label":label,"buckets":buckets,"key_prefix":prefix,"permissions":permissions});
    if let Some(value) = expires_at {
        body["expires_at"] = json!(value);
    }
    client.post("/v1/customer/cli/s3/credentials", body).await
}

/// Request a short-lived read/list-only storage session used for automatic
/// onboarding of interactive CLI reads. The control plane never treats this
/// as a long-lived credential-management grant.
pub async fn create_storage_session(
    client: &ControlClient,
    wallet: &str,
    label: &str,
    buckets: &[String],
    prefix: &str,
    expires_at: Option<u64>,
) -> Result<Value> {
    let mut body = json!({
        "wallet": wallet,
        "label": label,
        "buckets": buckets,
        "key_prefix": prefix,
        "permissions": ["read", "list"]
    });
    if let Some(value) = expires_at {
        body["expires_at"] = json!(value);
    }
    match client
        .post("/v1/customer/cli/s3/session", body.clone())
        .await
    {
        Ok(value) => Ok(value),
        Err(error)
            if error
                .downcast_ref::<crate::error::ApiError>()
                .is_some_and(|api| api.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            // RC2 control planes do not know the additive session route yet.
            // The same body is bounded to read/list and seven days, so the
            // preserved customer credential route remains a safe compatibility
            // fallback during a rolling backend deployment.
            client.post("/v1/customer/cli/s3/credentials", body).await
        }
        Err(error) => Err(error),
    }
}

pub async fn revoke_credential(client: &ControlClient, access_key_id: &str) -> Result<Value> {
    client.authorize_storage_writes(false).await?;
    client
        .delete(&format!("/v1/customer/cli/s3/credentials/{access_key_id}"))
        .await
}

pub async fn endpoint(client: &ControlClient) -> Result<Value> {
    client.require_login()?;
    client.get("/v1/customer/cli/s3/endpoint").await
}

#[cfg(test)]
mod tests {
    use super::merge_bucket_inventories;
    use serde_json::{json, Value};

    #[test]
    fn bucket_inventory_merges_managed_and_legacy_namespaces() {
        let merged = merge_bucket_inventories(
            &json!({
                "available": true,
                "items": [
                    {"id": "managed-id", "name": "pipe-bucket-new"},
                    {"name": "shared"}
                ]
            }),
            &json!({
                "available": true,
                "items": [{"name": "legacy"}, {"name": "shared"}]
            }),
        )
        .unwrap();
        assert_eq!(
            merged["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["legacy", "pipe-bucket-new", "shared"]
        );
        assert_eq!(merged["items"][2]["id"], Value::Null);
    }

    #[test]
    fn unavailable_managed_inventory_does_not_hide_legacy_buckets() {
        let merged = merge_bucket_inventories(
            &json!({"available": false, "items": []}),
            &json!({"available": true, "items": [{"name": "legacy"}]}),
        )
        .unwrap();
        assert_eq!(merged["items"][0]["name"], "legacy");
    }
}

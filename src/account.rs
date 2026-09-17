use crate::auth::ControlClient;
use anyhow::Result;
use serde_json::{json, Value};

pub async fn account(client: &ControlClient) -> Result<Value> {
    client.get("/v1/customer/cli/account").await
}

pub async fn usage(client: &ControlClient, from: Option<u64>, to: Option<u64>) -> Result<Value> {
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
    client.get("/v1/customer/cli/s3/credentials").await
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
    client.get("/v1/customer/cli/s3/endpoint").await
}

//! Reviewed REST discovery; invocation accepts stable operation IDs, never URLs.
use crate::{auth::ControlClient, output};
use anyhow::{anyhow, ensure, Result};
use clap::Subcommand;
use serde_json::{json, Value};
use std::sync::OnceLock;
const CONTRACT: &str = include_str!("../contracts/platform-draft/control-plane.json");
const STORAGE: &str = include_str!("../contracts/openapi/storage.json");
const S3: &str = include_str!("../contracts/openapi/s3.json");
const COVERAGE: &str = include_str!("../contracts/coverage.json");
fn spec() -> &'static Value {
    static S: OnceLock<Value> = OnceLock::new();
    S.get_or_init(|| serde_json::from_str(CONTRACT).expect("pinned contract"))
}
fn storage_spec() -> &'static Value {
    static S: OnceLock<Value> = OnceLock::new();
    S.get_or_init(|| serde_json::from_str(STORAGE).expect("pinned storage contract"))
}
fn s3_spec() -> &'static Value {
    static S: OnceLock<Value> = OnceLock::new();
    S.get_or_init(|| serde_json::from_str(S3).expect("pinned S3 contract"))
}
fn document(id: &str) -> &'static Value {
    if id.starts_with("storage.") {
        storage_spec()
    } else {
        spec()
    }
}
fn disposition(id: &str) -> Option<&'static Value> {
    static C: OnceLock<Value> = OnceLock::new();
    C.get_or_init(|| serde_json::from_str(COVERAGE).expect("coverage"))["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["operation_id"] == id)
}
#[derive(Subcommand, Debug)]
pub enum ApiCommands {
    List,
    Describe {
        operation: String,
    },
    Call {
        operation: String,
        #[arg(long = "path")]
        paths: Vec<String>,
        #[arg(long = "query")]
        query: Vec<String>,
    },
}
pub(crate) fn operation(id: &str) -> Result<(&str, &str, &Value)> {
    for (path, item) in document(id)["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            if op["operationId"] == id {
                return Ok((path, method, op));
            }
        }
    }
    if let Some(op) = s3_spec()["x-pipe-s3-operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["operationId"] == id)
    {
        return Ok((
            op["path"].as_str().unwrap_or("/s3/{bucket}/{key}"),
            op["method"].as_str().unwrap(),
            op,
        ));
    }
    Err(anyhow!("unknown operation ID"))
}
fn eligible(id: &str) -> bool {
    disposition(id).is_some_and(|v| {
        (v["disposition"] == "advanced" || v["advanced_access"] == true)
            && v["implementation_status"] == "implemented"
    })
}
pub(crate) fn validate(schema: &Value, value: &Value) -> Result<()> {
    validate_in(spec(), schema, value)
}
fn validate_in(document: &Value, schema: &Value, value: &Value) -> Result<()> {
    let mut root = document.clone();
    root.as_object_mut().unwrap().remove("paths");
    root["$ref"] = json!("#/request");
    root["request"] = schema.clone();
    let validator =
        jsonschema::validator_for(&root).map_err(|_| anyhow!("invalid pinned request schema"))?;
    ensure!(
        validator.is_valid(value),
        "argument does not match the pinned contract"
    );
    Ok(())
}
pub(crate) fn validate_response(id: &str, status: &str, value: &Value) -> Result<()> {
    let (_, _, op) = operation(id)?;
    let schema = &op["responses"][status]["content"]["application/json"]["schema"];
    ensure!(
        !schema.is_null(),
        "missing response schema in pinned contract"
    );
    validate_in(document(id), schema, value)
        .map_err(|_| anyhow!("response does not match the pinned {id} contract"))
}
fn pairs(items: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    let mut result = std::collections::BTreeMap::new();
    for item in items {
        let (k, v) = item
            .split_once('=')
            .ok_or_else(|| anyhow!("expected NAME=VALUE"))?;
        ensure!(
            result.insert(k.into(), v.into()).is_none(),
            "duplicate parameter"
        );
    }
    Ok(result)
}
fn build(id: &str, paths: &[String], query: &[String]) -> Result<String> {
    let (template, method, op) = operation(id)?;
    ensure!(method=="get" && eligible(id),"operation requires a managed workflow or is unavailable in this client; see pipe api describe");
    let mut path = template.to_owned();
    let mut paths = pairs(paths)?;
    let mut query = pairs(query)?;
    let mut encoded = Vec::new();
    for p in op["parameters"].as_array().into_iter().flatten() {
        let name = p["name"]
            .as_str()
            .ok_or_else(|| anyhow!("invalid contract parameter"))?;
        let location = p["in"].as_str().unwrap_or("");
        let value = match location {
            "path" => paths.remove(name),
            "query" => query.remove(name),
            _ => None,
        };
        if let Some(value) = value {
            let typed = if p["schema"]["type"] == "integer" {
                serde_json::from_str::<Value>(&value)
                    .map_err(|_| anyhow!("invalid integer parameter"))?
            } else {
                json!(value)
            };
            validate_in(document(id), &p["schema"], &typed)?;
            if name == "limit" {
                ensure!(
                    typed.as_u64().is_some_and(|v| (1..=100).contains(&v)),
                    "limit must be between 1 and 100"
                );
            }
            if location == "path" {
                ensure!(value != "." && value != "..", "invalid resource identifier");
                let escaped = percent_encoding::utf8_percent_encode(
                    &value,
                    percent_encoding::NON_ALPHANUMERIC,
                )
                .to_string();
                path = path.replace(&format!("{{{name}}}"), &escaped);
            } else {
                encoded.push((name.to_owned(), value));
            }
        } else {
            ensure!(
                p["required"] != true || location == "header",
                "missing required {name}"
            );
        }
    }
    ensure!(paths.is_empty() && query.is_empty(), "unknown parameter");
    let mut url = reqwest::Url::parse("https://contract.invalid")?;
    url.set_path(&path);
    url.query_pairs_mut().extend_pairs(encoded);
    Ok(format!(
        "{}{}",
        url.path(),
        url.query()
            .filter(|s| !s.is_empty())
            .map(|q| format!("?{q}"))
            .unwrap_or_default()
    ))
}
pub async fn api(client: &ControlClient, cmd: ApiCommands, json_output: bool) -> Result<()> {
    let durable_result = matches!(&cmd, ApiCommands::Call { operation, .. }
        if operation == "getCustomerDurableOperation");
    let usage_result = matches!(&cmd, ApiCommands::Call { operation, .. } if operation == "platform.billing.account_usage" || operation == "platform.billing.org_usage");
    let value = match cmd {
        ApiCommands::List => {
            let mut items = Vec::new();
            let coverage: Value = serde_json::from_str(COVERAGE)?;
            for row in coverage["operations"].as_array().unwrap() {
                let id = row["operation_id"].as_str().unwrap();
                let (_, _, op) = operation(id)?;
                items.push(json!({"operation_id":id,"service":row["service"],"eligible":eligible(id),"summary":op["summary"],"disposition":row["disposition"],"reason":row["reason"],"command":row["command"]}));
            }
            json!({"items":items})
        }
        ApiCommands::Describe { operation: id } => {
            let (path, method, op) = operation(&id)?;
            json!({"operation_id":id,"method":method,"path":path,"eligible":eligible(&id),"contract":op,"coverage":disposition(&id)})
        }
        ApiCommands::Call {
            operation: id,
            paths,
            query,
        } => {
            let path = build(&id, &paths, &query)?;
            let (_, _, op) = operation(&id)?;
            let anonymous = op["security"].as_array().is_some_and(|v| v.is_empty());
            let value = if id.starts_with("storage.") || anonymous {
                ensure!(
                    anonymous,
                    "native credential operations require a separate supported workflow"
                );
                let url = if id.starts_with("storage.") {
                    let endpoint = client
                        .profile
                        .s3_endpoint
                        .as_deref()
                        .unwrap_or("https://gw-001.pipedev.network");
                    crate::error::ensure_https(endpoint, "storage endpoint")?;
                    format!("{}{path}", endpoint.trim_end_matches('/'))
                } else {
                    client.url(&path)
                };
                // Public reads never forward a CLI, browser, wallet or operator token.
                let response = client
                    .http
                    .get(url)
                    .send()
                    .await
                    .map_err(|e| e.without_url())?;
                if response.status() != reqwest::StatusCode::OK {
                    return Err(crate::error::response_error(response).await);
                }
                serde_json::from_slice(
                    &crate::error::bounded_body(response, 16 * 1024 * 1024).await?,
                )?
            } else {
                client.get(&path).await?
            };
            validate_response(&id, "200", &value)?;
            value
        }
    };
    if durable_result {
        crate::durable::present(value, None, json_output)
    } else if usage_result {
        output::print_application(&value, json_output)
    } else {
        output::print(&value, json_output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unreviewed_writes_and_unexpected_parameters() {
        assert!(build("createTopup", &[], &[]).is_err());
        assert!(build("createComputeVm", &[], &[]).is_err());
        assert!(build("listComputeVms", &[], &["limit=101".into()]).is_err());
        assert!(build("listComputeVms", &[], &["url=https://evil.invalid".into()]).is_err());
        assert!(build("getComputeVm", &["id=..".into()], &[]).is_err());
        assert!(build("listComputeVms", &[], &["limit=10".into()]).is_ok());
        for id in [
            "storage.auth",
            "storage.put_cache",
            "storage.open_session",
            "storage.durable.namespace_info",
            "platform.phone.start_handler",
        ] {
            assert!(!eligible(id));
            assert!(build(id, &[], &[]).is_err());
        }
    }
    #[test]
    fn every_public_operation_remains_discoverable_with_a_disposition() {
        let coverage: Value = serde_json::from_str(COVERAGE).unwrap();
        for row in coverage["operations"].as_array().unwrap() {
            let id = row["operation_id"].as_str().unwrap();
            assert!(operation(id).is_ok(), "missing {id}");
            assert_eq!(disposition(id), Some(row));
        }
    }
    #[tokio::test]
    async fn public_reads_use_the_selected_service_without_credentials_or_redirects() {
        use crate::config::Profile;
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };
        let control = MockServer::start().await;
        let storage = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let mut profile = Profile::new(control.uri());
        profile.s3_endpoint = Some(storage.uri());
        let c = ControlClient::for_test(profile, root.path()).unwrap();
        Mock::given(method("GET"))
            .and(path("/healthz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status":"ok"})))
            .expect(1)
            .mount(&control)
            .await;
        Mock::given(method("GET")).and(path("/v1/whoami")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"ip":"127.0.0.1","port":12345,"observed":"127.0.0.1:12345","via_proxy":false}))).expect(1).mount(&storage).await;
        for id in ["control.health", "storage.whoami"] {
            api(
                &c,
                ApiCommands::Call {
                    operation: id.into(),
                    paths: vec![],
                    query: vec![],
                },
                true,
            )
            .await
            .unwrap();
        }
        Mock::given(method("GET"))
            .and(path("/v1/mesh"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/stolen", control.uri())),
            )
            .expect(1)
            .mount(&storage)
            .await;
        assert!(api(
            &c,
            ApiCommands::Call {
                operation: "storage.mesh".into(),
                paths: vec![],
                query: vec![]
            },
            true
        )
        .await
        .is_err());
        let requests = control.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        for r in requests
            .into_iter()
            .chain(storage.received_requests().await.unwrap())
        {
            assert!(!r.headers.contains_key("authorization"));
            assert!(!r.headers.contains_key("x-api-key"));
        }
    }
}

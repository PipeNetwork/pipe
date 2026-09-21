//! Offline validation of real CLI HTTP requests against a reviewed release.
//! Kept behind cfg(test); signing, transport and payments have no schema dependency.
use crate::{account, auth::ControlClient, config::Profile, payments};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::sync::OnceLock;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, Request, Respond, ResponseTemplate,
};

fn document() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| {
        serde_json::from_str(include_str!("../contracts/openapi/control-plane.json")).unwrap()
    })
}

pub(crate) fn s3_operation(request: &Request) -> String {
    static S3: OnceLock<Value> = OnceLock::new();
    let doc = S3.get_or_init(|| {
        serde_json::from_str(include_str!("../contracts/openapi/s3.json")).unwrap()
    });
    let path = request
        .url
        .path()
        .strip_prefix("/s3/")
        .unwrap_or(request.url.path().trim_start_matches('/'));
    let object = path.trim_end_matches('/').contains('/');
    let query: std::collections::BTreeMap<_, _> = request.url.query_pairs().collect();
    let variant = doc["x-pipe-s3-operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| {
            op["method"] == request.method.as_str()
                && (op["target"] == "object") == object
                && op["query_present"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|key| query.contains_key(key.as_str().unwrap()))
                && (op["range_header"] != true || request.headers.contains_key("range"))
        })
        .expect("CLI request is missing from the pinned S3 dispatch registry");
    assert!(request
        .headers
        .get("authorization")
        .is_some_and(|v| v.to_str().unwrap().starts_with("AWS4-HMAC-SHA256 ")));
    variant["operationId"].as_str().unwrap().to_owned()
}

fn operation(method: &str, path: &str) -> &'static Value {
    let segments: Vec<_> = path.split('/').collect();
    let (_, item) = document()["paths"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(template, _)| {
            let fields: Vec<_> = template.split('/').collect();
            fields.len() == segments.len()
                && fields
                    .iter()
                    .zip(&segments)
                    .all(|(a, b)| a == b || a.starts_with('{') && a.ends_with('}') && !b.is_empty())
        })
        .unwrap_or_else(|| panic!("undocumented CLI path {path}"));
    let op = &item[method.to_ascii_lowercase()];
    assert!(
        op.get("operationId").is_some(),
        "undocumented method {method} {path}"
    );
    op
}

fn validate(schema: &Value, value: &Value, label: &str) {
    let root = json!({"components": document()["components"], "allOf": [schema]});
    let validator = jsonschema::options().build(&root).unwrap();
    if let Some(error) = validator.iter_errors(value).next() {
        // Never print secret-bearing fixture bodies.
        panic!(
            "{label}: contract mismatch at {} (schema {})",
            error.instance_path(),
            error.schema_path()
        );
    };
}

pub(crate) fn validate_response(method: &str, path: &str, status: u16, value: &Value) {
    let op = operation(method, path);
    let response = &op["responses"][status.to_string()];
    assert!(
        !response.is_null(),
        "undocumented response {status} {method} {path}"
    );
    validate(
        response
            .pointer("/content/application~1json/schema")
            .expect("JSON response schema"),
        value,
        op["operationId"].as_str().unwrap(),
    );
}

struct ContractResponse {
    status: u16,
    body: Value,
}
impl Respond for ContractResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let op = operation(request.method.as_str(), request.url.path());
        if let Some(schema) = op.pointer("/requestBody/content/application~1json/schema") {
            let body = if request.body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&request.body).unwrap()
            };
            validate(schema, &body, "CLI request");
        }
        for parameter in op["parameters"].as_array().into_iter().flatten() {
            let name = parameter["name"].as_str().unwrap();
            let value = match parameter["in"].as_str().unwrap() {
                "header" => request
                    .headers
                    .get(name)
                    .map(|v| v.to_str().unwrap().to_owned()),
                "query" => request
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.into_owned()),
                _ => continue,
            };
            assert!(
                value.is_some() || parameter["required"] != true,
                "missing {name}"
            );
            if let Some(value) = value {
                let value = if parameter["schema"]["type"] == "integer" {
                    json!(value.parse::<i64>().unwrap())
                } else {
                    json!(value)
                };
                validate(&parameter["schema"], &value, "CLI parameter");
            }
        }
        if op["security"]
            .as_array()
            .is_some_and(|items| items.iter().any(|v| v.get("cliBearer").is_some()))
        {
            assert!(request
                .headers
                .get("authorization")
                .is_some_and(|v| v.to_str().unwrap().starts_with("Bearer ")));
        }
        validate_response(
            request.method.as_str(),
            request.url.path(),
            self.status,
            &self.body,
        );
        assert!(op["responses"][self.status.to_string()]["headers"]
            .get("x-request-id")
            .is_some());
        ResponseTemplate::new(self.status)
            .insert_header("x-request-id", "synthetic-contract-request")
            .set_body_json(&self.body)
    }
}

async fn mount(server: &MockServer, verb: &str, route: &str, value: Value) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ContractResponse {
            status: 200,
            body: value,
        })
        .up_to_n_times(1)
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn complete_customer_rest_requests_and_responses_use_pinned_contract() {
    let server = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let client = ControlClient::for_test(Profile::new(server.uri()), directory.path()).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let wallet = hex::encode(key.verifying_key().to_bytes());
    client
        .secrets
        .set("wallet_private_key", &hex::encode(key.to_bytes()))
        .unwrap();
    client.secrets.set("owner_wallet", &wallet).unwrap();
    let now = chrono::Utc::now().timestamp();
    let id = Uuid::new_v4();
    let challenge = Uuid::new_v4();
    let message=format!("Pipe Storage authorization\ndomain: pipe-cli\nmesh: {}\naction: cli_login\nowner: {wallet}\nnonce: {}\nissued_at: {now}\nexpires_at: {}\n",Uuid::new_v4(),"a".repeat(64),now+300);
    mount(&server,"POST","/v1/customer/cli/auth/challenge",json!({"challenge_id":challenge,"owner_wallet":wallet,"credit_wallet":null,"message":message,"issued_at":now,"expires_at":now+300})).await;
    let session = json!({"access_token":"a".repeat(64),"refresh_token":"b".repeat(128),"token_type":"Bearer","owner_wallet":wallet,"session_id":id,"expires_in":900,"refresh_expires_in":2592000});
    mount(
        &server,
        "POST",
        "/v1/customer/cli/auth/session",
        session.clone(),
    )
    .await;
    let login = client.login(None, None).await.unwrap();
    assert!(login.get("access_token").is_none() && login.get("refresh_token").is_none());
    mount(&server, "POST", "/v1/customer/cli/auth/refresh", session).await;
    client.refresh().await.unwrap();
    mount(&server,"GET","/v1/customer/cli/account",json!({"owner_wallet":wallet,"identities":[],"payments":[],"authentication":{"kind":"cli"}})).await;
    account::account(&client).await.unwrap();
    mount(&server,"GET","/v1/customer/cli/usage",json!({"from":1,"to":2,"items":[{"wallet":wallet,"operation":"read","bytes":"9007199254740993","atoms":"9007199254740993","events":1,"unmeasured_events":0}]})).await;
    let usage = account::usage(&client, Some(1), Some(2)).await.unwrap();
    assert_eq!(usage["items"][0]["atoms"], "9007199254740993");
    mount(&server,"GET","/v1/customer/cli/auth/sessions",json!({"items":[{"id":id,"client_version":"synthetic","device_label":"fixture","created_at":now,"last_used_at":now,"access_expires_at":now+900,"refresh_expires_at":now+2592000,"revoked":false,"current":true}]})).await;
    client.get("/v1/customer/cli/auth/sessions").await.unwrap();
    let route = format!("/v1/customer/cli/auth/sessions/{id}");
    mount(&server, "DELETE", &route, json!({"id":id,"revoked":true})).await;
    client.delete(&route).await.unwrap();
    mount(&server,"POST","/v1/customer/cli/s3/credentials",json!({"access_key_id":"LTTEST","secret_access_key":"synthetic-once","wallet":wallet,"buckets":["test"],"key_prefix":"","permissions":["read"],"created_at":now,"expires_at":null})).await;
    let created = account::create_credential(
        &client,
        &wallet,
        "fixture",
        &["test".into()],
        "",
        &["read".into()],
        None,
    )
    .await
    .unwrap();
    assert_eq!(created["secret_access_key"], "synthetic-once");
    mount(&server,"GET","/v1/customer/cli/s3/credentials",json!({"items":[{"access_key_id":"LTTEST","wallet":wallet,"label":"fixture","buckets":["test"],"key_prefix":"","permissions":["read"],"credential_key_id":"synthetic","created_at":now,"expires_at":null,"revoked_at":null,"last_used_at":null}]})).await;
    assert!(!account::credentials(&client)
        .await
        .unwrap()
        .to_string()
        .contains("synthetic-once"));
    mount(
        &server,
        "DELETE",
        "/v1/customer/cli/s3/credentials/LTTEST",
        json!({"access_key_id":"LTTEST","revoked":true}),
    )
    .await;
    account::revoke_credential(&client, "LTTEST").await.unwrap();
    mount(&server,"GET","/v1/customer/cli/s3/endpoint",json!({"endpoint":"https://gw-001.pipedev.network","region":"us-east-1","owner_wallet":wallet})).await;
    account::endpoint(&client).await.unwrap();
    Mock::given(method("GET"))
        .and(path("/v1/customer/cli/account"))
        .respond_with(ContractResponse {
            status: 500,
            body: json!({"code":"internal","message":"synthetic-secret-that-must-be-redacted"}),
        })
        .expect(1)
        .mount(&server)
        .await;
    let error = account::account(&client).await.unwrap_err().to_string();
    assert!(error.contains("synthetic-contract-request"));
    assert!(!error.contains("synthetic-secret-that-must-be-redacted"));
    mount(
        &server,
        "POST",
        "/v1/customer/cli/auth/logout",
        json!({"session_id":id,"owner_wallet":wallet,"revoked":true}),
    )
    .await;
    client.logout().await.unwrap();
}

pub(crate) fn invoice_fixture(id: Uuid, key: &SigningKey) -> Value {
    let mut invoice = crate::solana::tests::invoice(id, key, Some(4));
    let fields = json!({"payer":invoice["terms"]["payer"],"transaction":null,"network":invoice["terms"]["network"],"finalized_slot":null,"attempt_count":0,"last_error_class":null,"created_at":"2026-09-17 00:00:00+00","expires_at":"2026-09-17 00:10:00+00","finalized_at":null,"credited_at":null});
    invoice
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    validate_response("POST", "/v1/payments/wallet-topups", 200, &invoice);
    invoice
}

#[tokio::test]
async fn payment_discovery_invoice_recovery_and_signed_submission_match_contract() {
    let server = MockServer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let client = ControlClient::for_test(Profile::new(server.uri()), directory.path()).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let wallet = hex::encode(key.verifying_key().to_bytes());
    client
        .secrets
        .set("wallet_private_key", &hex::encode(key.to_bytes()))
        .unwrap();
    client.secrets.set("owner_wallet", &wallet).unwrap();
    mount(&server,"GET","/v1/payments/config",json!({"enabled":true,"methods":["solana_wallet"],"walletPayments":{"enabled":true,"acceptNew":true},"payTo":null,"network":null,"asset":null,"minTopupAtoms":null,"maxTopupAtoms":null,"health":{"reconciliationReady":true,"signedTerminal":true,"ledgerConsistent":true,"reviewOverdue":false,"discoveryCurrent":true}})).await;
    payments::config(&client).await.unwrap();
    let id = Uuid::new_v4();
    let invoice = invoice_fixture(id, &key);
    mount(
        &server,
        "POST",
        "/v1/payments/wallet-topups",
        invoice.clone(),
    )
    .await;
    payments::create(&client, 1_000_000, None, Some(Uuid::new_v4()))
        .await
        .unwrap();
    let route = format!("/v1/payments/topups/{id}");
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ContractResponse {
            status: 200,
            body: invoice.clone(),
        })
        .expect(2)
        .mount(&server)
        .await;
    payments::status(&client, &id.to_string()).await.unwrap();
    mount(
        &server,
        "POST",
        &format!("/v1/payments/wallet-topups/{id}/submit"),
        invoice,
    )
    .await;
    payments::pay(&client, &id.to_string()).await.unwrap();
    // The legacy x402 flow uses the same durable recovery key and actual 402 wire contract.
    let required = json!({"x402Version":2,"resource":{"url":"https://example.test/v1/payments/topups","description":"synthetic","mimeType":"application/json","serviceName":"Pipe Storage"},"accepts":[{"scheme":"exact","network":crate::solana::MAINNET,"asset":crate::solana::USDC,"amount":"1000000","payTo":crate::solana::USDC,"maxTimeoutSeconds":120,"extra":{"feePayer":crate::solana::USDC,"name":"USDC","version":"2","decimals":6,"memo":format!("pipe-credit:{}",Uuid::new_v4())}}]});
    Mock::given(method("POST"))
        .and(path("/v1/payments/topups"))
        .respond_with(ContractResponse {
            status: 402,
            body: required,
        })
        .expect(1)
        .mount(&server)
        .await;
    payments::create_x402(&client, 1_000_000, Some(Uuid::new_v4()))
        .await
        .unwrap();
}

#[test]
fn pinned_catalog_hashes_and_s3_dispatch_registry_are_local_and_complete() {
    use sha2::{Digest, Sha256};
    let catalog: Value =
        serde_json::from_str(include_str!("../contracts/openapi/index.json")).unwrap();
    for entry in catalog["documents"].as_array().unwrap() {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                "contracts/openapi/{}.json",
                entry["name"].as_str().unwrap()
            )),
        )
        .unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), entry["sha256"]);
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["x-pipe-source-revision"], catalog["source_revision"]);
    }
    let s3: Value = serde_json::from_str(include_str!("../contracts/openapi/s3.json")).unwrap();
    let registry = s3["x-pipe-s3-operations"].as_array().unwrap();
    assert_eq!(registry.len(), 16);
    assert!(s3["paths"]
        .as_object()
        .unwrap()
        .keys()
        .all(|p| !p.contains('?')));
    for operation in registry {
        assert!(s3["paths"][operation["path"].as_str().unwrap()]
            [operation["method"].as_str().unwrap().to_ascii_lowercase()]
        .get("operationId")
        .is_some());
    }
}

//! Run the actual binary across processes to cover profile selection, durable
//! secrets, command wiring and output, in addition to HTTP-client unit tests.
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Command, Output},
};
use uuid::Uuid;
use wiremock::{
    matchers::{body_partial_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn pipe(root: &Path, args: &[&str]) -> Output {
    pipe_format(root, args, &["--json"])
}

fn pipe_format(root: &Path, args: &[&str], format: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pipe"))
        .env("PIPE_DISABLE_KEYRING", "1")
        .env("PIPE_CLI_SECRET_PASSWORD", "executable-fixture-password")
        .env("PIPE_CLI_STATE_DIR", root.join("state"))
        .env("XDG_CONFIG_HOME", root)
        .env("APPDATA", root)
        .arg("--config")
        .arg(root.join("config.json"))
        .args(format)
        .args(args)
        .output()
        .unwrap()
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_wallet_to_storage_across_processes() {
    let root = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let base = server.uri();
    success(pipe(
        root.path(),
        &["profile", "create", "personal", "--control-api-url", &base],
    ));
    success(pipe(root.path(), &["profile", "use", "personal"]));
    let profiles = success(pipe(root.path(), &["profile", "list"]));
    assert_eq!(profiles["active"], "personal");
    let signing = SigningKey::from_bytes(&[7; 32]);
    let secret = hex::encode(signing.to_bytes());
    let wallet = hex::encode(signing.verifying_key().to_bytes());
    let wallet_file = root.path().join("wallet.json");
    std::fs::write(
        &wallet_file,
        serde_json::to_vec(&json!({"secret_key_hex":secret})).unwrap(),
    )
    .unwrap();
    let now = chrono::Utc::now().timestamp();
    let message = format!("Pipe Storage authorization\ndomain: pipe-cli\nmesh: {}\naction: cli_login\nowner: {wallet}\nnonce: {}\nissued_at: {now}\nexpires_at: {}\n",Uuid::new_v4(),"a".repeat(64),now+300);
    let challenge = Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path("/v1/customer/cli/auth/challenge"))
        .and(body_partial_json(json!({"wallet":wallet})))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"challenge_id":challenge,"owner_wallet":wallet,"message":message}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path("/v1/customer/cli/auth/session"))
        .and(body_partial_json(json!({"challenge_id":challenge,"signature":hex::encode(signing.sign(message.as_bytes()).to_bytes())})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"a".repeat(64),"refresh_token":"r".repeat(128),"token_type":"Bearer","owner_wallet":wallet,"session_id":Uuid::new_v4(),"expires_in":900,"refresh_expires_in":2592000})))
        .expect(1).mount(&server).await;
    let login = pipe(
        root.path(),
        &[
            "auth",
            "login",
            "--legacy-wallet",
            "--wallet",
            wallet_file.to_str().unwrap(),
        ],
    );
    assert!(!String::from_utf8_lossy(&login.stdout).contains(&secret));
    assert!(!String::from_utf8_lossy(&login.stderr).contains(&secret));
    assert_eq!(success(login)["owner_wallet"], wallet);
    Mock::given(method("POST"))
        .and(path("/v1/customer/cli/s3/credentials"))
        .and(header(
            "authorization",
            format!("Bearer {}", "a".repeat(64)),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"access_key_id":"LTTEST","secret_access_key":"test-s3-secret"}),
            ),
        )
        .expect(1)
        .mount(&server)
        .await;
    let created = success(pipe(
        root.path(),
        &[
            "s3",
            "credential",
            "create",
            "--bucket",
            "bucket",
            "--show-secret",
        ],
    ));
    assert_eq!(created["secret_access_key"], "test-s3-secret");
    Mock::given(method("GET")).and(path("/v1/customer/cli/s3/credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items":[{"access_key_id":"LTTEST","secret_access_key":"must-redact"}],"refresh_token":"must-redact"})))
        .mount(&server).await;
    let listed = success(pipe(root.path(), &["s3", "credential", "list"]));
    assert!(!listed.to_string().contains("must-redact"));
    Mock::given(method("GET"))
        .and(path("/v1/customer/cli/s3/endpoint"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"endpoint":base,"region":"us-east-1"})),
        )
        .mount(&server)
        .await;
    success(pipe(root.path(), &["s3", "endpoint"]));
    Mock::given(method("PUT"))
        .and(path("/bucket/key"))
        .and(header(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        ))
        .and(header("if-none-match", "*"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let input = root.path().join("input");
    std::fs::write(&input, b"hello").unwrap();
    success(pipe(
        root.path(),
        &[
            "object",
            "put",
            input.to_str().unwrap(),
            "bucket/key",
            "--if-none-match",
            "*",
        ],
    ));
    Mock::given(method("GET"))
        .and(path("/bucket/key"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "opaque-etag")
                .set_body_bytes(b"hello".to_vec()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let output = root.path().join("output");
    success(pipe(
        root.path(),
        &["object", "get", "bucket/key", output.to_str().unwrap()],
    ));
    assert_eq!(std::fs::read(output).unwrap(), b"hello");
    for (verb, status, s3_code, code, exit) in [
        ("delete", 403, "AccessDenied", "authorization", 4),
        ("put", 412, "PreconditionFailed", "conflict", 6),
        ("put", 402, "HttpError", "payment_required", 1),
        ("put", 503, "ServiceUnavailable", "unknown_outcome", 8),
    ] {
        let key = format!("/bucket/error-{status}");
        Mock::given(method(if verb == "delete" { "DELETE" } else { "PUT" }))
            .and(path(&key))
            .respond_with(ResponseTemplate::new(status).set_body_string(format!(
                "<Error><Code>{s3_code}</Code><Message>test-s3-secret</Message></Error>"
            )))
            .expect(3)
            .mount(&server)
            .await;
        let remote = key.trim_start_matches('/');
        let args = if verb == "delete" {
            vec!["--yes", "storage", "object", "delete", remote]
        } else {
            vec!["storage", "object", "put", input.to_str().unwrap(), remote]
        };
        for mode in ["json", "jsonl", "table"] {
            let failure = pipe_format(root.path(), &args, &["--output", mode]);
            assert_eq!(failure.status.code(), Some(exit));
            let stderr = String::from_utf8_lossy(&failure.stderr);
            assert!(stderr.contains(&status.to_string()));
            if exit == 8 {
                assert!(stderr.contains("S3 mutation outcome is unknown"));
                assert!(stderr.contains("reconcile the original operation"));
            }
            assert!(!stderr.contains("test-s3-secret"));
            assert!(!String::from_utf8_lossy(&failure.stdout).contains("test-s3-secret"));
            if mode == "table" {
                assert!(failure.stdout.is_empty());
            } else {
                let document: Value = serde_json::from_slice(&failure.stdout).unwrap();
                assert_eq!(document["schema_version"], 1);
                assert_eq!(document["result"]["error"]["code"], code);
                assert_eq!(document["result"]["error"]["http_status"], status);
                assert_eq!(document["result"]["error"]["s3_code"], s3_code);
                assert!(document["result"]["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains(&status.to_string()));
                if exit == 8 {
                    assert!(document["result"]["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("S3 mutation outcome is unknown"));
                }
                if mode == "jsonl" {
                    assert_eq!(String::from_utf8_lossy(&failure.stdout).lines().count(), 1);
                }
            }
        }
    }
    let rejected = pipe(root.path(), &["new-user", "legacy"]);
    assert!(!rejected.status.success());
}

#[test]
fn executable_rejects_insecure_or_credential_bearing_endpoints() {
    let root = tempfile::tempdir().unwrap();
    for endpoint in [
        "http://example.test",
        "https://user:secret@example.test",
        "https://example.test?token=secret",
    ] {
        let result = pipe(
            root.path(),
            &["profile", "create", "bad", "--control-api-url", endpoint],
        );
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stdout).contains("user:secret"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn executable_browser_login_encrypts_secrets() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    success(pipe(
        root.path(),
        &[
            "profile",
            "create",
            "test",
            "--control-api-url",
            &server.uri(),
        ],
    ));
    success(pipe(root.path(), &["profile", "use", "test"]));
    Mock::given(method("POST")).and(path("/v1/cli/auth/device"))
        .and(header("content-type","application/x-www-form-urlencoded"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"device_code":"pcli_d_test","user_code":"BCDFG-HJKLM","verification_uri":"https://pipe.network/cli/authorize","verification_uri_complete":"https://pipe.network/cli/authorize?user_code=BCDFG-HJKLM","expires_in":600,"interval":5}))).expect(1).mount(&server).await;
    Mock::given(method("POST")).and(path("/v1/cli/auth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":format!("pcli_a_{}","a".repeat(64)),"refresh_token":format!("pcli_r_{}","b".repeat(128)),"token_type":"Bearer","scope":"account.read billing.read compute.read durable.read hosting.read kv.read org.read storage.read usage.read","account_id":null,"owner_wallet":"c".repeat(64),"session_id":Uuid::new_v4(),"expires_in":900,"refresh_expires_in":2592000}))).expect(1).mount(&server).await;
    let result = pipe(root.path(), &["auth", "login", "--no-browser"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("pcli_a_"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("pcli_r_"));
    Mock::given(method("GET"))
        .and(path("/v1/compute/vms"))
        .and(header(
            "authorization",
            format!("Bearer pcli_a_{}", "a".repeat(64)),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"vms":[],"next_cursor":null,"features":features()})),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        success(pipe(root.path(), &["compute", "vms", "list"]))["vms"],
        json!([])
    );
    let bytes = std::fs::read(root.path().join("state/secrets.json")).unwrap();
    assert!(bytes.starts_with(b"PIPESEC3"));
    assert!(!bytes.windows(7).any(|b| b == b"pcli_a_"));
}

#[test]
fn executable_output_and_unavailable_secret_store_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pipe"))
        .arg("--config")
        .arg(root.path().join("config.json"))
        .args(["--output", "json", "profile", "list"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["schema_version"], 1);
    assert!(doc["result"].is_object());
    let output = Command::new(env!("CARGO_BIN_EXE_pipe"))
        .env("PIPE_DISABLE_KEYRING", "1")
        .env_remove("PIPE_CLI_SECRET_PASSWORD")
        .env("PIPE_CLI_STATE_DIR", root.path().join("secrets"))
        .arg("--config")
        .arg(root.path().join("config.json"))
        .args(["auth", "login", "--no-browser", "--no-input"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!root.path().join("secrets/secrets.json").exists());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("explicitly select encrypted fallback")
    );
}

fn features() -> Value {
    json!({"stage":"test","customer_launch_ready":false,"billing":"test","inference_mode":"external","hi_image_support":false,"disk_encryption":false,"tenant_network_isolation":false,"backups":false,"delete_destroys_disk":true})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_compute_confirmation_and_unknown_outcome_are_recoverable() {
    let root = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    success(pipe(
        root.path(),
        &[
            "profile",
            "create",
            "fixture",
            "--control-api-url",
            &server.uri(),
        ],
    ));
    success(pipe(root.path(), &["profile", "use", "fixture"]));
    let vm = Uuid::new_v4().to_string();
    let request = Uuid::new_v4().to_string();
    Mock::given(path(format!("/v1/compute/vms/{vm}")))
        .respond_with(ResponseTemplate::new(503))
        .expect(0)
        .mount(&server)
        .await;
    let denied = pipe(
        root.path(),
        &["compute", "vms", "delete", &vm, "--no-input"],
    );
    assert!(!denied.status.success());
    Mock::given(path("/v1/cli/context")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"principal":{"owner_wallet":"owner","account_id":null,"credential_id":Uuid::nil(),"credential_kind":"session","account_access":true,"organizations":[],"resources":[],"scopes":["compute.write"]},"contexts":[],"storage":{"endpoint":"https://gw-001.pipedev.network","region":"us-east-1"}}))).mount(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/compute/vms/{vm}/start")))
        .and(header("idempotency-key", &request))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let unknown = pipe(
        root.path(),
        &[
            "compute",
            "vms",
            "start",
            &vm,
            "--request-id",
            &request,
            "--no-input",
            "--output",
            "json",
        ],
    );
    assert_eq!(unknown.status.code(), Some(8));
    let document: Value = serde_json::from_slice(&unknown.stdout).unwrap();
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["result"]["error"]["code"], "unknown_outcome");
    assert!(document["result"]["error"]["message"]
        .as_str()
        .unwrap()
        .contains(&request));
    let journal = success(pipe(root.path(), &["compute", "requests"]));
    assert_eq!(journal["requests"][&request]["state"], "unknown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_platform_wallet_validates_signature_and_grants() {
    let root = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    success(pipe(
        root.path(),
        &[
            "profile",
            "create",
            "personal",
            "--control-api-url",
            &server.uri(),
        ],
    ));
    success(pipe(root.path(), &["profile", "use", "personal"]));
    let key = SigningKey::from_bytes(&[9; 32]);
    let owner = hex::encode(key.verifying_key().to_bytes());
    let file = root.path().join("wallet.json");
    std::fs::write(
        &file,
        json!({"secret_key_hex":hex::encode(key.to_bytes())}).to_string(),
    )
    .unwrap();
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    let scope = "compute.read compute.write";
    let message = format!("Pipe Platform authorization\ndomain: pipe-cli-v3\nmesh: {}\naction: wallet_login\nowner: {owner}\naccount: null\nscopes: {scope}\nclient: pipe-cli\ndevice: \"Pipe CLI\"\nnonce: {}\nissued_at: {now}\nexpires_at: {}\n",Uuid::new_v4(),"b".repeat(64),now+300);
    Mock::given(method("POST")).and(path("/v1/cli/auth/wallet/challenge"))
        .and(body_partial_json(json!({"wallet":owner,"scope":scope,"device_label":"Pipe CLI"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"challenge_id":id,"owner_wallet":owner,"account_id":null,"scope":scope,"message":message,"issued_at":now,"expires_at":now+300})))
        .expect(1).mount(&server).await;
    Mock::given(method("POST")).and(path("/v1/cli/auth/wallet/session"))
        .and(body_partial_json(json!({"challenge_id":id,"signature":hex::encode(key.sign(message.as_bytes()).to_bytes())})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":format!("pcli_a_{}","a".repeat(64)),"refresh_token":format!("pcli_r_{}","b".repeat(128)),"token_type":"Bearer","session_id":Uuid::new_v4(),"owner_wallet":owner,"account_id":null,"scope":scope,"expires_in":900,"refresh_expires_in":2592000})))
        .expect(1).mount(&server).await;
    let value = success(pipe(
        root.path(),
        &[
            "auth",
            "login",
            "--wallet",
            file.to_str().unwrap(),
            "--scope",
            scope,
        ],
    ));
    assert_eq!(value["owner_wallet"], owner);
    assert_eq!(value["scope"], scope);
    assert!(!value.to_string().contains("pcli_"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advanced_durable_results_preserve_application_fields_and_failure_status() {
    let root = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    success(pipe(
        root.path(),
        &[
            "profile",
            "create",
            "durable",
            "--control-api-url",
            &server.uri(),
        ],
    ));
    success(pipe(root.path(), &["profile", "use", "durable"]));
    let id = Uuid::new_v4();
    let result = json!({"secret":"application-field","token":null,"n":9007199254740993u64});
    Mock::given(method("GET")).and(move |r: &wiremock::Request| percent_encoding::percent_decode_str(r.url.path()).decode_utf8_lossy() == format!("/v1/customer/durable/requests/{id}"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"operation_id":id,"status":"complete","charge_atoms":"2","response_expired":false,"response":{"sequence":1,"status":200,"checkpoint_bytes":4,"result":result}})))
        .expect(1).mount(&server).await;
    let out = pipe(
        root.path(),
        &[
            "api",
            "call",
            "getCustomerDurableOperation",
            "--path",
            &format!("id={id}"),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["response"]["result"], result);
    let id = Uuid::new_v4();
    Mock::given(method("GET")).and(move |r: &wiremock::Request| percent_encoding::percent_decode_str(r.url.path()).decode_utf8_lossy() == format!("/v1/customer/durable/requests/{id}"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"operation_id":id,"status":"complete","charge_atoms":"2","response_expired":true,"response":null})))
        .expect(1).mount(&server).await;
    let out = pipe(
        root.path(),
        &[
            "api",
            "call",
            "getCustomerDurableOperation",
            "--path",
            &format!("id={id}"),
        ],
    );
    assert_eq!(out.status.code(), Some(8));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "response_expired");
    assert_eq!(v["operation"]["operation_id"], id.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn executable_platform_usage_preserves_application_fields() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    success(pipe(
        root.path(),
        &[
            "profile",
            "create",
            "usage",
            "--control-api-url",
            &server.uri(),
        ],
    ));
    success(pipe(root.path(), &["profile", "use", "usage"]));
    let details = json!({"token":"provider accounting label","api_key":"application field","arbitrary":[null,9007199254740993u64,true]});
    let value = json!({"total_requests":1,"total_tokens_in":9007199254740993u64,"total_tokens_out":1,"total_cost":0.001,"cache":{"cached_input_tokens":0,"reported_requests":0,"reported_input_tokens":0},"records":[{"request_id":Uuid::new_v4().to_string(),"project_id":null,"model":"fixture","tokens_in":9007199254740993u64,"tokens_out":1,"token_details":details,"cost":0.001,"provider_billed":true,"duration_ms":null,"created_at":"2026-09-17T00:00:00Z"}],"next_cursor":null,"groups_truncated":false});
    Mock::given(method("GET"))
        .and(path("/v1/usage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(value))
        .expect(2)
        .mount(&server)
        .await;
    for (args, advanced) in [
        (vec!["billing", "usage", "--output", "json"], false),
        (
            vec![
                "api",
                "call",
                "platform.billing.account_usage",
                "--output",
                "json",
            ],
            true,
        ),
    ] {
        let out = pipe(root.path(), &args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        let data = if advanced {
            &v["result"]
        } else {
            &v["result"]["data"]
        };
        assert_eq!(data["records"][0]["token_details"], details);
        assert_eq!(data["total_tokens_in"].as_u64(), Some(9007199254740993));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn executable_billing_json_bound_preserves_the_unemitted_page_cursor() {
    struct HistoryPages;
    impl wiremock::Respond for HistoryPages {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            let n = request
                .url
                .query_pairs()
                .find(|(k, _)| k == "cursor")
                .map(|(_, v)| {
                    Uuid::parse_str(v.split_once('|').unwrap().1)
                        .unwrap()
                        .as_u128()
                        + 1
                })
                .unwrap_or(1);
            let id = Uuid::from_u128(n).to_string();
            ResponseTemplate::new(200).set_body_json(json!({"total_requests":30,"total_tokens_in":30,"total_tokens_out":0,"total_cost":0,"cache":{"cached_input_tokens":0,"reported_requests":0,"reported_input_tokens":0},"records":[{"request_id":id,"project_id":null,"model":"fixture","tokens_in":1,"tokens_out":0,"token_details":{"padding":"x".repeat(1_300_000)},"cost":0,"provider_billed":false,"duration_ms":null,"created_at":"2026-09-17T00:00:00Z"}],"next_cursor":format!("2026-09-17T00:00:00Z|{id}"),"groups_truncated":false}))
        }
    }
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    success(pipe(
        root.path(),
        &[
            "profile",
            "create",
            "bounded",
            "--control-api-url",
            &server.uri(),
        ],
    ));
    success(pipe(root.path(), &["profile", "use", "bounded"]));
    Mock::given(method("GET"))
        .and(path("/v1/usage"))
        .respond_with(HistoryPages)
        .mount(&server)
        .await;
    let out = pipe(
        root.path(),
        &[
            "billing", "usage", "--limit", "1", "--all", "--output", "json",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let pages = v["result"]["pages"].as_array().unwrap();
    assert!(!pages.is_empty() && pages.len() < 30);
    assert_eq!(v["result"]["truncated"], true);
    assert_eq!(
        v["result"]["next_cursor"],
        pages.last().unwrap()["next_cursor"]
    );
    assert!(serde_json::to_vec(pages).unwrap().len() <= 16 * 1024 * 1024);
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        pages.len() + 1,
        "the fetched but unemitted page must remain resumable"
    );
}

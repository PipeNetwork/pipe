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
    matchers::{body_partial_json, header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

fn pipe(root: &Path, args: &[&str]) -> Output {
    pipe_format(root, args, &["--json"])
}

fn pipe_format(root: &Path, args: &[&str], format: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pipe"))
        .current_dir(root)
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
        ("put", 403, "AccessDenied", "authorization", 4),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_headless_login_uses_private_machine_key_without_password() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let session_id = Uuid::new_v4();
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
    let run_headless = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pipe"))
            .current_dir(root.path())
            .env_remove("PIPE_DISABLE_KEYRING")
            .env_remove("PIPE_CLI_SECRET_PASSWORD")
            .env_remove("PIPE_CLI_TOKEN")
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("SSH_CONNECTION")
            .env_remove("SSH_TTY")
            .env("PIPE_CLI_STATE_DIR", root.path().join("state"))
            .env("XDG_CONFIG_HOME", root.path())
            .env("APPDATA", root.path())
            .arg("--config")
            .arg(root.path().join("config.json"))
            .arg("--json")
            .args(args)
            .output()
            .unwrap()
    };
    // An unsuccessful old login leaves no session. Do not send an anonymous
    // endpoint request, which production reports as a disabled legacy CLI 404.
    for args in [vec!["s3", "ls"], vec!["s3", "ls", "s3://test/"]] {
        let missing = run_headless(&args);
        assert_eq!(missing.status.code(), Some(3));
        let error: Value = serde_json::from_slice(&missing.stdout).unwrap();
        assert_eq!(error["error"]["code"], "authentication");
        assert!(error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pipe auth login"));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    Mock::given(method("POST"))
        .and(path("/v1/cli/auth/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code":"pcli_d_machine",
            "user_code":"BCDFG-HJKLM",
            "verification_uri":"https://pipe.network/cli/authorize",
            "verification_uri_complete":"https://pipe.network/cli/authorize?user_code=BCDFG-HJKLM",
            "expires_in":600,
            "interval":5
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/cli/auth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token":format!("pcli_a_{}", "a".repeat(64)),
            "refresh_token":format!("pcli_r_{}", "b".repeat(128)),
            "token_type":"Bearer",
            "scope":"account.read billing.read compute.read durable.read hosting.read kv.read org.read storage.read usage.read",
            "account_id":null,
            "owner_wallet":"c".repeat(64),
            "session_id":session_id,
            "expires_in":900,
            "refresh_expires_in":2592000
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = run_headless(&["auth", "login"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let machine_key = root.path().join("state/secrets.key");
    assert_eq!(std::fs::metadata(&machine_key).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&machine_key)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(std::fs::read(root.path().join("state/secrets.json"))
        .unwrap()
        .starts_with(b"PIPESEC3"));

    // Freshly logged-in users have no S3 endpoint or key. Listing buckets is a
    // control-plane read; it must survive gateway discovery being unavailable.
    for route in ["endpoint", "credentials", "buckets"] {
        Mock::given(path(format!("/v1/customer/cli/s3/{route}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "code":"not_found", "message":"CLI access is not enabled"
            })))
            .expect(0)
            .mount(&server)
            .await;
    }
    let cursor = Uuid::new_v4().to_string();
    Mock::given(method("GET"))
        .and(path("/v1/customer/storage/buckets"))
        .and(query_param("limit", "100"))
        .and(header(
            "authorization",
            format!("Bearer pcli_a_{}", "a".repeat(64)),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "available":true, "items":[{"name":"test","managed":false}], "next_cursor":cursor
        })))
        .with_priority(3)
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/customer/storage/buckets"))
        .and(query_param("after", &cursor))
        .and(header("authorization", format!("Bearer pcli_a_{}", "a".repeat(64))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "available":true, "items":[{"name":"pipe-bucket-managed","managed":true}], "next_cursor":null
        })))
        .with_priority(2)
        .expect(3)
        .mount(&server)
        .await;
    for args in [
        vec!["s3", "ls"],
        vec!["bucket", "list"],
        vec!["storage", "bucket", "list"],
    ] {
        let listed = success(run_headless(&args));
        assert_eq!(listed["items"].as_array().unwrap().len(), 2);
        assert_eq!(listed["items"][0]["name"], "test");
        assert_eq!(listed["items"][1]["name"], "pipe-bucket-managed");
    }
    // Persisted authentication stays scoped to the selected profile.
    success(pipe(
        root.path(),
        &[
            "profile",
            "create",
            "other",
            "--control-api-url",
            &server.uri(),
        ],
    ));
    assert_eq!(
        run_headless(&["--profile", "other", "s3", "ls"])
            .status
            .code(),
        Some(3)
    );
    // After the 15-minute access lifetime, refresh the platform session and
    // retain it for the next process instead of falling through to legacy auth.
    Mock::given(method("GET"))
        .and(path("/v1/customer/storage/buckets"))
        .and(header(
            "authorization",
            format!("Bearer pcli_a_{}", "a".repeat(64)),
        ))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/cli/auth/refresh"))
        .and(body_partial_json(json!({"refresh_token":format!("pcli_r_{}", "b".repeat(128))})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token":format!("pcli_a_{}", "d".repeat(64)),
            "refresh_token":format!("pcli_r_{}", "e".repeat(128)),
            "token_type":"Bearer",
            "scope":"account.read billing.read compute.read durable.read hosting.read kv.read org.read storage.read usage.read",
            "account_id":null,
            "owner_wallet":"c".repeat(64),
            "session_id":session_id,
            "expires_in":900,
            "refresh_expires_in":2592000
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/customer/storage/buckets"))
        .and(header(
            "authorization",
            format!("Bearer pcli_a_{}", "d".repeat(64)),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "available":true, "items":[{"name":"test"}], "next_cursor":null
        })))
        .expect(2)
        .mount(&server)
        .await;
    for _ in 0..2 {
        assert_eq!(
            success(run_headless(&["s3", "ls"]))["items"][0]["name"],
            "test"
        );
    }
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
    assert!(String::from_utf8_lossy(&output.stderr).contains("PIPE_CLI_SECRET_PASSWORD"));
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

async fn device_fixture(server: &MockServer, owner: &str, account: &str, scope: &str, token: char) {
    Mock::given(method("POST")).and(path("/v1/cli/auth/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"device_code":"fixture-device","user_code":"BCDFG-HJKLM","verification_uri":"https://pipe.network/cli/authorize","verification_uri_complete":"https://pipe.network/cli/authorize?user_code=BCDFG-HJKLM","expires_in":600,"interval":5})))
        .mount(server).await;
    Mock::given(method("POST")).and(path("/v1/cli/auth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":format!("pcli_a_{}",token.to_string().repeat(64)),"refresh_token":format!("pcli_r_{}",token.to_string().repeat(128)),"token_type":"Bearer","scope":scope,"account_id":account,"owner_wallet":owner,"session_id":Uuid::new_v4(),"expires_in":900,"refresh_expires_in":2592000})))
        .mount(server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn executable_s3_ls_matches_familiar_directory_and_recursive_listings() {
    let root = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let owner = "c".repeat(64);
    success(pipe(
        root.path(),
        &[
            "profile",
            "create",
            "listing",
            "--control-api-url",
            &server.uri(),
            "--s3-endpoint",
            &server.uri(),
        ],
    ));
    success(pipe(root.path(), &["profile", "use", "listing"]));
    device_fixture(
        &server,
        &owner,
        "listing-account",
        "account.read storage.read",
        'a',
    )
    .await;
    success(pipe(
        root.path(),
        &[
            "auth",
            "login",
            "--scope",
            "account.read storage.read",
            "--no-browser",
        ],
    ));
    Mock::given(method("POST")).and(path("/v1/customer/cli/s3/session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_key_id":"LTLIST","secret_access_key":"listing-secret","wallet":owner,"buckets":["test"],"permissions":["read","list"]})))
        .expect(1).mount(&server).await;
    success(pipe(
        root.path(),
        &["s3", "setup", "--bucket", "test", "--wallet", &owner],
    ));
    success(pipe(
        root.path(),
        &[
            "profile",
            "set",
            "--bucket",
            "different-bucket",
            "--prefix",
            "ignored/",
        ],
    ));
    Mock::given(method("GET")).and(path("/v1/customer/storage/buckets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"available":true,"items":[{"name":"test","created_at":1789686149,"wallet":owner},{"name":"legacy","created_at":null}],"next_cursor":null})))
        .mount(&server).await;

    // Two pages, including a directory-only entry and an object with terminal
    // control characters. Only compact human output escapes the original key.
    Mock::given(method("GET")).and(path("/test")).and(query_param("prefix", "")).and(query_param("delimiter", "/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>root+ &amp;</NextContinuationToken><CommonPrefixes><Prefix>test/</Prefix></CommonPrefixes><Contents><Key>read mé &amp; 雪.txt</Key><LastModified>2026-09-18T00:29:46Z</LastModified><Size>14</Size><ETag>opaque-etag</ETag></Contents></ListBucketResult>"))
        .with_priority(3).mount(&server).await;
    Mock::given(method("GET")).and(path("/test")).and(query_param("continuation-token", "root+ &"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>z&#10;name.txt</Key><LastModified>2026-09-18T00:29:46Z</LastModified><Size>0</Size></Contents></ListBucketResult>"))
        .with_priority(2).mount(&server).await;
    Mock::given(method("GET")).and(path("/test")).and(query_param("prefix", "test/")).and(query_param("delimiter", "/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>false</IsTruncated><CommonPrefixes><Prefix>test/sub/</Prefix></CommonPrefixes><Contents><Key>test/a.txt</Key><LastModified>2026-09-18T00:29:46Z</LastModified><Size>1024</Size></Contents></ListBucketResult>"))
        .mount(&server).await;
    Mock::given(method("GET")).and(path("/test")).and(query_param("prefix", "test/"))
        .and(|r: &wiremock::Request| !r.url.query_pairs().any(|(k, _)| k == "delimiter"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>recursive</NextContinuationToken><Contents><Key>test/a.txt</Key><LastModified>2026-09-18T00:29:46Z</LastModified><Size>1024</Size></Contents></ListBucketResult>"))
        .with_priority(3).mount(&server).await;
    Mock::given(method("GET")).and(path("/test")).and(query_param("continuation-token", "recursive"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>test/sub/b.txt</Key><LastModified>2026-09-18T00:29:46Z</LastModified><Size>2048</Size></Contents></ListBucketResult>"))
        .with_priority(2).mount(&server).await;
    Mock::given(method("GET"))
        .and(path("/test"))
        .and(query_param("prefix", "empty/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
        ))
        .mount(&server)
        .await;
    let human = |args: &[&str]| {
        let result = Command::new(env!("CARGO_BIN_EXE_pipe"))
            .env("PIPE_DISABLE_KEYRING", "1")
            .env("PIPE_CLI_SECRET_PASSWORD", "executable-fixture-password")
            .env("PIPE_CLI_STATE_DIR", root.path().join("state"))
            .arg("--config")
            .arg(root.path().join("config.json"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap()
    };
    let date = chrono::DateTime::parse_from_rfc3339("2026-09-18T00:29:46Z")
        .unwrap()
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let bucket_date = chrono::DateTime::from_timestamp(1789686149, 0)
        .unwrap()
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    for args in [
        vec!["s3", "ls"],
        vec!["s3", "ls", "s3://"],
        vec!["bucket", "list"],
    ] {
        let text = human(&args);
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains(&format!("{bucket_date} test\n")));
        assert!(text.contains("-                   legacy\n"));
        assert!(!text.contains(&owner));
    }
    for location in ["s3://test/", "s3://test", "test", "test/"] {
        assert_eq!(
            human(&["s3", "ls", location, "--page-size", "2"]),
            format!("                           PRE test/\n{date}         14 read mé & 雪.txt\n{date}          0 z\\nname.txt\n")
        );
    }
    assert_eq!(
        human(&["s3", "ls", "test/test/"]),
        format!("                           PRE sub/\n{date}       1024 a.txt\n")
    );
    let recursive = human(&[
        "s3",
        "list",
        "s3://test/test/",
        "--recursive",
        "--human-readable",
        "--summarize",
        "--page-size",
        "1",
    ]);
    assert_eq!(
        recursive,
        format!("{date}    1.0 KiB test/a.txt\n{date}    2.0 KiB test/sub/b.txt\n\nTotal Objects: 2\n   Total Size: 3.0 KiB\n")
    );
    assert_eq!(human(&["s3", "ls", "test/empty/"]), "");
    let json = success(pipe_format(
        root.path(),
        &["s3", "ls", "test/", "--summarize"],
        &["--output", "json"],
    ));
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["result"]["items"].as_array().unwrap().len(), 2);
    assert_eq!(json["result"]["items"][0]["etag"], "opaque-etag");
    assert_eq!(json["result"]["items"][1]["key"], "z\nname.txt");
    assert_eq!(json["result"]["common_prefixes"], json!(["test/"]));
    assert_eq!(
        json["result"]["summary"],
        json!({"total_objects":2,"total_size":14})
    );
    assert_eq!(json["result"]["next"], Value::Null);
    let jsonl = human(&["--output", "jsonl", "s3", "ls", "test/"]);
    let pages: Vec<Value> = jsonl
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0]["result"]["next"], "root+ &");
    assert_eq!(pages[1]["result"]["next"], Value::Null);
    for page_size in ["0", "1001"] {
        assert_eq!(
            pipe(
                root.path(),
                &["s3", "ls", "test/", "--page-size", page_size]
            )
            .status
            .code(),
            Some(2)
        );
    }
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().any(|r| r.url.path() == "/test"
        && r.url
            .query_pairs()
            .any(|(k, v)| k == "max-keys" && v == "2")));
    assert!(!requests.iter().any(|r| r.url.path() == "/different-bucket"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn executable_storage_setup_requests_missing_scopes_and_preserves_account() {
    let root = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let owner = "c".repeat(64);
    let scope = "account.read storage.read";
    let expanded = "account.read credentials.write storage.read storage.write";
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
    device_fixture(&server, &owner, "original", scope, 'a').await;
    success(pipe(
        root.path(),
        &["auth", "login", "--scope", scope, "--no-browser"],
    ));
    server.reset().await;
    let denied = pipe(
        root.path(),
        &["s3", "setup", "--write", "--bucket", "test", "--no-input"],
    );
    assert_eq!(denied.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&denied.stdout).contains("credentials.write"));
    assert!(server.received_requests().await.unwrap().is_empty());

    // A different canonical account, even for the same owner, must never
    // replace the original session or receive a pending storage mutation.
    device_fixture(&server, &owner, "different-account", expanded, 'b').await;
    Mock::given(method("POST"))
        .and(path("/v1/cli/auth/logout"))
        .and(header(
            "authorization",
            format!("Bearer pcli_a_{}", "b".repeat(64)),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    let wrong = pipe(
        root.path(),
        &["s3", "setup", "--write", "--bucket", "test", "--no-browser"],
    );
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stdout).contains("different account"));
    assert_eq!(
        success(pipe(root.path(), &["auth", "status"]))["scope"],
        scope
    );
    assert!(!server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|r| r.url.path().contains("/s3/credentials")));
    server.verify().await;
    server.reset().await;

    device_fixture(&server, &owner, "original", expanded, 'd').await;
    Mock::given(method("GET"))
        .and(path("/v1/customer/cli/account"))
        .and(header(
            "authorization",
            format!("Bearer pcli_a_{}", "d".repeat(64)),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"identities":[{"wallet":owner,"available_atoms":"1000000"}]}),
            ),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path("/v1/customer/cli/s3/credentials"))
        .and(header("authorization", format!("Bearer pcli_a_{}", "d".repeat(64))))
        .and(body_partial_json(json!({"wallet":owner,"buckets":["test"],"permissions":["read","list","write"]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_key_id":"LTWRITE","secret_access_key":"fixture-write-secret","wallet":owner,"buckets":["test"],"permissions":["read","list","write"]})))
        .expect(1).mount(&server).await;
    let setup = success(pipe(
        root.path(),
        &["s3", "setup", "--write", "--bucket", "test", "--no-browser"],
    ));
    assert!(!setup.to_string().contains("fixture-write-secret"));
    assert_eq!(
        success(pipe(root.path(), &["auth", "status"]))["scope"],
        expanded
    );
    let requests = server.received_requests().await.unwrap();
    let requested = requests
        .iter()
        .find(|r| r.url.path() == "/v1/cli/auth/device")
        .unwrap();
    let form: std::collections::HashMap<_, _> = reqwest::Url::parse(&format!(
        "https://example.test/?{}",
        String::from_utf8_lossy(&requested.body)
    ))
    .unwrap()
    .query_pairs()
    .into_owned()
    .collect();
    assert_eq!(form["scope"], expanded);
    server.verify().await;
    server.reset().await;

    Mock::given(method("GET"))
        .and(path("/v1/customer/cli/s3/endpoint"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"endpoint":server.uri(),"region":"us-east-1"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/test/pipe"))
        .and(header(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        ))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "opaque"))
        .expect(1)
        .mount(&server)
        .await;
    let input = root.path().join("pipe");
    std::fs::write(&input, b"binary\0payload").unwrap();
    let uploaded = success(pipe(
        root.path(),
        &["s3", "cp", input.to_str().unwrap(), "s3://test/"],
    ));
    assert_eq!(uploaded["key"], "pipe");
    Mock::given(method("GET"))
        .and(path("/test/pipe"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"binary\0payload".to_vec()))
        .expect(2)
        .mount(&server)
        .await;
    let dir = root.path().join("downloads");
    std::fs::create_dir(&dir).unwrap();
    success(pipe(
        root.path(),
        &["s3", "cp", "s3://test/pipe", dir.to_str().unwrap()],
    ));
    assert_eq!(std::fs::read(dir.join("pipe")).unwrap(), b"binary\0payload");
    success(pipe(
        root.path(),
        &["s3", "cp", "s3://test/pipe", "downloads/renamed.bin"],
    ));
    assert_eq!(
        std::fs::read(dir.join("renamed.bin")).unwrap(),
        b"binary\0payload"
    );
    for verb in ["PUT", "HEAD", "DELETE"] {
        Mock::given(method(verb))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/v1/customer/storage/buckets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "available": true,
            "items": [{"name": "test"}],
            "next_cursor": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    for args in [
        vec!["s3", "mb", "s3://test/"],
        vec!["s3", "head", "s3://test/"],
        vec!["s3", "ls"],
        vec!["s3", "rb", "s3://test/", "--yes"],
    ] {
        success(pipe(root.path(), &args));
    }
    Mock::given(method("DELETE"))
        .and(path("/test/pipe"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    success(pipe(root.path(), &["s3", "rm", "s3://test/pipe", "--yes"]));
    assert!(!server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|r| r.url.path().starts_with("/v1/cli/auth")));
}

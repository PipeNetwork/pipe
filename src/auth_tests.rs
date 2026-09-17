use super::*;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn session_value(wallet: &str, id: Uuid, access: &str) -> Value {
    json!({"access_token":access.repeat(64),"refresh_token":"r".repeat(128),"token_type":"Bearer","owner_wallet":wallet,"session_id":id,"expires_in":900,"refresh_expires_in":2592000})
}

#[tokio::test]
async fn login_signs_only_cli_domain_and_keeps_tokens_out_of_result() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let client = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let wallet = hex::encode(key.verifying_key().to_bytes());
    client
        .secrets
        .set("wallet_private_key", &hex::encode(key.to_bytes()))
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    let message = format!("Pipe Storage authorization\ndomain: pipe-cli\nmesh: {}\naction: cli_login\nowner: {wallet}\nnonce: {}\nissued_at: {now}\nexpires_at: {}\n",Uuid::new_v4(),"a".repeat(64),now+300);
    let challenge = Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path("/v1/customer/cli/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"challenge_id":challenge,"owner_wallet":wallet,"message":message}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let signature = hex::encode(key.sign(message.as_bytes()).to_bytes());
    Mock::given(method("POST"))
        .and(path("/v1/customer/cli/auth/session"))
        .and(wiremock::matchers::body_partial_json(
            json!({"challenge_id":challenge,"signature":signature}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(session_value(
            &wallet,
            Uuid::new_v4(),
            "a",
        )))
        .expect(1)
        .mount(&server)
        .await;
    let value = client.login(None, None).await.unwrap();
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert_eq!(client.current_wallet().unwrap(), wallet);
    assert!(client.session().unwrap().is_some());
}

#[tokio::test]
async fn expired_access_refreshes_then_replays_request_with_new_token() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let client = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    let id = Uuid::new_v4();
    let wallet = "a".repeat(64);
    client
        .store_session(&serde_json::from_value(session_value(&wallet, id, "a")).unwrap())
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/v1/customer/cli/account"))
        .and(header(
            "authorization",
            format!("Bearer {}", "a".repeat(64)),
        ))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/customer/cli/auth/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(session_value(&wallet, id, "b")))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/customer/cli/account"))
        .and(header(
            "authorization",
            format!("Bearer {}", "b".repeat(64)),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"owner_wallet":wallet})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client.get("/v1/customer/cli/account").await.unwrap()["owner_wallet"],
        wallet
    );
    assert_eq!(
        client.session().unwrap().unwrap().access_token,
        "b".repeat(64)
    );
}

#[tokio::test]
async fn uncertain_refresh_failure_requires_reauthentication() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let client = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    client
        .store_session(
            &serde_json::from_value(session_value(&"a".repeat(64), Uuid::new_v4(), "a")).unwrap(),
        )
        .unwrap();
    Mock::given(path("/v1/customer/cli/auth/refresh"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    assert!(client.refresh().await.is_err());
    assert!(client.session().unwrap().is_none());
}

#[tokio::test]
async fn malformed_and_oversized_responses_and_error_ids() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let client = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    for (route, body) in [
        ("bad", "{".to_owned()),
        ("large", "x".repeat(2 * 1024 * 1024 + 1)),
    ] {
        Mock::given(path(format!("/{route}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        assert!(client.get(&format!("/{route}")).await.is_err());
    }
    Mock::given(path("/error"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-request-id", "request-123")
                .set_body_json(json!({"code":"forbidden","message":"echoed-secret-value"})),
        )
        .mount(&server)
        .await;
    let error = client.get("/error").await.unwrap_err().to_string();
    assert!(error.contains("request-123"));
    assert!(!error.contains("echoed-secret-value"));
}

#[test]
fn refuses_website_or_transaction_signing_challenges() {
    let wallet = "a".repeat(64);
    assert!(validate_challenge("transfer all tokens", &wallet).is_err());
    let now = chrono::Utc::now().timestamp();
    let message = format!("Pipe Storage authorization\ndomain: pipe.network\nmesh: {}\naction: cli_login\nowner: {wallet}\nnonce: {}\nissued_at: {now}\nexpires_at: {}\n",Uuid::new_v4(),"a".repeat(64),now+300);
    assert!(validate_challenge(&message, &wallet).is_err());
}

#[tokio::test]
async fn credential_lifecycle_and_logout_contract() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let client = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    let wallet = "a".repeat(64);
    client
        .store_session(
            &serde_json::from_value(session_value(&wallet, Uuid::new_v4(), "a")).unwrap(),
        )
        .unwrap();
    Mock::given(method("POST"))
        .and(path("/v1/customer/cli/s3/credentials"))
        .and(wiremock::matchers::body_partial_json(
            json!({"wallet":wallet,"buckets":["test"],"permissions":["read"]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"access_key_id":"LTTEST","secret_access_key":"secret-created-once"}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let created = crate::account::create_credential(
        &client,
        &wallet,
        "test",
        &["test".into()],
        "",
        &["read".into()],
        None,
    )
    .await
    .unwrap();
    assert_eq!(created["access_key_id"], "LTTEST");
    Mock::given(method("GET"))
        .and(path("/v1/customer/cli/s3/credentials"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"items":[{"access_key_id":"LTTEST"}]})),
        )
        .mount(&server)
        .await;
    assert!(
        crate::account::credentials(&client).await.unwrap()["items"][0]
            .get("secret_access_key")
            .is_none()
    );
    Mock::given(method("DELETE"))
        .and(path("/v1/customer/cli/s3/credentials/LTTEST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"revoked":true})))
        .mount(&server)
        .await;
    assert_eq!(
        crate::account::revoke_credential(&client, "LTTEST")
            .await
            .unwrap()["revoked"],
        true
    );
    Mock::given(method("POST"))
        .and(path("/v1/customer/cli/auth/logout"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"revoked":true})))
        .mount(&server)
        .await;
    client.logout().await.unwrap();
    assert!(client.session().unwrap().is_none());
}

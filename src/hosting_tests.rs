use super::*;
use crate::config::Profile;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};
fn customer(c: &ControlClient, owner: &str) -> Binding {
    Binding::Customer {
        context: ContextBinding {
            endpoint: c.url(""),
            owner_wallet: owner.into(),
            account_id: None,
        },
    }
}
fn site(id: Uuid, active: &str) -> Value {
    json!({"id":id,"slug":"test","hostname":"test.localhost","postgres_binding":null,"active_release":active,"owner_id":"owner","rollback_release":null})
}
#[tokio::test]
async fn lost_activation_never_overwrites_a_later_release_or_changes_accounts() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
    let b = customer(&c, "owner");
    let id = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path(format!("/v1/hosting/sites/{site_id}/activate")))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET")).and(path(format!("/v1/hosting/sites/{site_id}"))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"site":site(site_id,&"b".repeat(64)),"runtime_alive":true,"runtime_instance":null}))).expect(1).mount(&server).await;
    let error = submit(
        &c,
        &b,
        id,
        Some(Request::Activate {
            site: site_id,
            release_id: "a".repeat(64),
            expected_active: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(crate::error::classification(&error), ("unknown_outcome", 8));
    drop(c);
    let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
    assert!(submit(&c, &customer(&c, "other"), id, None).await.is_err());
    assert_eq!(
        crate::error::classification(&submit(&c, &b, id, None).await.unwrap_err()),
        ("unknown_outcome", 8)
    );
    assert_eq!(State::load(&c).unwrap().requests[&id].state, "unknown");
}
#[tokio::test]
async fn invalid_mutation_is_never_journaled_or_sent_and_product_keys_cannot_purchase() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
    let b = customer(&c, "owner");
    assert!(submit(
        &c,
        &b,
        Uuid::new_v4(),
        Some(Request::Activate {
            site: Uuid::new_v4(),
            release_id: "../escape".into(),
            expected_active: None
        })
    )
    .await
    .is_err());
    assert!(submit(
        &c,
        &Binding::Product {
            endpoint: c.url(""),
            account: Uuid::new_v4(),
            credential: Uuid::new_v4()
        },
        Uuid::new_v4(),
        Some(Request::Purchase {
            plan: "starter".into(),
            price_version: "v1".into()
        })
    )
    .await
    .is_err());
    assert!(State::load(&c).unwrap().requests.is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[test]
fn saved_bundle_is_encrypted_and_corruption_preserves_the_original() {
    let root = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new("https://fixture.invalid"), root.path()).unwrap();
    let clear = b"private deployment content";
    let hash = crate::sigv4::sha256_hex(clear);
    hosting_state::bundle(&c, &hash, Some(clear)).unwrap();
    let path = c
        .secrets
        .state_directory()
        .join(format!("hosting-bundles/{hash}.enc"));
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(clear.len()).any(|v| v == clear));
    assert_eq!(
        hosting_state::bundle(&c, &hash, None).unwrap().as_slice(),
        clear
    );
    let mut corrupt = bytes;
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &corrupt).unwrap();
    assert!(hosting_state::bundle(&c, &hash, None).is_err());
    assert_eq!(std::fs::read(path).unwrap(), corrupt);
}
#[tokio::test]
async fn pending_purchase_wait_is_bounded_and_keeps_its_original_idempotency_key() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
    let b = customer(&c, "owner");
    let id = Uuid::new_v4();
    let purchase = json!({"id":Uuid::new_v4(),"plan":"starter","atoms":"5000000","starts":1,"paid_until":2592001,"status":"pending"});
    Mock::given(method("POST"))
        .and(path("/v1/customer/hosting/purchases"))
        .and(wiremock::matchers::header(
            "idempotency-key",
            id.to_string(),
        ))
        .respond_with(ResponseTemplate::new(202).set_body_json(purchase))
        .expect(2)
        .mount(&server)
        .await;
    let v = submit(
        &c,
        &b,
        id,
        Some(Request::Purchase {
            plan: "starter".into(),
            price_version: "v1".into(),
        }),
    )
    .await
    .unwrap();
    let error = waited(
        &c,
        &b,
        id,
        v,
        &Wait {
            wait: true,
            timeout: 1,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(crate::error::classification(&error), ("wait_timeout", 9));
    assert_eq!(State::load(&c).unwrap().requests[&id].state, "pending");
}

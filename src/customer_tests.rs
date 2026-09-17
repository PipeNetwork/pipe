use super::*;
use crate::config::Profile;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};
fn bound(c: &ControlClient) -> ContextBinding {
    ContextBinding {
        endpoint: c.url(""),
        owner_wallet: "owner".into(),
        account_id: Some("acct_test".into()),
    }
}
#[tokio::test]
async fn ambiguous_role_change_never_overwrites_a_later_role_or_changes_account() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
    Mock::given(method("PATCH"))
        .and(path(
            "/v1/platform/organizations/org_test/memberships/acct_other",
        ))
        .respond_with(ResponseTemplate::new(502))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET")).and(path("/v1/platform/organizations/org_test/memberships")).respond_with(ResponseTemplate::new(200).set_body_json(json!([{"account_id":"acct_other","email":"other@example.test","display_name":null,"role":"owner","created_at":"2026-09-17T00:00:00Z","updated_at":"2026-09-17T00:00:00Z"}]))).expect(1).mount(&server).await;
    let e = mutate(
        &c,
        &bound(&c),
        Request::UpdateMember {
            org: "org_test".into(),
            account: "acct_other".into(),
            role: "member".into(),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(crate::error::classification(&e).1, 8);
    let id = *State::load(&c).unwrap().requests.keys().next().unwrap();
    drop(c);
    let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
    let mut other = bound(&c);
    other.account_id = Some("acct_other".into());
    assert!(resume(&c, &other, id).await.is_err());
    assert_eq!(
        crate::error::classification(&resume(&c, &bound(&c), id).await.unwrap_err()).1,
        8
    );
    assert!(mutate(&c, &bound(&c), Request::RotateReferral)
        .await
        .is_err());
}
#[tokio::test]
async fn invalid_identifiers_and_names_are_not_sent_or_saved() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
    assert!(read(
        &c,
        &Request::Members {
            org: "../admin".into()
        }
    )
    .await
    .is_err());
    assert!(mutate(
        &c,
        &bound(&c),
        Request::CreateOrg {
            id: "org_test".into(),
            name: "x".repeat(201)
        }
    )
    .await
    .is_err());
    assert!(State::load(&c).unwrap().requests.is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[test]
fn invitation_material_is_encrypted_and_corruption_does_not_overwrite_it() {
    let root = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new("https://fixture.invalid"), root.path()).unwrap();
    let token = "a-secret-invitation-token";
    State::load(&c)
        .unwrap()
        .prepare(
            &c,
            Uuid::new_v4(),
            bound(&c),
            Request::CreateInvite {
                org: "org_test".into(),
                id: "invite_test".into(),
                email: "private@example.test".into(),
                role: "member".into(),
                accept_token: token.into(),
            },
        )
        .unwrap();
    let path = c.secrets.state_directory().join("customer-state-v1.enc");
    let mut bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(token.len()).any(|v| v == token.as_bytes()));
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    assert!(State::load(&c).is_err());
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[tokio::test]
async fn different_key_receipt_preserves_original_encrypted_material_and_blocks_replacement() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
    let id = Uuid::new_v4();
    let secret = format!("api_{}", Uuid::new_v4().simple());
    let original = Request::CreateApiKey {
        id,
        api_key: secret.clone(),
        settings: Default::default(),
    };
    Mock::given(method("POST"))
        .and(path("/v1/account/api-keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id":"gg_fixture", "api_key_id":id,
            "api_key":format!("api_{}", Uuid::new_v4().simple())
        })))
        .expect(1)
        .mount(&server)
        .await;
    let e = mutate(&c, &bound(&c), original.clone()).await.unwrap_err();
    assert_eq!(crate::error::classification(&e).1, 8);
    let bytes = std::fs::read(c.secrets.state_directory().join("customer-state-v1.enc")).unwrap();
    assert!(!bytes.windows(secret.len()).any(|v| v == secret.as_bytes()));
    drop(c);
    let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
    let state = State::load(&c).unwrap();
    let entry = state.requests.values().next().unwrap();
    assert_eq!(entry.state, "unknown");
    assert_eq!(entry.request, original);
    assert!(mutate(
        &c,
        &bound(&c),
        Request::CreateApiKey {
            id: Uuid::new_v4(),
            api_key: format!("api_{}", Uuid::new_v4().simple()),
            settings: Default::default()
        }
    )
    .await
    .is_err());
}

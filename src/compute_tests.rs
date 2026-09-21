use super::*;
use crate::config::Profile;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn features() -> Value {
    json!({"stage":"test","customer_launch_ready":false,"billing":"test","inference_mode":"external","hi_image_support":false,"disk_encryption":false,"tenant_network_isolation":false,"backups":false,"delete_destroys_disk":true})
}
fn acceptance(vm: Uuid, op: Uuid) -> Value {
    json!({"vm_id":vm,"operation_id":op,"generation":1,"desired_state":"running","observed_state":"unknown","ready":false,"ssh_ready":false,"features":features()})
}
#[tokio::test]
async fn uncertain_mutation_survives_restart_and_resumes_exactly_once() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let client = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    let changed = Arc::new(AtomicBool::new(false));
    let changed_context = changed.clone();
    Mock::given(path("/v1/cli/context")).respond_with(move |_: &wiremock::Request| {
        ResponseTemplate::new(200).set_body_json(json!({"principal":{"owner_wallet":if changed_context.load(Ordering::SeqCst){"other"}else{"owner"},"account_id":null,"credential_id":Uuid::nil(),"credential_kind":"session","account_access":true,"organizations":[],"resources":[],"scopes":["compute.write"]},"contexts":[],"storage":{"endpoint":"https://gw-001.pipedev.network","region":"us-east-1"}}))
    }).mount(&server).await;
    let vm = Uuid::new_v4();
    let op = Uuid::new_v4();
    let key = Uuid::new_v4();
    let r = Request::action(vm, Action::Start, false);
    let count = Arc::new(AtomicUsize::new(0));
    let requests = count.clone();
    Mock::given(method("POST"))
        .and(path(&r.path))
        .and(header("idempotency-key", key.to_string()))
        .and(body_json(r.body.clone()))
        .respond_with(move |_: &wiremock::Request| {
            if requests.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(202).set_body_json(acceptance(vm, op))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let error = submit(&client, Some(r.clone()), Some(key), Wait::default(), true)
        .await
        .unwrap_err();
    assert_eq!(crate::error::classification(&error), ("unknown_outcome", 8));
    assert!(
        submit(&client, Some(r.clone()), None, Wait::default(), true)
            .await
            .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    drop(client);
    let client = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    changed.store(true, Ordering::SeqCst);
    assert!(submit(&client, None, Some(key), Wait::default(), true)
        .await
        .is_err());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    changed.store(false, Ordering::SeqCst);
    submit(&client, None, Some(key), Wait::default(), true)
        .await
        .unwrap();
    submit(&client, None, Some(key), Wait::default(), true)
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert!(submit(
        &client,
        Some(Request::action(vm, Action::Stop, true)),
        Some(key),
        Wait::default(),
        true
    )
    .await
    .is_err());
    let journal = Journal::open(&client).unwrap();
    assert_eq!(
        journal.get(key).unwrap().response.as_ref().unwrap()["operation_id"],
        json!(op)
    );
}
#[test]
fn saved_requests_cannot_override_paths_or_payment_workflows() {
    let id = Uuid::new_v4();
    for action in [Action::Start, Action::Stop, Action::Reboot, Action::Delete] {
        validate_request(&Request::action(id, action, false)).unwrap();
    }
    let mut r = Request::action(id, Action::Stop, false);
    for destination in [
        "https://attacker.invalid/",
        "/v1/operator/compute/hosts",
        "/v1/compute/vms/../stop",
    ] {
        r.path = destination.into();
        assert!(validate_request(&r).is_err());
    }
    r = Request::action(id, Action::Start, false);
    r.operation_id = "createInvoice".into();
    assert!(validate_request(&r).is_err());
}
#[tokio::test]
async fn operation_deadline_leaves_server_work_running() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    let id = Uuid::new_v4();
    Mock::given(method("GET")).and(path(format!("/v1/compute/operations/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"operation_id":id,"vm_id":Uuid::new_v4(),"generation":1,"action":"create","status":"running","phase":"provisioning","error_code":null,"created_at":0,"completed_at":null})))
        .expect(1).mount(&server).await;
    let error = wait_operation(&c, id, None, 1, true).await.unwrap_err();
    assert_eq!(crate::error::classification(&error), ("wait_timeout", 9));
    assert!(error.to_string().contains("server work may continue"));
}
#[tokio::test]
async fn pagination_rejects_repeated_cursors_and_schema_drift() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    Mock::given(path("/v1/compute/vms"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"vms":[],"next_cursor":Uuid::nil(),"features":features()})),
        )
        .expect(2)
        .mount(&server)
        .await;
    assert!(list(&c, 1, None, true, true)
        .await
        .unwrap_err()
        .to_string()
        .contains("repeated pagination"));
    assert!(platform::validate_response(
        "listComputeVms",
        "200",
        &json!({"items":[],"next_cursor":null})
    )
    .is_err());
}

#[tokio::test]
async fn definite_conflicts_allow_a_corrected_request_without_discarding_the_record() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let client = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    Mock::given(path("/v1/cli/context")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"principal":{"owner_wallet":"owner","account_id":null,"credential_id":Uuid::nil(),"credential_kind":"session","account_access":true,"organizations":[],"resources":[],"scopes":["compute.write"]},"contexts":[],"storage":{"endpoint":"https://gw-001.pipedev.network","region":"us-east-1"}}))).mount(&server).await;
    let vm = Uuid::new_v4();
    let id = Uuid::new_v4();
    Mock::given(path(format!("/v1/compute/vms/{vm}/start")))
        .respond_with(
            ResponseTemplate::new(409).set_body_json(json!({"code":"operation_in_progress"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let error = submit(
        &client,
        Some(Request::action(vm, Action::Start, false)),
        Some(id),
        Wait::default(),
        true,
    )
    .await
    .unwrap_err();
    assert_eq!(crate::error::classification(&error), ("conflict", 6));
    assert_eq!(
        Journal::open(&client).unwrap().get(id).unwrap().state,
        "rejected"
    );
}

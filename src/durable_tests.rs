use super::*;
use crate::{compute_journal::ContextBinding, config::Profile};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};
fn customer(c: &ControlClient, owner: &str) -> Binding {
    Binding::Customer {
        context: ContextBinding {
            endpoint: c.profile.control_api_url.clone(),
            owner_wallet: owner.into(),
            account_id: None,
        },
    }
}
fn receipt(id: Uuid) -> Value {
    json!({"operation_id":id,"status":"pending","charge_atoms":"0","response":null,"response_expired":false})
}
#[tokio::test]
async fn lost_reply_keeps_encrypted_payload_and_replays_exact_intent_after_restart() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    let namespace = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let id = Uuid::new_v4();
    let request = Request::Execute {
        namespace,
        body: Execute {
            object: "counter".into(),
            action: Action::PutState {
                key: "app".into(),
                value: json!({"secret":"application-secret-marker","token":null,"n":9007199254740993u64}),
            },
        },
    };
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/customer/durable/namespaces/{namespace}/execute"
        )))
        .and(header("idempotency-key", id.to_string()))
        .and(body_json(
            request_body(&State::load(&c).unwrap(), &request).unwrap(),
        ))
        .respond_with(move |_: &wiremock::Request| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_json(receipt(operation))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let b = customer(&c, "owner");
    let error = submit(&c, Some(request.clone()), id, b.clone())
        .await
        .unwrap_err();
    assert_eq!(crate::error::classification(&error), ("unknown_outcome", 8));
    assert!(submit(&c, Some(request.clone()), Uuid::new_v4(), b.clone())
        .await
        .is_err());
    let bytes = std::fs::read(c.secrets.state_directory().join("durable-state-v1.enc")).unwrap();
    assert!(!bytes.windows(25).any(|v| v == b"application-secret-marker"));
    drop(c);
    let c = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    assert!(submit(&c, None, id, customer(&c, "other")).await.is_err());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(
        submit(&c, None, id, b.clone()).await.unwrap(),
        receipt(operation)
    );
    assert_eq!(
        submit(&c, None, id, b.clone()).await.unwrap(),
        receipt(operation)
    );
    assert!(submit(
        &c,
        Some(Request::Execute {
            namespace,
            body: Execute {
                object: "different".into(),
                action: Action::DeleteObject,
            }
        }),
        id,
        b
    )
    .await
    .is_err());
    assert_eq!(count.load(Ordering::SeqCst), 2);
    let file = c.secrets.state_directory().join("durable-state-v1.enc");
    let mut corrupt = std::fs::read(&file).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&file, &corrupt).unwrap();
    assert!(State::load(&c).is_err());
    assert_eq!(std::fs::read(file).unwrap(), corrupt);
}
#[tokio::test]
async fn invalid_unsent_request_never_creates_an_unknown_outcome() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    let request = Request::Execute {
        namespace: Uuid::new_v4(),
        body: Execute {
            object: "invalid\nname".into(),
            action: Action::DeleteObject,
        },
    };
    assert!(
        submit(&c, Some(request), Uuid::new_v4(), customer(&c, "owner"))
            .await
            .is_err()
    );
    assert!(State::load(&c).unwrap().requests.is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[tokio::test]
async fn deadline_bounds_a_hung_operation_read_without_resubmitting() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let c = ControlClient::for_test(Profile::new(server.uri()), dir.path()).unwrap();
    let id = Uuid::new_v4();
    Mock::given(method("GET"))
        .and(path(format!("/v1/customer/durable/requests/{id}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(receipt(id))
                .set_delay(Duration::from_secs(5)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let started = std::time::Instant::now();
    let error = poll(
        &c,
        &customer(&c, "owner"),
        id,
        None,
        &Wait {
            wait: true,
            timeout: 1,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(crate::error::classification(&error), ("wait_timeout", 9));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

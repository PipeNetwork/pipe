use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use wiremock::{matchers::method, Mock, MockServer, Request, ResponseTemplate};

fn client(server: &MockServer) -> S3Client {
    let mut profile = Profile::new("https://control.example");
    profile.s3_endpoint = Some(server.uri());
    S3Client::new(&profile, "AKID".into(), "private-fixture-secret".into()).unwrap()
}

#[tokio::test]
async fn definite_s3_failures_keep_status_classification_and_sanitized_details() {
    for (status, code, expected) in [
        (401, "ExpiredToken", ("authentication", 3)),
        (402, "HttpError", ("payment_required", 1)),
        (403, "AccessDenied", ("authorization", 4)),
        (412, "PreconditionFailed", ("conflict", 6)),
        (429, "SlowDown", ("unavailable", 5)),
        (501, "NotImplemented", ("unavailable", 5)),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(status).set_body_string(format!(
                "<Error><Code>{code}</Code><Message>private-fixture-secret</Message></Error>"
            )))
            .expect(2)
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        std::fs::write(&source, b"contents").unwrap();
        let s3 = client(&server);
        for error in [
            s3.put_object("bucket", "key", Bytes::from_static(b"contents"), None)
                .await
                .unwrap_err(),
            s3.put_file("bucket", "key", &source, None)
                .await
                .unwrap_err(),
        ] {
            assert_eq!(crate::error::classification(&error), expected);
            assert!(error.downcast_ref::<MutationUnknown>().is_none());
            let document = crate::error::document(&error);
            assert_eq!(document["error"]["http_status"], status);
            assert_eq!(document["error"]["s3_code"], code);
            assert!(document["error"]["message"]
                .as_str()
                .unwrap()
                .contains(&status.to_string()));
            assert!(!document.to_string().contains("private-fixture-secret"));
            assert!(!crate::error::message(&error).contains("private-fixture-secret"));
        }
    }
}

#[tokio::test]
async fn earlier_ambiguous_mutation_is_retained_across_every_existing_retry_loop() {
    for operation in ["delete", "part", "complete"] {
        let server = MockServer::start().await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = attempts.clone();
        Mock::given(method(match operation {
            "delete" => "DELETE",
            "part" => "PUT",
            _ => "POST",
        }))
        .respond_with(move |_: &Request| {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503)
                    .set_body_string("<Error><Code>ServiceUnavailable</Code></Error>")
            } else {
                ResponseTemplate::new(403)
                    .set_body_string("<Error><Code>AccessDenied</Code></Error>")
            }
        })
        .expect(2)
        .mount(&server)
        .await;
        let s3 = client(&server);
        let error = match operation {
            "delete" => s3.delete_object("bucket", "key").await.unwrap_err(),
            "part" => s3
                .upload_part(
                    "bucket",
                    "key",
                    "original-upload",
                    1,
                    Bytes::from_static(b"part"),
                )
                .await
                .unwrap_err(),
            _ => s3
                .complete_multipart_upload(
                    "bucket",
                    "key",
                    "original-upload",
                    &[Part {
                        part_number: 1,
                        etag: "opaque-etag".into(),
                        size: Some(4),
                    }],
                )
                .await
                .unwrap_err(),
        };
        assert_eq!(
            crate::error::classification(&error),
            ("unknown_outcome", 8),
            "{operation}"
        );
        assert_eq!(
            error.downcast_ref::<S3Error>().unwrap().status,
            StatusCode::FORBIDDEN
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].url, requests[1].url);
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn transient_single_put_is_unknown_without_replay_or_unrelated_head() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(507))
        .expect(1)
        .mount(&server)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    std::fs::write(&source, b"contents").unwrap();
    let error = client(&server)
        .put_file("bucket", "key", &source, None)
        .await
        .unwrap_err();
    assert_eq!(crate::error::classification(&error), ("unknown_outcome", 8));
    assert_eq!(
        error.downcast_ref::<S3Error>().unwrap().status.as_u16(),
        507
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert_eq!(std::fs::read(&source).unwrap(), b"contents");
}

#[tokio::test]
async fn dropped_streaming_response_is_unknown_while_dropped_read_is_transport() {
    use std::io::Read;
    for upload in [true, false] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut block = [0; 4096];
                let count = socket.read(&mut block).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&block[..count]);
                if if upload {
                    bytes.ends_with(b"\r\n0\r\n\r\n")
                } else {
                    bytes.ends_with(b"\r\n\r\n")
                } {
                    break;
                }
                assert!(bytes.len() < 64 * 1024);
            }
            if upload {
                assert!(bytes
                    .windows(b"contents".len())
                    .any(|part| part == b"contents"));
                assert!(bytes
                    .windows(b"chunk-signature=".len())
                    .any(|part| part == b"chunk-signature="));
            }
            // Request forwarding completed; deliberately provide no response.
        });
        let mut profile = Profile::new("https://control.example");
        profile.s3_endpoint = Some(format!("http://{address}"));
        let s3 = S3Client::new(&profile, "AKID".into(), "private-fixture-secret".into()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        std::fs::write(&source, b"contents").unwrap();
        let error = if upload {
            s3.put_file("bucket", "key", &source, None)
                .await
                .unwrap_err()
        } else {
            // No automatic read retries are needed to distinguish transport.
            s3.send(
                Method::GET,
                s3.url("bucket", Some("key"), None).unwrap(),
                s3.headers(&sha256_hex(b"")),
                None,
                false,
            )
            .await
            .unwrap_err()
        };
        peer.join().unwrap();
        assert_eq!(
            crate::error::classification(&error),
            if upload {
                ("unknown_outcome", 8)
            } else {
                ("transport", 7)
            }
        );
        assert!(error
            .downcast_ref::<reqwest::Error>()
            .unwrap()
            .url()
            .is_none());
        assert!(!crate::error::message(&error).contains("private-fixture-secret"));
    }
}

#[tokio::test]
async fn successful_but_unusable_multipart_acknowledgments_keep_unknown_outcome() {
    for operation in ["create", "part", "complete"] {
        let server = MockServer::start().await;
        Mock::given(method(if operation == "part" { "PUT" } else { "POST" }))
            .respond_with(ResponseTemplate::new(200).set_body_string("incomplete acknowledgment"))
            .expect(1)
            .mount(&server)
            .await;
        let s3 = client(&server);
        let error = match operation {
            "create" => s3
                .create_multipart_upload("bucket", "key", None)
                .await
                .unwrap_err(),
            "part" => s3
                .upload_part("bucket", "key", "original", 1, Bytes::from_static(b"part"))
                .await
                .unwrap_err(),
            _ => s3
                .complete_multipart_upload_observed(
                    "bucket",
                    "key",
                    "original",
                    &[Part {
                        part_number: 1,
                        etag: "opaque".into(),
                        size: Some(4),
                    }],
                )
                .await
                .unwrap_err(),
        };
        assert_eq!(crate::error::classification(&error), ("unknown_outcome", 8));
    }
}

#[test]
fn safe_rendering_preserves_other_unknown_types_without_dumping_anyhow_causes() {
    let error = anyhow!("private nested material").context("safe outer context");
    assert_eq!(crate::error::message(&error), "safe outer context");
    let error = anyhow::Error::new(s3_error(StatusCode::FORBIDDEN, "AccessDenied".into())).context(
        crate::error::UnknownOutcome {
            request_id: uuid::Uuid::new_v4(),
        },
    );
    assert_eq!(crate::error::classification(&error), ("unknown_outcome", 8));
    assert_eq!(crate::error::document(&error)["error"]["http_status"], 403);
}

#[tokio::test]
async fn control_body_deadline_is_transport_unless_a_stronger_outcome_marker_exists() {
    let elapsed = tokio::time::timeout(Duration::from_millis(1), std::future::pending::<()>())
        .await
        .unwrap_err();
    let error = anyhow::Error::new(elapsed).context("S3 control response deadline exceeded");
    assert_eq!(crate::error::classification(&error), ("transport", 7));
    let mut unknown = false;
    let error = mutation_failure(error, &mut unknown);
    assert!(unknown);
    assert_eq!(crate::error::classification(&error), ("unknown_outcome", 8));
    let error = anyhow::Error::new(crate::error::WaitTimeout {
        operation_id: uuid::Uuid::new_v4(),
    });
    assert_eq!(crate::error::classification(&error), ("wait_timeout", 9));
}

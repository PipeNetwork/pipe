use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, Request, ResponseTemplate,
};

fn client(server: &MockServer) -> S3Client {
    let mut profile = Profile::new("https://control.example");
    profile.s3_endpoint = Some(server.uri());
    S3Client::new(&profile, "AKID".into(), "secret".into()).unwrap()
}

fn xml(body: impl Into<String>) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_string(body)
        .insert_header("content-type", "application/xml")
}

fn failure(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_string(format!(
        "<Error><Code>{code}</Code><Message>request refused</Message></Error>"
    ))
}

fn mac(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(bytes);
    mac.finalize().into_bytes().to_vec()
}

fn signing_key(date: &str) -> Vec<u8> {
    let date = mac(b"AWS4secret", date.as_bytes());
    let region = mac(&date, b"us-east-1");
    let service = mac(&region, b"s3");
    mac(&service, b"aws4_request")
}

/// Independent verification of the captured HTTP request, with explicit expected
/// URI/query. Does not call the production canonicalizer or signer.
fn verify_signature(
    request: &Request,
    uri: &str,
    query: &str,
) -> (Vec<u8>, String, String, String) {
    crate::openapi_contract::s3_operation(request);
    assert_eq!(request.url.path(), uri);
    let authorization = request.headers["authorization"].to_str().unwrap();
    let signed = authorization
        .split("SignedHeaders=")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap();
    let timestamp = request.headers["x-amz-date"].to_str().unwrap();
    let payload = request.headers["x-amz-content-sha256"].to_str().unwrap();
    let canonical_headers: String = signed
        .split(';')
        .map(|name| {
            format!(
                "{name}:{}\n",
                request.headers[name]
                    .to_str()
                    .unwrap()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        })
        .collect();
    let canonical = format!(
        "{}\n{uri}\n{query}\n{canonical_headers}\n{signed}\n{payload}",
        request.method
    );
    let scope = format!("{}/us-east-1/s3/aws4_request", &timestamp[..8]);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let key = signing_key(&timestamp[..8]);
    let signature = hex::encode(mac(&key, to_sign.as_bytes()));
    assert!(
        authorization.ends_with(&format!("Signature={signature}")),
        "{authorization}"
    );
    (key, timestamp.into(), scope, signature)
}

#[tokio::test]
async fn signed_object_paths_preserve_literal_percent_reserved_and_unicode() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    client(&server)
        .put_object(
            "bucket",
            "a%2Fb +!~é/?#",
            Bytes::from_static(b"content"),
            Some("text/plain"),
        )
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    verify_signature(&requests[0], "/bucket/a%252Fb%20%2B%21~%C3%A9/%3F%23", "");
    assert_eq!(
        requests[0].headers["x-amz-content-sha256"],
        sha256_hex(b"content")
    );
    assert_eq!(requests[0].body, b"content");
}

#[tokio::test]
async fn streaming_request_verifies_every_signature_including_empty_hash_and_terminator() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("input");
    let input = vec![b'x'; 150_123];
    tokio::fs::write(&file, &input).await.unwrap();
    client(&server)
        .with_conditions(None, Some("*".into()))
        .unwrap()
        .put_file("bucket", "key", &file, None)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    let request = &requests[0];
    let (key, timestamp, scope, mut previous) = verify_signature(request, "/bucket/key", "");
    assert_eq!(
        request.headers["x-amz-decoded-content-length"],
        input.len().to_string()
    );
    assert_eq!(request.headers["if-none-match"], "*");
    let mut encoded = request.body.as_slice();
    let mut decoded = Vec::new();
    loop {
        let end = encoded.windows(2).position(|w| w == b"\r\n").unwrap();
        let header = std::str::from_utf8(&encoded[..end]).unwrap();
        let (length, signature) = header.split_once(";chunk-signature=").unwrap();
        let length = usize::from_str_radix(length, 16).unwrap();
        encoded = &encoded[end + 2..];
        let chunk = &encoded[..length];
        let to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{timestamp}\n{scope}\n{previous}\n{}\n{}",
            sha256_hex(b""),
            sha256_hex(chunk)
        );
        assert_eq!(signature, hex::encode(mac(&key, to_sign.as_bytes())));
        previous = signature.into();
        decoded.extend_from_slice(chunk);
        assert_eq!(&encoded[length..length + 2], b"\r\n");
        encoded = &encoded[length + 2..];
        if length == 0 {
            assert!(encoded.is_empty());
            break;
        }
    }
    assert_eq!(decoded, input);
}

#[tokio::test]
async fn put_failures_remain_failures_even_when_object_exists() {
    for status in [403, 412, 500] {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(failure(status, "Rejected"))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let s3 = client(&server);
        let error = s3
            .put_object("bucket", "key", Bytes::from_static(b"new"), None)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<S3Error>().unwrap().status.as_u16(),
            status
        );
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("input");
        tokio::fs::write(&file, b"new").await.unwrap();
        let error = s3.put_file("bucket", "key", &file, None).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<S3Error>().unwrap().status.as_u16(),
            status
        );
    }
}

#[tokio::test]
async fn conditions_are_signed_only_for_objects_and_completion() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/bucket/key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("data"))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"part\""))
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(query_param("uploads", "")).respond_with(xml("<InitiateMultipartUploadResult><UploadId>id</UploadId></InitiateMultipartUploadResult>")).mount(&server).await;
    Mock::given(method("POST")).and(query_param("uploadId", "id")).respond_with(xml("<CompleteMultipartUploadResult><ETag>&quot;final&quot;</ETag></CompleteMultipartUploadResult>")).mount(&server).await;
    let s3 = client(&server)
        .with_conditions(Some("\"old\"".into()), None)
        .unwrap()
        .with_progress(false);
    s3.get_object("bucket", "key", None).await.unwrap();
    s3.head_object("bucket", "key").await.unwrap();
    s3.put_object("bucket", "key", Bytes::new(), None)
        .await
        .unwrap();
    s3.head_bucket("bucket").await.unwrap();
    s3.create_bucket("bucket").await.unwrap();
    s3.create_multipart_upload("bucket", "key", None)
        .await
        .unwrap();
    s3.upload_part("bucket", "key", "id", 1, Bytes::from_static(b"part"))
        .await
        .unwrap();
    s3.complete_multipart_upload(
        "bucket",
        "key",
        "id",
        &[Part {
            part_number: 1,
            etag: "\"part\"".into(),
            size: Some(4),
        }],
    )
    .await
    .unwrap();
    let requests = server.received_requests().await.unwrap();
    for (index, request) in requests.iter().enumerate() {
        crate::openapi_contract::s3_operation(request);
        let conditioned = matches!(index, 0 | 1 | 2 | 7);
        assert_eq!(
            request.headers.contains_key("if-match"),
            conditioned,
            "request {index}"
        );
        if conditioned {
            assert!(request.headers["authorization"]
                .to_str()
                .unwrap()
                .contains("if-match;"));
        }
    }
}

#[tokio::test]
async fn object_pagination_decodes_xml_once_and_preserves_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(query_param("prefix", "a +!~é")).respond_with(xml("<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>a+ /&amp;!</NextContinuationToken><Contents><Key>a&amp;quot;&#34;&#x26;</Key><ETag>&#34;etag&#34;</ETag><Size>12</Size><LastModified>today</LastModified></Contents></ListBucketResult>")).up_to_n_times(1).mount(&server).await;
    Mock::given(method("GET")).and(query_param("continuation-token", "a+ /&!")).respond_with(xml("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>second</Key><Size>3</Size></Contents></ListBucketResult>")).mount(&server).await;
    let items = client(&server)
        .list_all_objects("bucket", Some("a +!~é"))
        .await
        .unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].key, "a&quot;\"&");
    assert_eq!(items[0].etag.as_deref(), Some("\"etag\""));
    assert_eq!(items[0].size, Some(12));
    assert_eq!(items[0].last_modified.as_deref(), Some("today"));
    let requests = server.received_requests().await.unwrap();
    verify_signature(
        &requests[1],
        "/bucket",
        "continuation-token=a%2B%20%2F%26%21&list-type=2&prefix=a%20%2B%21~%C3%A9",
    );
}

#[tokio::test]
async fn multipart_pagination_distinguishes_part_from_part_number_marker() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(query_param("part-number-marker", "0")).respond_with(xml("<ListPartsResult><PartNumberMarker>0</PartNumberMarker><NextPartNumberMarker>1</NextPartNumberMarker><IsTruncated>true</IsTruncated><Part><PartNumber>1</PartNumber><ETag>&#34;a&amp;quot;&#34;</ETag><Size>8</Size></Part></ListPartsResult>")).mount(&server).await;
    Mock::given(method("GET")).and(query_param("part-number-marker", "1")).respond_with(xml("<ListPartsResult><PartNumberMarker>1</PartNumberMarker><IsTruncated>false</IsTruncated><Part><PartNumber>2</PartNumber><ETag>&quot;b&quot;</ETag><Size>3</Size></Part></ListPartsResult>")).mount(&server).await;
    let parts = client(&server)
        .list_parts("bucket", "key", "id+!&")
        .await
        .unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].etag, "\"a&quot;\"");
    assert_eq!(parts[1].part_number, 2);
    let requests = server.received_requests().await.unwrap();
    verify_signature(
        &requests[1],
        "/bucket/key",
        "part-number-marker=1&uploadId=id%2B%21%26",
    );
}

#[tokio::test]
async fn upload_listing_paginates_with_both_markers_and_returns_keys() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(xml("<ListMultipartUploadsResult><IsTruncated>true</IsTruncated><NextKeyMarker>a&amp;+</NextKeyMarker><NextUploadIdMarker>1+</NextUploadIdMarker><Upload><Key>a&amp;+</Key><UploadId>1+</UploadId><Initiated>now</Initiated></Upload></ListMultipartUploadsResult>")).up_to_n_times(1).mount(&server).await;
    Mock::given(method("GET")).and(query_param("key-marker", "a&+")).and(query_param("upload-id-marker", "1+")).respond_with(xml("<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><Upload><Key>a&amp;+</Key><UploadId>2</UploadId></Upload></ListMultipartUploadsResult>")).mount(&server).await;
    let list = client(&server)
        .list_multipart_uploads("bucket")
        .await
        .unwrap();
    assert_eq!(list.upload_ids, ["1+", "2"]);
    assert_eq!(list.uploads[0].key, "a&+");
}

#[tokio::test]
async fn malformed_and_oversized_control_responses_are_rejected() {
    for body in ["<ListPartsResult><Part><PartNumber>bad</PartNumber></Part></ListPartsResult>".to_owned(),
        "<ListPartsResult/><ListPartsResult/>".into(), "<!DOCTYPE x><ListPartsResult/>".into(),
        "<ListPartsResult><IsTruncated>true</IsTruncated><NextPartNumberMarker>0</NextPartNumberMarker></ListPartsResult>".into(),
        "x".repeat(MAX_CONTROL_BYTES + 1)] {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(xml(body)).expect(1).mount(&server).await;
        assert!(client(&server).list_parts("bucket", "key", "id").await.is_err());
    }
}

#[tokio::test]
async fn retry_policy_uses_typed_status_and_exhausts_exact_budget() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(failure(503, "ServiceUnavailable"))
        .expect((MAX_RETRIES + 1) as u64)
        .mount(&server)
        .await;
    let error = client(&server)
        .get_object("bucket", "key", None)
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<S3Error>().unwrap().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).set_body_string("500 Internal Error"))
        .expect(1)
        .mount(&server)
        .await;
    assert!(client(&server)
        .get_object("bucket", "key", None)
        .await
        .is_err());
    assert!(!retryable(&anyhow!("S3 request failed with 503")));
}

#[tokio::test]
async fn completion_replays_identical_xml_and_conditions_after_embedded_error() {
    let server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    Mock::given(method("POST")).respond_with(move |_: &Request| {
        if count.fetch_add(1, Ordering::SeqCst) == 0 { failure(200, "ServiceUnavailable") }
        else { xml("<CompleteMultipartUploadResult><ETag>&quot;done&quot;</ETag></CompleteMultipartUploadResult>") }
    }).expect(2).mount(&server).await;
    let parts = [Part {
        part_number: 1,
        etag: "\"a&<b>\"".into(),
        size: Some(4),
    }];
    client(&server)
        .with_conditions(None, Some("*".into()))
        .unwrap()
        .complete_multipart_upload("bucket", "key", "id", &parts)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests[0].body, requests[1].body);
    assert_eq!(requests[1].headers["if-none-match"], "*");
    assert!(String::from_utf8_lossy(&requests[0].body).contains("&amp;"));
    verify_signature(&requests[1], "/bucket/key", "uploadId=id");
}

#[tokio::test]
async fn completion_refusal_or_wrong_document_never_succeeds() {
    for template in [
        failure(200, "AccessDenied"),
        failure(412, "PreconditionFailed"),
        xml("<ListPartsResult/>"),
        xml(""),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(template)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        assert!(client(&server)
            .complete_multipart_upload(
                "bucket",
                "key",
                "id",
                &[Part {
                    part_number: 1,
                    etag: "etag".into(),
                    size: None
                }]
            )
            .await
            .is_err());
    }
}

fn listed_parts() -> ResponseTemplate {
    xml(format!("<ListPartsResult><PartNumberMarker>0</PartNumberMarker><IsTruncated>false</IsTruncated><Part><PartNumber>1</PartNumber><ETag>&quot;p1&quot;</ETag><Size>{MULTIPART_PART_SIZE}</Size></Part></ListPartsResult>"))
}

#[tokio::test]
async fn resume_without_manifest_reuploads_same_size_parts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(listed_parts())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"new\""))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(xml(
            "<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    let data = vec![b'x'; MULTIPART_PART_SIZE + 91];
    tokio::fs::write(&path, &data).await.unwrap();
    let state = tempfile::tempdir().unwrap();
    client(&server)
        .with_state_directory(state.path().to_path_buf())
        .put_file_resumable("bucket", "key", &path, None, Some("id"))
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    let parts: Vec<_> = requests.iter().filter(|r| r.method == "PUT").collect();
    assert_eq!(parts[0].body.len(), MULTIPART_PART_SIZE);
    assert_eq!(parts[1].body.len(), 91);
    assert_eq!(parts[0].body, data[..MULTIPART_PART_SIZE]);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn resume_manifest_rejects_changed_same_length_file_and_reuses_verified_parts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(listed_parts())
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(query_param("partNumber", "1"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"p1\""))
        .expect(1)
        .mount(&server)
        .await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    Mock::given(method("PUT"))
        .and(query_param("partNumber", "2"))
        .respond_with(move |_: &Request| {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                failure(403, "AccessDenied")
            } else {
                ResponseTemplate::new(200).insert_header("etag", "\"p2\"")
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(xml(
            "<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    let data = vec![b'x'; MULTIPART_PART_SIZE + 17];
    tokio::fs::write(&path, &data).await.unwrap();
    let state = tempfile::tempdir().unwrap();
    let s3 = client(&server).with_state_directory(state.path().to_path_buf());
    assert!(s3
        .put_file_resumable("bucket", "key", &path, None, Some("id"))
        .await
        .is_err());
    let before = server.received_requests().await.unwrap().len();
    tokio::fs::write(&path, vec![b'y'; data.len()])
        .await
        .unwrap();
    let error = s3
        .put_file_resumable("bucket", "key", &path, None, Some("id"))
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("differs from file content"));
    assert_eq!(server.received_requests().await.unwrap().len(), before);
    tokio::fs::write(&path, &data).await.unwrap();
    s3.put_file_resumable("bucket", "key", &path, None, Some("id"))
        .await
        .unwrap();
}

#[tokio::test]
async fn resume_after_uncertain_completion_replays_without_reuploading_parts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(listed_parts())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"p1\""))
        .expect(1)
        .mount(&server)
        .await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    Mock::given(method("POST")).respond_with(move |_: &Request| {
        if count.fetch_add(1, Ordering::SeqCst) <= MAX_RETRIES { failure(503, "ServiceUnavailable") }
        else { xml("<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>") }
    }).expect((MAX_RETRIES + 2) as u64).mount(&server).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    tokio::fs::write(&path, vec![b'x'; MULTIPART_PART_SIZE])
        .await
        .unwrap();
    let state = tempfile::tempdir().unwrap();
    let s3 = client(&server)
        .with_state_directory(state.path().to_path_buf())
        .with_conditions(None, Some("*".into()))
        .unwrap();
    assert!(s3
        .put_file_resumable("bucket", "key", &path, None, Some("id"))
        .await
        .is_err());
    s3.put_file_resumable("bucket", "key", &path, None, Some("id"))
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    let completions: Vec<_> = requests.iter().filter(|r| r.method == "POST").collect();
    assert!(completions.windows(2).all(|p| p[0].body == p[1].body));
}

#[tokio::test]
async fn downloads_replace_atomically_and_check_pipe_content_hash() {
    let server = MockServer::start().await;
    let data = b"downloaded";
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(data)
                .insert_header("etag", format!("\"{}\"", blake3::hash(data).to_hex())),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output");
    tokio::fs::write(&path, b"old").await.unwrap();
    assert_eq!(
        client(&server)
            .get_to_file("bucket", "key", &path, None)
            .await
            .unwrap(),
        data.len() as u64
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn failed_downloads_preserve_destination_and_remove_temporary_files() {
    for response in [
        failure(403, "AccessDenied"),
        ResponseTemplate::new(200)
            .set_body_string("wrong")
            .insert_header(
                "etag",
                format!("\"{}\"", blake3::hash(b"expected").to_hex()),
            ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(response)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output");
        tokio::fs::write(&path, b"old").await.unwrap();
        assert!(client(&server)
            .get_to_file("bucket", "key", &path, None)
            .await
            .is_err());
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"old");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[tokio::test]
async fn interrupted_response_preserves_old_download_and_removes_partial_file() {
    // WireMock always emits complete HTTP bodies. A minimal raw peer supplies
    // the transport failure that a normal mock response cannot express.
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial",
            )
            .unwrap();
    });
    let mut profile = Profile::new("https://control.example");
    profile.s3_endpoint = Some(format!("http://{address}"));
    let client = S3Client::new(&profile, "AKID".into(), "secret".into()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output");
    tokio::fs::write(&path, b"old").await.unwrap();
    assert!(client
        .get_to_file("bucket", "key", &path, None)
        .await
        .is_err());
    assert_eq!(tokio::fs::read(&path).await.unwrap(), b"old");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    peer.join().unwrap();
}

#[tokio::test]
async fn streaming_progress_counts_payload_and_errors_end_the_stream() {
    use futures_util::StreamExt;
    let progress = ProgressBar::hidden();
    let signer = sigv4::StreamingSigner::new(
        "secret",
        "20260916/us-east-1/s3/aws4_request",
        "20260916T000000Z",
        &"a".repeat(64),
    )
    .unwrap();
    let inner = futures_util::stream::iter([
        Ok(Bytes::new()),
        Ok(Bytes::from_static(b"abc")),
        Err(std::io::Error::other("source interrupted")),
        Ok(Bytes::from_static(b"ignored")),
    ]);
    let mut stream = AwsChunkedStream {
        inner,
        signer: Some(signer),
        progress: progress.clone(),
    };
    assert!(stream.next().await.unwrap().is_ok());
    assert_eq!(progress.position(), 3);
    assert!(stream.next().await.unwrap().is_err());
    assert!(stream.next().await.is_none());
    assert_eq!(progress.position(), 3);
}

#[tokio::test]
async fn huge_http_error_preserves_status_for_downcasting() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string("x".repeat(MAX_ERROR_BYTES + 1)))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server)
        .get_object("bucket", "key", None)
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<S3Error>().unwrap().status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn error_responses_never_echo_server_text_and_not_implemented_is_clear() {
    for body in [
        "submittedCredentialSecret".to_owned(),
        "<Error><Code>AccessDenied</Code><Message>submittedCredentialSecret</Message></Error>"
            .into(),
        "<Error><Code>submittedCredentialSecret</Code></Error>".into(),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_string(body))
            .mount(&server)
            .await;
        let error = client(&server)
            .get_object("bucket", "key", None)
            .await
            .unwrap_err();
        assert!(!format!("{error:#}").contains("submittedCredentialSecret"));
    }
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(failure(501, "NotImplemented"))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server)
        .get_object("bucket", "key", None)
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<S3Error>().unwrap().code,
        "NotImplemented"
    );
    assert!(error.to_string().contains("not supported by Pipe"));
}

#[test]
fn direct_client_construction_enforces_profile_https_and_valid_region() {
    let mut profile = Profile::new("https://control.example");
    profile.s3_endpoint = Some("http://s3.example".into());
    assert!(S3Client::new(&profile, "AKID".into(), "secret".into()).is_err());
    profile.s3_endpoint = Some("https://s3.example".into());
    profile.region = "bad/region".into();
    assert!(S3Client::new(&profile, "AKID".into(), "secret".into()).is_err());
}

#[tokio::test]
async fn range_download_checks_status_bounds_and_actual_length() {
    for (response, success) in [
        (
            ResponseTemplate::new(206)
                .set_body_string("234")
                .insert_header("content-range", "bytes 2-4/5"),
            true,
        ),
        (ResponseTemplate::new(200).set_body_string("01234"), false),
        (
            ResponseTemplate::new(206)
                .set_body_string("234")
                .insert_header("content-range", "bytes 1-3/5"),
            false,
        ),
        (
            ResponseTemplate::new(206)
                .set_body_string("23")
                .insert_header("content-range", "bytes 2-4/5"),
            false,
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(response)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output");
        tokio::fs::write(&path, b"old").await.unwrap();
        let result = client(&server)
            .get_to_file("bucket", "key", &path, Some((2, 8)))
            .await;
        assert_eq!(result.is_ok(), success);
        assert_eq!(
            tokio::fs::read(&path).await.unwrap(),
            if success { b"234" } else { b"old" }
        );
    }
}

#[test]
fn invalid_conditions_and_unsafe_path_normalization_are_rejected() {
    assert!(validate_conditions(Some("etag\r\ninjected: yes"), None).is_err());
    assert!(validate_conditions(None, Some(" ")).is_err());
    assert_eq!(sigv4::encode_path("/bucket/%2e%2e"), "/bucket/%252e%252e");
    assert_eq!(
        sigv4::canonical_path("/bucket/a%2fb+c"),
        "/bucket/a%2Fb%2Bc"
    );
}

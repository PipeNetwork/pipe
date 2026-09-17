//! Small AWS Signature Version 4 implementation for Pipe's S3-compatible
//! gateway. It deliberately does not depend on the AWS SDK so Pipe-specific
//! compatibility rules remain visible at the call site.

use chrono::Utc;
use hmac::{Hmac, Mac};
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};
use reqwest::{Method, Url};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;
pub const STREAMING_PAYLOAD_HASH: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
const QUERY_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonical_path(path: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    path.split('/')
        // Decode within each segment so an encoded slash stays encoded.
        .map(|segment| {
            percent_encode(
                &percent_encoding::percent_decode_str(segment).collect::<Vec<_>>(),
                QUERY_SET,
            )
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Encode a raw object path. Unlike canonical_path, literal '%' is data.
pub fn encode_path(path: &str) -> String {
    path.split('/')
        .map(encode_query)
        .collect::<Vec<_>>()
        .join("/")
}

pub fn canonical_query(url: &Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (encode_query(&k), encode_query(&v)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn encode_query(value: &str) -> String {
    percent_encode(value.as_bytes(), QUERY_SET).to_string()
}

#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &Method,
    url: &Url,
    region: &str,
    access_key: &str,
    secret_key: &str,
    mut headers: BTreeMap<String, String>,
    payload_hash: &str,
    now: chrono::DateTime<Utc>,
) -> BTreeMap<String, String> {
    headers = headers
        .into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), normalize(&v)))
        .collect();
    headers.remove("authorization");
    let host = url.host_str().unwrap_or_default().to_owned();
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    headers.insert("host".into(), host);
    headers.insert("x-amz-content-sha256".into(), payload_hash.into());
    let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    headers.insert("x-amz-date".into(), timestamp.clone());
    let canonical_headers = headers
        .iter()
        .map(|(key, value)| format!("{}:{}\n", key.to_ascii_lowercase(), normalize(value)))
        .collect::<String>();
    let signed_headers = headers
        .keys()
        .map(|key| key.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_path(url.path()),
        canonical_query(url),
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let date = now.format("%Y%m%d").to_string();
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signing_key = derive_key(secret_key, &date, region, "s3");
    let signature = hex::encode(hmac(&signing_key, string_to_sign.as_bytes()));
    headers.insert("authorization".into(), format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"));
    headers
}

fn normalize(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
fn hmac(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}
fn derive_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let date_key = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let region_key = hmac(&date_key, region.as_bytes());
    let service_key = hmac(&region_key, service.as_bytes());
    hmac(&service_key, b"aws4_request")
}

pub struct StreamingSigner {
    signing_key: Vec<u8>,
    timestamp: String,
    scope: String,
    previous_signature: String,
}

impl StreamingSigner {
    pub fn new(
        secret: &str,
        scope: &str,
        timestamp: &str,
        seed_signature: &str,
    ) -> Result<Self, String> {
        let parts: Vec<&str> = scope.split('/').collect();
        if parts.len() != 4 || parts[2] != "s3" || parts[3] != "aws4_request" {
            return Err("invalid SigV4 credential scope".into());
        }
        Ok(Self {
            signing_key: derive_key(secret, parts[0], parts[1], parts[2]),
            timestamp: timestamp.to_owned(),
            scope: scope.to_owned(),
            previous_signature: seed_signature.to_owned(),
        })
    }

    pub fn chunk(&mut self, data: &[u8]) -> Vec<u8> {
        let signature = self.chunk_signature(data);
        let mut encoded = format!("{:x};chunk-signature={signature}\r\n", data.len()).into_bytes();
        encoded.extend_from_slice(data);
        encoded.extend_from_slice(b"\r\n");
        encoded
    }

    pub fn final_chunk(&mut self) -> Vec<u8> {
        let signature = self.chunk_signature(&[]);
        format!("0;chunk-signature={signature}\r\n\r\n").into_bytes()
    }

    fn chunk_signature(&mut self, data: &[u8]) -> String {
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            self.timestamp,
            self.scope,
            self.previous_signature,
            sha256_hex(b""),
            sha256_hex(data)
        );
        let signature = hex::encode(hmac(&self.signing_key, string_to_sign.as_bytes()));
        self.previous_signature = signature.clone();
        signature
    }
}

impl Drop for StreamingSigner {
    fn drop(&mut self) {
        self.signing_key.zeroize();
        self.previous_signature.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Published AWS fixtures, not expected values generated by this signer:
    // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
    #[test]
    fn aws_published_header_signatures() {
        let now = "2013-05-24T00:00:00Z"
            .parse::<chrono::DateTime<Utc>>()
            .unwrap();
        let fixtures = [
            (
                Method::GET,
                "/test.txt",
                vec![("range", "bytes=0-9")],
                b"".as_slice(),
                "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            ),
            (
                Method::PUT,
                "/test%24file.text",
                vec![
                    ("date", "Fri, 24 May 2013 00:00:00 GMT"),
                    ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                ],
                b"Welcome to Amazon S3.".as_slice(),
                "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
            ),
            (
                Method::GET,
                "/?lifecycle",
                vec![],
                b"".as_slice(),
                "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
            ),
            (
                Method::GET,
                "/?prefix=J&max-keys=2",
                vec![],
                b"".as_slice(),
                "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
            ),
        ];
        for (method, path, headers, body, expected) in fixtures {
            let signed = sign(
                &method,
                &Url::parse(&format!("https://examplebucket.s3.amazonaws.com{path}")).unwrap(),
                "us-east-1",
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                headers
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
                &sha256_hex(body),
                now,
            );
            assert_eq!(
                signed["authorization"].split("Signature=").nth(1).unwrap(),
                expected,
                "{path}"
            );
        }
    }

    // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html
    #[test]
    fn aws_published_streaming_seed_and_all_chunk_signatures() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let headers = [
            ("content-encoding", "aws-chunked"),
            ("content-length", "66824"),
            ("x-amz-decoded-content-length", "66560"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let signed = sign(
            &Method::PUT,
            &Url::parse("https://s3.amazonaws.com/examplebucket/chunkObject.txt").unwrap(),
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            secret,
            headers,
            STREAMING_PAYLOAD_HASH,
            "2013-05-24T00:00:00Z".parse().unwrap(),
        );
        assert_eq!(
            signed["authorization"].split("Signature=").nth(1).unwrap(),
            seed
        );
        let mut signer = StreamingSigner::new(
            secret,
            "20130524/us-east-1/s3/aws4_request",
            "20130524T000000Z",
            seed,
        )
        .unwrap();
        let first = signer.chunk(&vec![b'a'; 65536]);
        let second = signer.chunk(&vec![b'a'; 1024]);
        let last = signer.final_chunk();
        assert!(first.starts_with(b"10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n"));
        assert!(second.starts_with(b"400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n"));
        assert_eq!(last, b"0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n\r\n");
        assert_eq!(first.len() + second.len() + last.len(), 66824);
    }

    #[test]
    fn path_and_query_are_canonicalized_without_virtual_hosting() {
        let url = Url::parse("https://example.test/bucket/a%20b?z=two words&a=1").unwrap();
        assert_eq!(canonical_path(url.path()), "/bucket/a%20b");
        assert_eq!(canonical_query(&url), "a=1&z=two%20words");
    }

    #[test]
    fn query_sorts_encoded_names_and_values_and_uses_rfc3986_unreserved_set() {
        let url =
            Url::parse("https://example.test/?z=0&é=1&!=2&a=é&a=z&a=%21&plus=%2B&space=+").unwrap();
        assert_eq!(
            canonical_query(&url),
            "%21=2&%C3%A9=1&a=%21&a=%C3%A9&a=z&plus=%2B&space=%20&z=0"
        );
        assert_eq!(encode_query("-_.~!*'()"), "-_.~%21%2A%27%28%29");
    }

    #[test]
    fn raw_path_encoding_and_wire_canonicalization_have_distinct_percent_semantics() {
        assert_eq!(encode_path("/b/%2F+é!"), "/b/%252F%2B%C3%A9%21");
        assert_eq!(
            canonical_path("/b/%252F%2B%C3%A9%21"),
            "/b/%252F%2B%C3%A9%21"
        );
        assert_eq!(canonical_path("/b/a%2fb/%7e"), "/b/a%2Fb/~");
    }

    #[test]
    fn signing_contains_pipe_safe_payload_hash() {
        let url = Url::parse("https://example.test/bucket/key").unwrap();
        let headers = sign(
            &Method::PUT,
            &url,
            "us-east-1",
            "AKID",
            "secret",
            BTreeMap::new(),
            &sha256_hex(b"body"),
            Utc::now(),
        );
        assert!(headers.contains_key("authorization"));
        assert_eq!(headers["x-amz-content-sha256"], sha256_hex(b"body"));
    }

    #[test]
    fn streaming_signer_frames_data_and_final_chunk() {
        let mut signer = StreamingSigner::new(
            "secret",
            "20260916/us-east-1/s3/aws4_request",
            "20260916T000000Z",
            &"a".repeat(64),
        )
        .unwrap();
        let chunk = signer.chunk(b"hello");
        let text = String::from_utf8(chunk).unwrap();
        assert!(text.starts_with("5;chunk-signature="));
        assert!(text.ends_with("\r\nhello\r\n"));
        let final_chunk = String::from_utf8(signer.final_chunk()).unwrap();
        assert!(final_chunk.starts_with("0;chunk-signature="));
        assert!(final_chunk.ends_with("\r\n\r\n"));
    }
}

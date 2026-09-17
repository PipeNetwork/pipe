//! Path-style S3 transport for Pipe. ETags are opaque content identities, not MD5.

use crate::{
    config::Profile,
    sigv4::{self, sha256_hex},
};
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures_util::Stream;
use indicatif::ProgressBar;
use reqwest::{Body, Client, Method, Response, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;

pub const MAX_RANGE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_RETRIES: usize = 3;
const MULTIPART_THRESHOLD: u64 = 8 * 1024 * 1024;
const MULTIPART_PART_SIZE: usize = 8 * 1024 * 1024;
const MAX_PARTS: usize = 10_000;
const MAX_CONTROL_BYTES: usize = 4 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 64 * 1024;
const MAX_LIST_ITEMS: usize = 1_000_000;
const CONTROL_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct S3Client {
    http: Client,
    endpoint: Url,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
    progress: bool,
    state_directory: PathBuf,
}

/// Preserved through anyhow contexts; callers can downcast without parsing text.
#[derive(Debug, thiserror::Error)]
#[error("S3 request failed with {status} ({code}): {message}")]
pub struct S3Error {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

impl S3Error {
    pub fn is_retryable(&self) -> bool {
        matches!(self.status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504)
            || (self.status.is_success()
                && matches!(
                    self.code.as_str(),
                    "InternalError" | "ServiceUnavailable" | "SlowDown" | "RequestTimeout"
                ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectInfo {
    #[serde(rename(deserialize = "Key"))]
    pub key: String,
    #[serde(rename(deserialize = "ETag"), default)]
    pub etag: Option<String>,
    #[serde(rename(deserialize = "Size"), default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(rename(deserialize = "LastModified"), default)]
    pub last_modified: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Part {
    pub part_number: u32,
    pub etag: String,
    pub size: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultipartUpload {
    #[serde(rename(deserialize = "Key"))]
    pub key: String,
    #[serde(rename(deserialize = "UploadId"))]
    pub upload_id: String,
    #[serde(rename(deserialize = "Initiated"), default)]
    pub initiated: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ValueList {
    pub upload_ids: Vec<String>,
    pub uploads: Vec<MultipartUpload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ObjectPage {
    #[serde(rename = "Contents", default)]
    contents: Vec<ObjectInfo>,
    #[serde(default)]
    is_truncated: bool,
    next_continuation_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PartXml {
    part_number: u32,
    #[serde(rename = "ETag")]
    etag: String,
    size: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PartPage {
    #[serde(rename = "Part", default)]
    parts: Vec<PartXml>,
    #[serde(default)]
    is_truncated: bool,
    next_part_number_marker: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UploadPage {
    #[serde(rename = "Upload", default)]
    uploads: Vec<MultipartUpload>,
    #[serde(default)]
    is_truncated: bool,
    next_key_marker: Option<String>,
    next_upload_id_marker: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ErrorXml {
    code: String,
}

#[derive(Deserialize)]
struct Initiated {
    #[serde(rename = "UploadId")]
    upload_id: String,
}

#[derive(Deserialize)]
struct Completed {
    #[serde(rename = "ETag")]
    etag: String,
}

#[derive(Serialize)]
#[serde(rename = "CompleteMultipartUpload")]
struct Completion<'a> {
    #[serde(rename = "Part")]
    parts: Vec<CompletionPart<'a>>,
}

#[derive(Serialize)]
struct CompletionPart<'a> {
    #[serde(rename = "PartNumber")]
    number: u32,
    #[serde(rename = "ETag")]
    etag: &'a str,
}

/// A resume is bound to content, destination, and completion preconditions.
/// Part ETags are reused only when both this record and the remote list agree.
#[derive(Serialize, Deserialize)]
struct ResumeManifest {
    version: u32,
    identity: String,
    content_hash: String,
    size: u64,
    content_type: Option<String>,
    if_match: Option<String>,
    if_none_match: Option<String>,
    parts: Vec<Part>,
    completing: bool,
}

impl S3Client {
    pub fn new(
        profile: &Profile,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<Self> {
        profile.validate()?;
        let endpoint = profile.s3_endpoint.as_deref().ok_or_else(|| {
            anyhow!(
                "S3 endpoint is not configured; run 'pipe s3 endpoint' or set it in the profile"
            )
        })?;
        let endpoint = Url::parse(endpoint).context("parse S3 endpoint")?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            bail!("S3 endpoint must be an HTTP(S) origin without credentials, path, query, or fragment");
        }
        Ok(Self {
            http: Client::builder()
                .user_agent(format!("pipe-cli/{}", env!("CARGO_PKG_VERSION")))
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(15))
                .read_timeout(Duration::from_secs(60))
                .build()?,
            endpoint,
            region: profile.region.clone(),
            access_key_id,
            secret_access_key,
            if_match: None,
            if_none_match: None,
            progress: false,
            state_directory: dirs::cache_dir()
                .ok_or_else(|| anyhow!("cannot locate Pipe upload state directory"))?
                .join("pipe")
                .join("uploads"),
        })
    }

    pub fn from_parts(
        profile: &Profile,
        access_key_id: &str,
        secret_access_key: String,
    ) -> Result<Self> {
        Self::new(profile, access_key_id.to_owned(), secret_access_key)
    }

    pub fn with_conditions(
        mut self,
        if_match: Option<String>,
        if_none_match: Option<String>,
    ) -> Result<Self> {
        validate_conditions(if_match.as_deref(), if_none_match.as_deref())?;
        self.if_match = if_match;
        self.if_none_match = if_none_match;
        Ok(self)
    }

    pub fn with_progress(mut self, enabled: bool) -> Self {
        self.progress = enabled;
        self
    }

    /// Keep resume records outside input trees, including read-only sources.
    pub fn with_state_directory(mut self, directory: PathBuf) -> Self {
        self.state_directory = directory;
        self
    }

    /// Stable scope for local sync state; excludes the secret and object keys.
    pub fn endpoint_identity(&self) -> String {
        let identity = serde_json::to_vec(&(
            self.endpoint.as_str(),
            self.access_key_id.as_str(),
            self.region.as_str(),
        ))
        .expect("serializing an array of strings cannot fail");
        sha256_hex(&identity)
    }

    fn progress(&self, size: u64) -> ProgressBar {
        if self.progress {
            ProgressBar::new(size)
        } else {
            ProgressBar::hidden()
        }
    }

    fn object_headers(
        &self,
        hash: &str,
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<BTreeMap<String, String>> {
        let if_match = if_match.or(self.if_match.as_deref());
        let if_none_match = if_none_match.or(self.if_none_match.as_deref());
        validate_conditions(if_match, if_none_match)?;
        let mut headers = self.headers(hash);
        if let Some(value) = if_match {
            headers.insert("if-match".into(), value.into());
        }
        if let Some(value) = if_none_match {
            headers.insert("if-none-match".into(), value.into());
        }
        Ok(headers)
    }

    fn headers(&self, hash: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("x-amz-content-sha256".into(), hash.into())])
    }

    fn url(&self, bucket: &str, key: Option<&str>, query: Option<&str>) -> Result<Url> {
        if bucket.is_empty() || bucket.contains('/') || matches!(bucket, "." | "..") {
            bail!("invalid bucket name");
        }
        let mut path = format!("/{bucket}");
        if let Some(key) = key {
            if key.is_empty() {
                bail!("object key cannot be empty");
            }
            // WHATWG URLs normalize dot segments, even when percent encoded.
            // Reject them rather than silently operate on a different object.
            if key.split('/').any(|segment| matches!(segment, "." | "..")) {
                bail!("object keys containing dot path segments cannot be represented by this HTTP client");
            }
            path.push('/');
            path.push_str(key);
        }
        let path = sigv4::encode_path(&path);
        let mut url = Url::parse(&format!(
            "{}{}",
            self.endpoint.as_str().trim_end_matches('/'),
            path
        ))?;
        if url.path() != path {
            bail!("HTTP URL normalization would change the object key");
        }
        url.set_query(query);
        Ok(url)
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        headers: BTreeMap<String, String>,
        body: Option<Body>,
        retry_safe: bool,
    ) -> Result<Response> {
        // Streaming bodies cannot be replayed. Byte bodies use send_replayable.
        let mut body = body;
        let retries = if retry_safe && body.is_none() {
            MAX_RETRIES
        } else {
            0
        };
        for attempt in 0..=retries {
            let hash = headers
                .get("x-amz-content-sha256")
                .cloned()
                .unwrap_or_else(|| sha256_hex(b""));
            let signed = sigv4::sign(
                &method,
                &url,
                &self.region,
                &self.access_key_id,
                &self.secret_access_key,
                headers.clone(),
                &hash,
                chrono::Utc::now(),
            );
            let mut request = self.http.request(method.clone(), url.clone());
            for (name, value) in signed {
                request = request.header(name, value);
            }
            if let Some(body) = body.take() {
                request = request.body(body);
            }
            let result = match request.send().await {
                Ok(response) => self.check_response(response).await,
                Err(error) => Err(error.into()),
            };
            match result {
                Err(error) if attempt < retries && retryable(&error) => {
                    tokio::time::sleep(backoff(attempt + 1)).await
                }
                result => return result,
            }
        }
        unreachable!()
    }

    async fn send_replayable(
        &self,
        method: Method,
        url: Url,
        headers: BTreeMap<String, String>,
        body: Bytes,
    ) -> Result<Response> {
        for attempt in 0..=MAX_RETRIES {
            match self
                .send(
                    method.clone(),
                    url.clone(),
                    headers.clone(),
                    Some(Body::from(body.clone())),
                    false,
                )
                .await
            {
                Err(error) if attempt < MAX_RETRIES && retryable(&error) => {
                    tokio::time::sleep(backoff(attempt + 1)).await
                }
                result => return result,
            }
        }
        unreachable!()
    }

    async fn check_response(&self, response: Response) -> Result<Response> {
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        // Keep the HTTP failure typed even if its body is too large or broken.
        let body = bounded_body(response, MAX_ERROR_BYTES).await;
        let code = match body {
            Ok(bytes) => match parse_xml::<ErrorXml>(&bytes, "Error") {
                Ok(error) => error.code,
                Err(_) => "HttpError".into(),
            },
            Err(_) => "HttpError".into(),
        };
        Err(s3_error(status, code).into())
    }

    pub async fn create_bucket(&self, bucket: &str) -> Result<()> {
        self.send(
            Method::PUT,
            self.url(bucket, None, None)?,
            self.headers(&sha256_hex(b"")),
            None,
            true,
        )
        .await
        .map(|_| ())
    }
    pub async fn head_bucket(&self, bucket: &str) -> Result<()> {
        self.send(
            Method::HEAD,
            self.url(bucket, None, None)?,
            self.headers(&sha256_hex(b"")),
            None,
            true,
        )
        .await
        .map(|_| ())
    }
    pub async fn delete_bucket(&self, bucket: &str) -> Result<()> {
        self.send(
            Method::DELETE,
            self.url(bucket, None, None)?,
            self.headers(&sha256_hex(b"")),
            None,
            true,
        )
        .await
        .map(|_| ())
    }

    /// Fetch one page. Use list_all_objects to collect every page.
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        continuation: Option<&str>,
    ) -> Result<(Vec<ObjectInfo>, Option<String>)> {
        let mut query = String::from("list-type=2");
        if let Some(prefix) = prefix {
            query.push_str(&format!("&prefix={}", sigv4::encode_query(prefix)));
        }
        if let Some(token) = continuation {
            query.push_str(&format!(
                "&continuation-token={}",
                sigv4::encode_query(token)
            ));
        }
        let response = self
            .send(
                Method::GET,
                self.url(bucket, None, Some(&query))?,
                self.headers(&sha256_hex(b"")),
                None,
                true,
            )
            .await?;
        let page: ObjectPage = read_xml(response, "ListBucketResult").await?;
        let next = if page.is_truncated {
            let token = page
                .next_continuation_token
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("truncated object list omitted continuation token"))?;
            if Some(token.as_str()) == continuation {
                bail!("object pagination did not advance");
            }
            Some(token)
        } else {
            None
        };
        Ok((page.contents, next))
    }

    pub async fn list_all_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
    ) -> Result<Vec<ObjectInfo>> {
        let mut items = Vec::new();
        let mut continuation = None;
        let mut seen = HashSet::new();
        loop {
            let (page, next) = self
                .list_objects(bucket, prefix, continuation.as_deref())
                .await?;
            if items.len() + page.len() > MAX_LIST_ITEMS {
                bail!("object listing exceeds client item limit; use paginated list_objects");
            }
            items.extend(page);
            match next {
                Some(token) if seen.insert(token.clone()) => continuation = Some(token),
                Some(_) => bail!("object pagination repeated a continuation token"),
                None => return Ok(items),
            }
            if seen.len() > MAX_LIST_ITEMS {
                bail!("object pagination exceeds client page limit");
            }
        }
    }

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        data: Bytes,
        content_type: Option<&str>,
    ) -> Result<()> {
        self.put_object_conditional(bucket, key, data, content_type, None, None)
            .await
    }

    pub async fn put_object_conditional(
        &self,
        bucket: &str,
        key: &str,
        data: Bytes,
        content_type: Option<&str>,
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<()> {
        let mut headers = self.object_headers(&sha256_hex(&data), if_match, if_none_match)?;
        if let Some(value) = content_type {
            headers.insert("content-type".into(), value.into());
        }
        // A preexisting object proves nothing about a failed write. In particular
        // never turn a 403/412/5xx into success after an unrelated HEAD succeeds.
        self.send(
            Method::PUT,
            self.url(bucket, Some(key), None)?,
            headers,
            Some(Body::from(data)),
            false,
        )
        .await
        .map(|_| ())
        .context(
            "object PUT failed; an interrupted response may require reconciliation before retrying",
        )
    }

    pub async fn put_file(
        &self,
        bucket: &str,
        key: &str,
        path: &Path,
        content_type: Option<&str>,
    ) -> Result<()> {
        self.put_file_observed(bucket, key, path, content_type)
            .await
            .map(|_| ())
    }

    /// Return the ETag acknowledged by this write, without a follow-up read.
    /// None means a successful single PUT omitted a usable ETag header.
    pub async fn put_file_observed(
        &self,
        bucket: &str,
        key: &str,
        path: &Path,
        content_type: Option<&str>,
    ) -> Result<Option<String>> {
        self.put_file_resumable_observed(bucket, key, path, content_type, None)
            .await
    }

    pub async fn put_file_resumable(
        &self,
        bucket: &str,
        key: &str,
        path: &Path,
        content_type: Option<&str>,
        resume_upload_id: Option<&str>,
    ) -> Result<()> {
        self.put_file_resumable_observed(bucket, key, path, content_type, resume_upload_id)
            .await
            .map(|_| ())
    }

    /// Receipt-preserving variant, including replay of uncertain completion.
    pub async fn put_file_resumable_observed(
        &self,
        bucket: &str,
        key: &str,
        path: &Path,
        content_type: Option<&str>,
        resume_upload_id: Option<&str>,
    ) -> Result<Option<String>> {
        self.url(bucket, Some(key), None)?;
        self.object_headers(&sha256_hex(b""), None, None)?;
        if resume_upload_id == Some("") {
            bail!("upload ID cannot be empty");
        }
        // Bind the manifest to the snapshot actually uploaded. Later edits of
        // the source cannot change bytes after this identity is computed.
        let (snapshot, size, content_hash) = snapshot(path).await?;
        if size < MULTIPART_THRESHOLD && resume_upload_id.is_none() {
            let mut headers = self.object_headers(sigv4::STREAMING_PAYLOAD_HASH, None, None)?;
            headers.insert("content-encoding".into(), "aws-chunked".into());
            headers.insert("x-amz-decoded-content-length".into(), size.to_string());
            if let Some(value) = content_type {
                headers.insert("content-type".into(), value.into());
            }
            let progress = self.progress(size);
            let result = self
                .send_streaming_file(bucket, key, snapshot.path(), headers, progress.clone())
                .await
                .map(|response| {
                    response
                        .headers()
                        .get("etag")
                        .and_then(|value| value.to_str().ok())
                        .filter(|value| !value.trim().is_empty())
                        .map(str::to_owned)
                });
            progress.finish_and_clear();
            return result.context("object PUT failed; an interrupted response may require reconciliation before retrying");
        }
        if size == 0 || size.div_ceil(MULTIPART_PART_SIZE as u64) > MAX_PARTS as u64 {
            bail!("multipart file must contain 1..=10000 parts of at most 8 MiB");
        }
        let upload_id = match resume_upload_id {
            Some(id) => id.to_owned(),
            None => {
                self.create_multipart_upload(bucket, key, content_type)
                    .await?
            }
        };
        let result = self
            .upload_snapshot(
                bucket,
                key,
                snapshot.path(),
                size,
                &content_hash,
                content_type,
                &upload_id,
                resume_upload_id.is_some(),
            )
            .await;
        result.with_context(|| format!("multipart upload {upload_id} stopped; resume with --upload-id {upload_id} or abort it explicitly"))
    }

    #[allow(clippy::too_many_arguments)]
    async fn upload_snapshot(
        &self,
        bucket: &str,
        key: &str,
        snapshot: &Path,
        size: u64,
        content_hash: &str,
        content_type: Option<&str>,
        upload_id: &str,
        resuming: bool,
    ) -> Result<Option<String>> {
        let identity = sha256_hex(&serde_json::to_vec(&(
            self.endpoint.as_str(),
            &self.access_key_id,
            bucket,
            key,
            upload_id,
        ))?);
        tokio::fs::create_dir_all(&self.state_directory)
            .await
            .context("create multipart state directory")?;
        let manifest_path = self
            .state_directory
            .join(format!(".pipe-upload-{identity}.json"));
        let mut manifest = if resuming {
            match tokio::fs::File::open(&manifest_path).await {
                Ok(file) => {
                    let mut bytes = Vec::new();
                    file.take((MAX_CONTROL_BYTES + 1) as u64)
                        .read_to_end(&mut bytes)
                        .await?;
                    if bytes.len() > MAX_CONTROL_BYTES {
                        bail!("resume manifest exceeds size limit");
                    }
                    let record: ResumeManifest = serde_json::from_slice(&bytes).context("invalid resume manifest; abort this upload or remove the manifest to reupload every part")?;
                    if record.version != 1
                        || record.identity != identity
                        || record.content_hash != content_hash
                        || record.size != size
                        || record.content_type.as_deref() != content_type
                        || record.if_match != self.if_match
                        || record.if_none_match != self.if_none_match
                    {
                        bail!("resume manifest differs from file content, destination, content type, or conditions; use the original file and options or start a new upload");
                    }
                    Some(record)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };
        if let Some(record) = &manifest {
            if record.completing {
                // Pipe retains exact completion identity, even after parts are
                // cleaned up. Replay before attempting ListParts/UploadPart.
                let etag = self
                    .complete_multipart_upload_observed(bucket, key, upload_id, &record.parts)
                    .await?;
                tokio::fs::remove_file(&manifest_path)
                    .await
                    .context("upload completed but resume manifest cleanup failed")?;
                return Ok(Some(etag));
            }
        }
        let existing = if resuming {
            self.list_parts(bucket, key, upload_id).await?
        } else {
            Vec::new()
        };
        let trusted = manifest
            .as_ref()
            .map(|m| m.parts.clone())
            .unwrap_or_default();
        let record = manifest.get_or_insert_with(|| ResumeManifest {
            version: 1,
            identity,
            content_hash: content_hash.into(),
            size,
            content_type: content_type.map(str::to_owned),
            if_match: self.if_match.clone(),
            if_none_match: self.if_none_match.clone(),
            parts: Vec::new(),
            completing: false,
        });
        record.parts.clear();
        save_manifest(&manifest_path, record).await?;
        let mut source = tokio::fs::File::open(snapshot).await?;
        let progress = self.progress(size);
        let result = async {
            let count = size.div_ceil(MULTIPART_PART_SIZE as u64) as u32;
            for number in 1..=count {
                let length = (size - (number as u64 - 1) * MULTIPART_PART_SIZE as u64)
                    .min(MULTIPART_PART_SIZE as u64) as usize;
                let mut data = vec![0; length];
                source
                    .read_exact(&mut data)
                    .await
                    .context("read complete multipart part")?;
                let reused = trusted
                    .iter()
                    .find(|p| p.part_number == number && p.size == Some(length as u64))
                    .and_then(|local| {
                        existing.iter().find(|remote| {
                            remote.part_number == number
                                && remote.size == local.size
                                && remote.etag == local.etag
                        })
                    });
                let part = match reused {
                    Some(part) => part.clone(),
                    None => Part {
                        part_number: number,
                        etag: self
                            .upload_part(bucket, key, upload_id, number, Bytes::from(data))
                            .await?,
                        size: Some(length as u64),
                    },
                };
                record.parts.push(part);
                save_manifest(&manifest_path, record).await?;
                progress.inc(length as u64);
            }
            record.completing = true;
            save_manifest(&manifest_path, record).await?;
            let etag = self
                .complete_multipart_upload_observed(bucket, key, upload_id, &record.parts)
                .await?;
            tokio::fs::remove_file(&manifest_path)
                .await
                .context("upload completed but resume manifest cleanup failed")?;
            Ok(Some(etag))
        }
        .await;
        progress.finish_and_clear();
        result
    }

    async fn send_streaming_file(
        &self,
        bucket: &str,
        key: &str,
        path: &Path,
        headers: BTreeMap<String, String>,
        progress: ProgressBar,
    ) -> Result<Response> {
        let url = self.url(bucket, Some(key), None)?;
        let signed = sigv4::sign(
            &Method::PUT,
            &url,
            &self.region,
            &self.access_key_id,
            &self.secret_access_key,
            headers,
            sigv4::STREAMING_PAYLOAD_HASH,
            chrono::Utc::now(),
        );
        let seed = signed["authorization"]
            .split("Signature=")
            .nth(1)
            .ok_or_else(|| anyhow!("missing seed signature"))?;
        let timestamp = &signed["x-amz-date"];
        let scope = format!("{}/{}/s3/aws4_request", &timestamp[..8], self.region);
        let signer = sigv4::StreamingSigner::new(&self.secret_access_key, &scope, timestamp, seed)
            .map_err(|error| anyhow!(error))?;
        let file = tokio::fs::File::open(path).await?;
        let stream = AwsChunkedStream {
            inner: ReaderStream::with_capacity(file, 64 * 1024),
            signer: Some(signer),
            progress,
        };
        let mut request = self.http.request(Method::PUT, url);
        for (name, value) in signed {
            request = request.header(name, value);
        }
        self.check_response(request.body(Body::wrap_stream(stream)).send().await?)
            .await
    }

    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Response> {
        self.get_object_conditional(bucket, key, range, None, None)
            .await
    }
    pub async fn get_object_conditional(
        &self,
        bucket: &str,
        key: &str,
        range: Option<(u64, u64)>,
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Response> {
        let mut headers = self.object_headers(&sha256_hex(b""), if_match, if_none_match)?;
        if let Some((start, end)) = range {
            let size = end
                .checked_sub(start)
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| anyhow!("invalid range"))?;
            if size > MAX_RANGE_BYTES {
                bail!("explicit ranges are limited to 32 MiB");
            }
            headers.insert("range".into(), format!("bytes={start}-{end}"));
        }
        let response = self
            .send(
                Method::GET,
                self.url(bucket, Some(key), None)?,
                headers,
                None,
                true,
            )
            .await?;
        validate_download(&response, range)?;
        Ok(response)
    }

    pub async fn get_to_file(
        &self,
        bucket: &str,
        key: &str,
        path: &Path,
        range: Option<(u64, u64)>,
    ) -> Result<u64> {
        let mut response = self.get_object(bucket, key, range).await?;
        let expected = validate_download(&response, range)?;
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let temp =
            tempfile::NamedTempFile::new_in(parent(path)).context("create temporary download")?;
        let mut file = tokio::fs::File::from_std(temp.reopen()?);
        let progress = self.progress(expected.unwrap_or(0));
        let result = async {
            let mut count = 0u64;
            let mut hash = blake3::Hasher::new();
            while let Some(chunk) = response.chunk().await? {
                count = count
                    .checked_add(chunk.len() as u64)
                    .ok_or_else(|| anyhow!("download size overflow"))?;
                if expected.is_some_and(|length| count > length) {
                    bail!("download exceeds declared length");
                }
                file.write_all(&chunk).await?;
                hash.update(&chunk);
                progress.inc(chunk.len() as u64);
            }
            if expected.is_some_and(|length| count != length) {
                bail!("download ended before declared length");
            }
            if range.is_none() {
                if let Some(etag) = etag.as_deref().and_then(content_etag) {
                    if !etag.eq_ignore_ascii_case(&hash.finalize().to_hex()) {
                        bail!("download content does not match Pipe BLAKE3 ETag");
                    }
                }
            }
            file.flush().await?;
            file.sync_all().await?;
            drop(file);
            temp.persist(path)
                .context("atomically replace download destination")?;
            Ok(count)
        }
        .await;
        progress.finish_and_clear();
        result
    }

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectInfo> {
        self.head_object_conditional(bucket, key, None, None).await
    }
    pub async fn head_object_conditional(
        &self,
        bucket: &str,
        key: &str,
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<ObjectInfo> {
        let headers = self.object_headers(&sha256_hex(b""), if_match, if_none_match)?;
        let response = self
            .send(
                Method::HEAD,
                self.url(bucket, Some(key), None)?,
                headers,
                None,
                true,
            )
            .await?;
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        Ok(ObjectInfo {
            key: key.into(),
            etag: header("etag"),
            size: header("content-length")
                .map(|v| v.parse())
                .transpose()
                .context("invalid HEAD content length")?,
            content_type: header("content-type"),
            last_modified: header("last-modified"),
        })
    }
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        self.send(
            Method::DELETE,
            self.url(bucket, Some(key), None)?,
            self.headers(&sha256_hex(b"")),
            None,
            true,
        )
        .await
        .map(|_| ())
    }

    pub async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: Option<&str>,
    ) -> Result<String> {
        let mut headers = self.headers(&sha256_hex(b""));
        if let Some(value) = content_type {
            headers.insert("content-type".into(), value.into());
        }
        let response = self
            .send(
                Method::POST,
                self.url(bucket, Some(key), Some("uploads"))?,
                headers,
                None,
                false,
            )
            .await?;
        let created: Initiated = read_xml(response, "InitiateMultipartUploadResult").await?;
        if created.upload_id.is_empty() {
            bail!("S3 returned an empty upload ID");
        }
        Ok(created.upload_id)
    }
    pub async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        number: u32,
        data: Bytes,
    ) -> Result<String> {
        if !(1..=MAX_PARTS as u32).contains(&number) {
            bail!("multipart part number must be between 1 and 10000");
        }
        let query = format!("partNumber={number}&{}", upload_query(upload_id)?);
        let response = self
            .send_replayable(
                Method::PUT,
                self.url(bucket, Some(key), Some(&query))?,
                self.headers(&sha256_hex(&data)),
                data,
            )
            .await?;
        response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("S3 omitted multipart ETag"))
    }

    pub async fn list_parts(&self, bucket: &str, key: &str, upload_id: &str) -> Result<Vec<Part>> {
        let mut marker = 0;
        let mut parts = Vec::new();
        loop {
            let query = format!("{}&part-number-marker={marker}", upload_query(upload_id)?);
            let response = self
                .send(
                    Method::GET,
                    self.url(bucket, Some(key), Some(&query))?,
                    self.headers(&sha256_hex(b"")),
                    None,
                    true,
                )
                .await?;
            let page: PartPage = read_xml(response, "ListPartsResult").await?;
            let mut last = marker;
            for part in page.parts {
                if part.part_number <= last
                    || part.part_number > MAX_PARTS as u32
                    || part.etag.is_empty()
                {
                    bail!("invalid or unordered multipart part listing");
                }
                last = part.part_number;
                parts.push(Part {
                    part_number: part.part_number,
                    etag: part.etag,
                    size: part.size,
                });
            }
            if parts.len() > MAX_PARTS {
                bail!("multipart part listing exceeds 10000 parts");
            }
            if !page.is_truncated {
                return Ok(parts);
            }
            let next = page
                .next_part_number_marker
                .ok_or_else(|| anyhow!("truncated part listing omitted marker"))?;
            if next != last || next <= marker {
                bail!("multipart part pagination did not advance correctly");
            }
            marker = next;
        }
    }

    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[Part],
    ) -> Result<()> {
        self.complete_multipart_upload_observed(bucket, key, upload_id, parts)
            .await
            .map(|_| ())
    }

    /// Return the final object's ETag from CompleteMultipartUploadResult XML.
    /// Part ETags and later HEAD responses are not receipts for this operation.
    pub async fn complete_multipart_upload_observed(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[Part],
    ) -> Result<String> {
        if parts.is_empty()
            || parts.len() > MAX_PARTS
            || parts.iter().any(|p| {
                p.part_number == 0 || p.part_number > MAX_PARTS as u32 || p.etag.is_empty()
            })
            || parts
                .windows(2)
                .any(|p| p[0].part_number >= p[1].part_number)
        {
            bail!("completion requires 1..=10000 sorted, unique parts with ETags");
        }
        let xml = quick_xml::se::to_string(&Completion {
            parts: parts
                .iter()
                .map(|p| CompletionPart {
                    number: p.part_number,
                    etag: &p.etag,
                })
                .collect(),
        })?;
        if xml.len() > MAX_CONTROL_BYTES {
            bail!("multipart completion XML exceeds size limit");
        }
        let mut headers = self.object_headers(&sha256_hex(xml.as_bytes()), None, None)?;
        headers.insert("content-type".into(), "application/xml".into());
        let url = self.url(bucket, Some(key), Some(&upload_query(upload_id)?))?;
        // Pipe's completion fingerprint includes the ordered parts and conditions.
        // Replay exactly those after transient/ambiguous failures; HEAD is not
        // proof of this completion and must never suppress a precondition error.
        for attempt in 0..=MAX_RETRIES {
            let result = async {
                let response = self
                    .send(
                        Method::POST,
                        url.clone(),
                        headers.clone(),
                        Some(Body::from(xml.clone())),
                        false,
                    )
                    .await?;
                let completed: Completed =
                    read_xml(response, "CompleteMultipartUploadResult").await?;
                if completed.etag.is_empty() {
                    bail!("completion omitted ETag");
                }
                Ok(completed.etag)
            }
            .await;
            match result {
                Err(error) if attempt < MAX_RETRIES && retryable(&error) => tokio::time::sleep(backoff(attempt + 1)).await,
                result => return result.context("multipart completion was not acknowledged; retry the same part list and conditions"),
            }
        }
        unreachable!()
    }

    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<()> {
        self.send(
            Method::DELETE,
            self.url(bucket, Some(key), Some(&upload_query(upload_id)?))?,
            self.headers(&sha256_hex(b"")),
            None,
            true,
        )
        .await
        .map(|_| ())
    }

    pub async fn list_multipart_uploads(&self, bucket: &str) -> Result<ValueList> {
        let mut uploads = Vec::new();
        let mut marker: Option<(String, String)> = None;
        loop {
            let mut query = String::from("uploads");
            if let Some((key, id)) = &marker {
                query.push_str(&format!(
                    "&key-marker={}&upload-id-marker={}",
                    sigv4::encode_query(key),
                    sigv4::encode_query(id)
                ));
            }
            let response = self
                .send(
                    Method::GET,
                    self.url(bucket, None, Some(&query))?,
                    self.headers(&sha256_hex(b"")),
                    None,
                    true,
                )
                .await?;
            let page: UploadPage = read_xml(response, "ListMultipartUploadsResult").await?;
            let mut last = marker.clone();
            for upload in page.uploads {
                let pair = (upload.key.clone(), upload.upload_id.clone());
                if upload.upload_id.is_empty() || last.as_ref().is_some_and(|last| &pair <= last) {
                    bail!("invalid or unordered multipart upload listing");
                }
                last = Some(pair);
                uploads.push(upload);
            }
            if uploads.len() > MAX_LIST_ITEMS {
                bail!("multipart upload listing exceeds client item limit");
            }
            if !page.is_truncated {
                return Ok(ValueList {
                    upload_ids: uploads.iter().map(|u| u.upload_id.clone()).collect(),
                    uploads,
                });
            }
            let next = (
                page.next_key_marker
                    .ok_or_else(|| anyhow!("truncated upload listing omitted key marker"))?,
                page.next_upload_id_marker
                    .ok_or_else(|| anyhow!("truncated upload listing omitted upload ID marker"))?,
            );
            if Some(&next) != last.as_ref()
                || marker.as_ref().is_some_and(|old| &next <= old)
                || next.1.is_empty()
            {
                bail!("multipart upload pagination did not advance correctly");
            }
            marker = Some(next);
        }
    }
}

fn validate_conditions(if_match: Option<&str>, if_none_match: Option<&str>) -> Result<()> {
    for value in [if_match, if_none_match].into_iter().flatten() {
        if value.trim().is_empty() {
            bail!("conditional ETag header cannot be empty");
        }
        reqwest::header::HeaderValue::from_str(value).context("invalid conditional ETag header")?;
    }
    Ok(())
}

fn upload_query(id: &str) -> Result<String> {
    if id.is_empty() {
        bail!("upload ID cannot be empty");
    }
    Ok(format!("uploadId={}", sigv4::encode_query(id)))
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

async fn snapshot(path: &Path) -> Result<(tempfile::NamedTempFile, u64, String)> {
    let mut source = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    if !source.metadata().await?.is_file() {
        bail!("upload source must be a regular file");
    }
    let temp = tempfile::NamedTempFile::new().context("create upload snapshot")?;
    let mut target = tokio::fs::File::from_std(temp.reopen()?);
    let mut hash = blake3::Hasher::new();
    let mut size = 0u64;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| anyhow!("file size overflow"))?;
        if size > MAX_PARTS as u64 * MULTIPART_PART_SIZE as u64 {
            bail!("file exceeds client multipart size limit");
        }
        hash.update(&buffer[..count]);
        target.write_all(&buffer[..count]).await?;
    }
    target.flush().await?;
    target.rewind().await?;
    Ok((temp, size, hash.finalize().to_hex().to_string()))
}

async fn save_manifest(path: &Path, manifest: &ResumeManifest) -> Result<()> {
    let bytes = serde_json::to_vec(manifest)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        bail!("resume manifest exceeds size limit");
    }
    let temp = tempfile::NamedTempFile::new_in(parent(path))
        .context("create multipart resume manifest in state directory")?;
    let mut file = tokio::fs::File::from_std(temp.reopen()?);
    file.write_all(&bytes).await?;
    file.flush().await?;
    file.sync_all().await?;
    drop(file);
    temp.persist(path)
        .context("atomically save multipart resume manifest")?;
    Ok(())
}

async fn bounded_body(response: Response, limit: usize) -> Result<Vec<u8>> {
    tokio::time::timeout(
        CONTROL_DEADLINE,
        crate::error::bounded_body(response, limit),
    )
    .await
    .context("S3 control response deadline exceeded")?
}

// Validate the document envelope as well as decoding fields. This rejects
// multiple roots, DTDs, and wrong success documents that serde alone may accept.
fn parse_xml<T: DeserializeOwned>(body: &[u8], expected: &str) -> Result<T> {
    let mut reader = quick_xml::Reader::from_reader(body);
    let mut depth = 0usize;
    let mut root = None;
    loop {
        use quick_xml::events::Event;
        match reader
            .read_event()
            .map_err(|_| anyhow!("malformed S3 XML"))?
        {
            Event::Start(event) if depth == 0 => {
                if root.is_some() {
                    bail!("multiple S3 XML roots");
                }
                root = Some(String::from_utf8(event.local_name().as_ref().to_vec())?);
                depth = 1;
            }
            Event::Empty(event) if depth == 0 => {
                if root.is_some() {
                    bail!("multiple S3 XML roots");
                }
                root = Some(String::from_utf8(event.local_name().as_ref().to_vec())?);
            }
            Event::Start(_) => {
                depth += 1;
                if depth > 64 {
                    bail!("S3 XML nesting exceeds limit");
                }
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("unexpected XML end"))?;
            }
            Event::DocType(_) => bail!("S3 XML DTD is not allowed"),
            Event::Text(text)
                if depth == 0 && !text.as_ref().iter().all(u8::is_ascii_whitespace) =>
            {
                bail!("data outside S3 XML root")
            }
            Event::CData(_) if depth == 0 => bail!("data outside S3 XML root"),
            Event::GeneralRef(_) if depth == 0 => bail!("data outside S3 XML root"),
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 || root.as_deref() != Some(expected) {
        bail!("expected complete {expected} XML document");
    }
    quick_xml::de::from_reader(body).map_err(|_| anyhow!("invalid fields in {expected} XML"))
}

async fn read_xml<T: DeserializeOwned>(response: Response, expected: &str) -> Result<T> {
    let status = response.status();
    let body = bounded_body(response, MAX_CONTROL_BYTES).await?;
    if let Ok(error) = parse_xml::<ErrorXml>(&body, "Error") {
        return Err(s3_error(status, error.code).into());
    }
    parse_xml(&body, expected)
}

fn s3_error(status: StatusCode, code: String) -> S3Error {
    // S3 messages and non-XML bodies can echo submitted credentials or data.
    // Expose recognized protocol codes and locally generated status text only.
    let code = if matches!(
        code.as_str(),
        "AccessDenied"
            | "NoSuchKey"
            | "NoSuchBucket"
            | "NoSuchUpload"
            | "PreconditionFailed"
            | "NotModified"
            | "InvalidRange"
            | "InternalError"
            | "ServiceUnavailable"
            | "SlowDown"
            | "RequestTimeout"
            | "NotImplemented"
            | "InvalidRequest"
            | "MalformedXML"
            | "InvalidPart"
            | "InvalidPartOrder"
            | "EntityTooSmall"
            | "EntityTooLarge"
            | "SignatureDoesNotMatch"
            | "InvalidAccessKeyId"
            | "RequestTimeTooSkewed"
            | "AuthorizationHeaderMalformed"
            | "BucketAlreadyExists"
            | "BucketNotEmpty"
            | "BucketAlreadyOwnedByYou"
            | "OperationAborted"
            | "InvalidArgument"
            | "MissingContentLength"
            | "MethodNotAllowed"
            | "BadDigest"
            | "IncompleteBody"
            | "InvalidBucketName"
            | "InvalidObjectState"
            | "ExpiredToken"
            | "InvalidToken"
    ) {
        code
    } else if status == StatusCode::NOT_IMPLEMENTED {
        "NotImplemented".into()
    } else {
        "HttpError".into()
    };
    let message = if code == "NotImplemented" {
        "S3 operation is not supported by Pipe"
    } else if status.is_success() {
        "S3 operation failed"
    } else {
        status.canonical_reason().unwrap_or("S3 request failed")
    }
    .into();
    S3Error {
        status,
        code,
        message,
    }
}

fn validate_download(response: &Response, range: Option<(u64, u64)>) -> Result<Option<u64>> {
    let length = response
        .headers()
        .get("content-length")
        .map(|v| v.to_str()?.parse::<u64>().map_err(anyhow::Error::from))
        .transpose()?;
    match range {
        None if response.status() != StatusCode::OK => bail!(
            "full object GET returned unexpected status {}",
            response.status()
        ),
        None => Ok(length),
        Some((start, end)) => {
            if response.status() != StatusCode::PARTIAL_CONTENT {
                bail!("server did not honor requested byte range");
            }
            let value = response
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| anyhow!("range response omitted Content-Range"))?;
            let (bounds, total) = value
                .strip_prefix("bytes ")
                .and_then(|s| s.split_once('/'))
                .ok_or_else(|| anyhow!("invalid Content-Range"))?;
            let (first, last) = bounds
                .split_once('-')
                .ok_or_else(|| anyhow!("invalid Content-Range"))?;
            let (first, last, total) = (
                first.parse::<u64>()?,
                last.parse::<u64>()?,
                total.parse::<u64>()?,
            );
            if total == 0
                || first != start
                || last != end.min(total - 1)
                || last < first
                || last >= total
            {
                bail!("Content-Range differs from requested range");
            }
            let expected = last - first + 1;
            if length.is_some_and(|length| length != expected) {
                bail!("range response length differs from Content-Range");
            }
            Ok(Some(expected))
        }
    }
}

fn content_etag(value: &str) -> Option<&str> {
    let value = value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(value);
    (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())).then_some(value)
}

fn retryable(error: &anyhow::Error) -> bool {
    if let Some(error) = error.downcast_ref::<S3Error>() {
        return error.is_retryable();
    }
    if error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
    {
        return true;
    }
    error
        .downcast_ref::<reqwest::Error>()
        .is_some_and(|e| e.is_connect() || e.is_timeout() || e.is_body() || e.is_request())
}

fn backoff(attempt: usize) -> Duration {
    Duration::from_millis(100 * (1u64 << attempt.min(6)))
}

struct AwsChunkedStream<S> {
    inner: S,
    signer: Option<sigv4::StreamingSigner>,
    progress: ProgressBar,
}

impl<S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin> Stream for AwsChunkedStream<S> {
    type Item = Result<Bytes, std::io::Error>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        if self.signer.is_none() {
            return Poll::Ready(None);
        }
        loop {
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(data))) if data.is_empty() => continue,
                Poll::Ready(Some(Ok(data))) => {
                    self.progress.inc(data.len() as u64);
                    return Poll::Ready(Some(Ok(Bytes::from(
                        self.signer.as_mut().unwrap().chunk(&data),
                    ))));
                }
                Poll::Ready(Some(Err(error))) => {
                    self.signer.take();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Some(Ok(Bytes::from(
                        self.signer.take().unwrap().final_chunk(),
                    ))))
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[path = "s3_contract_tests.rs"]
mod contract_tests;

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use wiremock::{
        matchers::{method, query_param},
        Mock, MockServer, Request, ResponseTemplate,
    };

    fn client(server: &MockServer) -> S3Client {
        let mut profile = Profile::new("https://control.example");
        profile.s3_endpoint = Some(server.uri());
        S3Client::new(&profile, "AKID".into(), "secret".into()).unwrap()
    }

    #[tokio::test]
    async fn endpoint_identity_scopes_endpoint_account_and_region_only() {
        let server = MockServer::start().await;
        let client = client(&server);
        let identity = client.endpoint_identity();
        assert_eq!(identity.len(), 64);
        assert_eq!(
            identity,
            client
                .clone()
                .with_progress(true)
                .with_conditions(None, Some("*".into()))
                .unwrap()
                .endpoint_identity()
        );
        let mut other = client.clone();
        other.secret_access_key = "rotated-secret".into();
        assert_eq!(identity, other.endpoint_identity());
        other = client.clone();
        other.region = "us-west-2".into();
        assert_ne!(identity, other.endpoint_identity());
        other = client.clone();
        other.access_key_id = "OTHER".into();
        assert_ne!(identity, other.endpoint_identity());
        other = client.clone();
        other.endpoint = Url::parse("https://another.example").unwrap();
        assert_ne!(identity, other.endpoint_identity());
    }

    #[tokio::test]
    async fn single_put_receipt_is_the_write_header_without_readback() {
        for (status, etag) in [
            (200, Some("\"written-version\"")),
            (200, None),
            (412, Some("\"unrelated-version\"")),
        ] {
            let server = MockServer::start().await;
            let mut response = ResponseTemplate::new(status);
            if let Some(etag) = etag {
                response = response.insert_header("etag", etag);
            }
            Mock::given(method("PUT"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("input");
            tokio::fs::write(&input, b"contents").await.unwrap();
            let result = client(&server)
                .put_file_observed("bucket", "key", &input, None)
                .await;
            if status == 200 {
                assert_eq!(result.unwrap().as_deref(), etag);
            } else {
                assert_eq!(
                    result
                        .unwrap_err()
                        .downcast_ref::<S3Error>()
                        .unwrap()
                        .status,
                    StatusCode::PRECONDITION_FAILED
                );
            }
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "PUT");
        }
    }

    #[tokio::test]
    async fn multipart_receipt_comes_from_completion_including_persisted_replay() {
        // Exercise fresh success and an unacknowledged completion resumed later.
        for fail_first_completion in [false, true] {
            let server = MockServer::start().await;
            Mock::given(method("POST")).and(query_param("uploads", ""))
                .respond_with(ResponseTemplate::new(200).set_body_string("<InitiateMultipartUploadResult><UploadId>id</UploadId></InitiateMultipartUploadResult>"))
                .expect(1).mount(&server).await;
            Mock::given(method("PUT"))
                .and(query_param("uploadId", "id"))
                .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"part-version\""))
                .expect(1)
                .mount(&server)
                .await;
            let attempts = Arc::new(AtomicUsize::new(0));
            let count = attempts.clone();
            Mock::given(method("POST")).and(query_param("uploadId", "id"))
                .respond_with(move |_: &Request| {
                    let attempt = count.fetch_add(1, Ordering::SeqCst);
                    if fail_first_completion && attempt <= MAX_RETRIES {
                        ResponseTemplate::new(503).set_body_string("<Error><Code>ServiceUnavailable</Code></Error>")
                    } else {
                        ResponseTemplate::new(200).insert_header("etag", "\"not-the-XML-receipt\"")
                            .set_body_string("<CompleteMultipartUploadResult><ETag>&quot;final&amp;version&quot;</ETag></CompleteMultipartUploadResult>")
                    }
                }).mount(&server).await;
            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("input");
            tokio::fs::write(&input, vec![b'x'; MULTIPART_PART_SIZE])
                .await
                .unwrap();
            let client = client(&server).with_state_directory(dir.path().join("state"));
            let mut result = client
                .put_file_observed("bucket", "key", &input, None)
                .await;
            if fail_first_completion {
                assert!(result.is_err());
                result = client
                    .put_file_resumable_observed("bucket", "key", &input, None, Some("id"))
                    .await;
            }
            assert_eq!(result.unwrap().as_deref(), Some("\"final&version\""));
            let requests = server.received_requests().await.unwrap();
            assert!(requests
                .iter()
                .all(|r| r.method == "PUT" || r.method == "POST"));
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                if fail_first_completion {
                    MAX_RETRIES + 2
                } else {
                    1
                }
            );
            assert_eq!(
                std::fs::read_dir(dir.path().join("state")).unwrap().count(),
                0
            );
        }
    }
}

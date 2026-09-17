use anyhow::{anyhow, Result};
use reqwest::StatusCode;
use serde_json::Value;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.message)?;
        if let Some(id) = &self.request_id {
            write!(f, " (request {id})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

pub async fn response_error(response: reqwest::Response) -> anyhow::Error {
    let status = response.status();
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = match bounded_body(response, 64 * 1024).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    };
    let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let code = value
        .get("code")
        .or_else(|| value.get("error").and_then(|e| e.get("code")))
        .and_then(Value::as_str)
        .unwrap_or("http_error")
        .to_owned();
    // Server-controlled text may echo submitted secrets; expose only a bounded code.
    let code = if code.len() <= 96 && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        code
    } else {
        "http_error".into()
    };
    let message = status
        .canonical_reason()
        .unwrap_or("server returned an error")
        .to_owned();
    anyhow::Error::new(ApiError {
        status,
        code,
        message,
        request_id,
    })
}

pub fn ensure_https(url: &str, label: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).map_err(|e| anyhow!("invalid {label}: {e}"))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
    {
        return Err(anyhow!("{label} must have a host and must not contain credentials, query parameters, or fragments"));
    }
    if parsed.scheme() != "https"
        && !(parsed.scheme() == "http"
            && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1")))
    {
        return Err(anyhow!(
            "{label} must use HTTPS (HTTP is allowed only for localhost tests)"
        ));
    }
    Ok(())
}

pub async fn bounded_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(anyhow!("API response exceeds the {limit}-byte limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.without_url())? {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(anyhow!("API response exceeds the {limit}-byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Stable process statuses: usage=2, authentication=3, authorization=4,
/// unavailable=5, conflict=6, transport=7, other=1.
#[derive(Debug, thiserror::Error)]
#[error("outcome unknown for request {request_id}; run pipe compute resume {request_id} --yes; do not create a replacement request")]
pub struct UnknownOutcome {
    pub request_id: uuid::Uuid,
}
#[derive(Debug, thiserror::Error)]
#[error("deadline reached for operation {operation_id}; server work may continue; inspect pipe compute operations {operation_id}")]
pub struct WaitTimeout {
    pub operation_id: uuid::Uuid,
}
#[derive(Debug, thiserror::Error)]
#[error("SSH exited with status {status}")]
pub struct SshExit {
    pub status: u8,
}
pub fn classification(error: &anyhow::Error) -> (&'static str, u8) {
    if error
        .downcast_ref::<crate::platform::ActivationUnknown>()
        .is_some()
    {
        return ("unknown_outcome", 8);
    }
    if error
        .downcast_ref::<crate::billing_workflows::UnknownOutcome>()
        .is_some()
    {
        return ("unknown_outcome", 8);
    }
    if error
        .downcast_ref::<crate::customer::UnknownOutcome>()
        .is_some()
    {
        return ("unknown_outcome", 8);
    }
    if error.downcast_ref::<crate::hosting::Unknown>().is_some() {
        return ("unknown_outcome", 8);
    }
    if error.downcast_ref::<crate::hosting::Timeout>().is_some() {
        return ("wait_timeout", 9);
    }
    if error.downcast_ref::<crate::durable::Expired>().is_some() {
        return ("response_expired", 8);
    }
    if error.downcast_ref::<crate::durable::Unknown>().is_some() {
        return ("unknown_outcome", 8);
    }
    if error.downcast_ref::<crate::durable::Timeout>().is_some() {
        return ("wait_timeout", 9);
    }
    if error
        .downcast_ref::<crate::durable::ApplicationError>()
        .is_some()
    {
        return ("application_error", 1);
    }
    if error.downcast_ref::<crate::kv::Unknown>().is_some() {
        return ("unknown_outcome", 8);
    }
    if let Some(kv) = error.downcast_ref::<pipe_transports::kv::Error>() {
        use pipe_transports::kv::Error;
        return match kv {
            Error::Unknown => ("unknown_outcome", 8),
            Error::Authentication => ("authentication", 3),
            Error::Authorization => ("authorization", 4),
            Error::Unavailable => ("unavailable", 5),
            Error::Transport => ("transport", 7),
            Error::Rejected(_) => ("kv_rejected", 1),
        };
    }
    if let Some(ssh) = error.downcast_ref::<SshExit>() {
        return ("ssh_exit", ssh.status);
    }
    if error.downcast_ref::<UnknownOutcome>().is_some() {
        return ("unknown_outcome", 8);
    }
    if error.downcast_ref::<WaitTimeout>().is_some() {
        return ("wait_timeout", 9);
    }
    if let Some(api) = error.downcast_ref::<ApiError>() {
        return match api.status.as_u16() {
            401 => ("authentication", 3),
            403 => ("authorization", 4),
            409 | 412 => ("conflict", 6),
            429 | 503 => ("unavailable", 5),
            _ => ("api_error", 1),
        };
    }
    if error.downcast_ref::<reqwest::Error>().is_some() {
        return ("transport", 7);
    }
    ("command_failed", 1)
}

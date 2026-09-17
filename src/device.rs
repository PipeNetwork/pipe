use crate::{
    auth::{ControlClient, Session},
    error::{bounded_body, response_error},
};
use anyhow::{anyhow, ensure, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
#[derive(Deserialize)]
struct Device {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}
pub async fn login(
    client: &ControlClient,
    label: &str,
    scope: &str,
    no_browser: bool,
) -> Result<Value> {
    login_for_account(client, label, scope, no_browser, None).await
}

pub(crate) async fn login_for_account(
    client: &ControlClient,
    label: &str,
    scope: &str,
    no_browser: bool,
    expected: Option<&Session>,
) -> Result<Value> {
    // Verify storage is usable before issuing any remote session.
    client.secrets.set("storage-probe", "ready")?;
    client.secrets.delete("storage-probe")?;
    let response = client
        .http
        .post(client.url("/v1/cli/auth/device"))
        .form(&[
            ("client_id", "pipe-cli"),
            ("scope", scope),
            ("device_label", label),
        ])
        .send()
        .await
        .map_err(|e| e.without_url())?;
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    let device: Device = serde_json::from_slice(&bounded_body(response, 16384).await?)?;
    ensure!(
        (1..=600).contains(&device.expires_in) && (5..=60).contains(&device.interval),
        "invalid device authorization limits"
    );
    let uri = reqwest::Url::parse(&device.verification_uri_complete)?;
    ensure!(
        device.verification_uri == "https://pipe.network/cli/authorize"
            && uri.scheme() == "https"
            && uri.host_str() == Some("pipe.network")
            && uri.path() == "/cli/authorize"
            && uri.username().is_empty()
            && uri.password().is_none()
            && uri.fragment().is_none()
            && uri.port().is_none(),
        "untrusted browser authorization URL"
    );
    ensure!(
        device.user_code.len() <= 32
            && device
                .user_code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid user code"
    );
    eprintln!(
        "Open {} and enter {}. Approve only the request from this terminal.",
        device.verification_uri, device.user_code
    );
    if !no_browser {
        let _ = open_browser(uri.as_str());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(device.expires_in);
    let mut interval = device.interval;
    loop {
        if tokio::time::Instant::now() + Duration::from_secs(interval) >= deadline {
            return Err(anyhow!("device authorization expired; run login again"));
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let request = client
            .http
            .post(client.url("/v1/cli/auth/token"))
            .form(&[
                ("client_id", "pipe-cli"),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device.device_code.as_str()),
            ])
            .send();
        let response = tokio::time::timeout_at(deadline, request)
            .await
            .map_err(|_| anyhow!("device authorization expired"))?
            .map_err(|e| e.without_url())?;
        let status = response.status();
        let data = bounded_body(response, 65536).await?;
        if status.is_success() {
            let session: Session = serde_json::from_slice(&data)?;
            crate::wallet_auth::validate_session(&session, scope)?;
            if expected.is_some_and(|old| {
                old.owner_wallet != session.owner_wallet || old.account_id != session.account_id
            }) {
                // Never replace the existing account or send its pending write
                // under an account selected in a different browser tab.
                let _ = client
                    .http
                    .post(client.url("/v1/cli/auth/logout"))
                    .bearer_auth(&session.access_token)
                    .send()
                    .await;
                return Err(anyhow!("browser authorization used a different account; select the original account and retry. The existing session was preserved"));
            }
            client.store_session(&session)?;
            return Ok(
                json!({"session_id":session.session_id,"owner_wallet":session.owner_wallet,"expires_in":session.expires_in}),
            );
        }
        let error: Value = serde_json::from_slice(&data)?;
        match error["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval = interval.saturating_add(5),
            Some("access_denied") => return Err(anyhow!("browser authorization denied")),
            Some("expired_token") => return Err(anyhow!("device authorization expired")),
            _ => return Err(anyhow!("device authorization failed ({status})")),
        }
    }
}
fn open_browser(url: &str) -> std::io::Result<std::process::Child> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = std::process::Command::new("xdg-open");
    command
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
}

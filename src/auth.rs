use crate::{
    config::Profile,
    error::{bounded_body, response_error},
    keyring::SecretStore,
};
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use uuid::Uuid;

#[derive(Clone)]
pub struct ControlClient {
    pub http: Client,
    pub profile: Profile,
    pub secrets: std::sync::Arc<SecretStore>,
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
    pub progress: bool,
}

#[derive(Debug, Deserialize)]
struct Challenge {
    challenge_id: Uuid,
    message: String,
    owner_wallet: String,
}

#[derive(Deserialize, Serialize)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub expires_in: u64,
    #[serde(default)]
    pub refresh_expires_in: u64,
    pub owner_wallet: String,
    pub session_id: Uuid,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct StoredS3Credential {
    access_key_id: String,
    secret_access_key: String,
}

impl ControlClient {
    pub fn new(profile: Profile, profile_name: impl Into<String>) -> Result<Self> {
        profile.validate()?;
        let http = Client::builder()
            .user_agent(format!("pipe-cli/{}", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        let namespace = format!(
            "{}:{}",
            profile_name.into(),
            crate::sigv4::sha256_hex(profile.control_api_url.trim_end_matches('/').as_bytes())
        );
        Ok(Self {
            http,
            profile,
            secrets: std::sync::Arc::new(SecretStore::new(namespace)),
            if_match: None,
            if_none_match: None,
            progress: false,
        })
    }
    #[cfg(test)]
    pub fn for_test(profile: Profile, directory: &Path) -> Result<Self> {
        let mut client = Self::new(profile, "test")?;
        client.secrets =
            std::sync::Arc::new(SecretStore::at(directory.to_owned(), "test".into(), false));
        Ok(client)
    }
    pub(crate) fn session(&self) -> Result<Option<Session>> {
        self.secrets
            .get("session")?
            .map(|s| serde_json::from_str(&s).context("invalid stored session"))
            .transpose()
    }
    pub fn wallet_signing_key(&self) -> Result<SigningKey> {
        anyhow::ensure!(
            std::env::var_os("PIPE_CLI_TOKEN").is_none(),
            "automation credentials cannot use local wallet signing keys"
        );
        let secret = zeroize::Zeroizing::new(
            self.secrets
                .get("wallet_private_key")?
                .ok_or_else(|| anyhow!("no local wallet; run 'pipe auth login'"))?,
        );
        signing_key(&secret)
    }
    pub fn url(&self, path: &str) -> String {
        format!(
            "{}{}",
            self.profile.control_api_url.trim_end_matches('/'),
            if path.starts_with('/') {
                path.to_owned()
            } else {
                format!("/{path}")
            }
        )
    }
    pub(crate) fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        auth: bool,
    ) -> Result<RequestBuilder> {
        let mut request = self
            .http
            .request(method, self.url(path))
            .header("x-request-id", Uuid::new_v4().to_string());
        if auth {
            if let Ok(token) = std::env::var("PIPE_CLI_TOKEN") {
                anyhow::ensure!(
                    token.starts_with("pcli_c_")
                        && token.len() == 71
                        && token[7..].bytes().all(|b| b.is_ascii_hexdigit()),
                    "PIPE_CLI_TOKEN requires a scoped automation credential"
                );
                request = request.bearer_auth(token);
            } else if let Some(session) = self.session()? {
                request = request.bearer_auth(session.access_token);
            }
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        Ok(request)
    }
    pub async fn get(&self, path: &str) -> Result<Value> {
        self.send(Method::GET, path, None).await
    }
    pub async fn post(&self, path: &str, body: Value) -> Result<Value> {
        self.send(Method::POST, path, Some(body)).await
    }
    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.send(Method::DELETE, path, None).await
    }
    pub async fn post_idempotent(&self, path: &str, body: Value, key: Uuid) -> Result<Value> {
        self.send_with_headers(Method::POST, path, Some(body), Some(key))
            .await
    }
    pub(crate) async fn send_idempotent(
        &self,
        method: Method,
        path: &str,
        body: Value,
        key: Uuid,
        expected_status: StatusCode,
    ) -> Result<Value> {
        self.send_checked(method, path, Some(body), Some(key), Some(expected_status))
            .await
    }
    async fn send(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        self.send_with_headers(method, path, body, None).await
    }
    async fn send_with_headers(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        idempotency: Option<Uuid>,
    ) -> Result<Value> {
        self.send_checked(method, path, body, idempotency, None)
            .await
    }
    async fn send_checked(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        idempotency: Option<Uuid>,
        expected_status: Option<StatusCode>,
    ) -> Result<Value> {
        let replay_body = body.clone();
        let mut request = self.request(method.clone(), path, body, true)?;
        if let Some(key) = idempotency {
            request = request.header("idempotency-key", key.to_string());
        }
        let response = request
            .send()
            .await
            .map_err(|e| e.without_url())
            .context("control-plane request")?;
        if response.status() == StatusCode::UNAUTHORIZED
            && std::env::var_os("PIPE_CLI_TOKEN").is_none()
            && path != "/v1/customer/cli/auth/refresh"
            && self.refresh().await.is_ok()
        {
            let mut retry = self.request(method, path, replay_body, true)?;
            if let Some(key) = idempotency {
                retry = retry.header("idempotency-key", key.to_string());
            }
            return self
                .finish_checked(
                    retry
                        .send()
                        .await
                        .map_err(|e| e.without_url())
                        .context("retry control-plane request")?,
                    expected_status,
                )
                .await;
        }
        self.finish_checked(response, expected_status).await
    }
    async fn finish_checked(
        &self,
        response: reqwest::Response,
        expected_status: Option<StatusCode>,
    ) -> Result<Value> {
        if !response.status().is_success() {
            return Err(response_error(response).await);
        }
        anyhow::ensure!(
            expected_status.is_none_or(|s| s == response.status()),
            "response status differs from the pinned contract"
        );
        let bytes = bounded_body(response, 2 * 1024 * 1024).await?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).context("decode control-plane response")
    }
    pub fn auth_base(&self) -> Result<&'static str> {
        Ok(
            if self
                .session()?
                .is_some_and(|s| s.access_token.starts_with("pcli_a_"))
            {
                "/v1/cli/auth"
            } else {
                "/v1/customer/cli/auth"
            },
        )
    }
    pub async fn refresh(&self) -> Result<()> {
        let old = self.session()?.ok_or_else(|| anyhow!("not logged in"))?;
        let path = format!("{}/refresh", self.auth_base()?);
        let refresh = &old.refresh_token;
        // Delete the active token before rotating: a lost response must require login.
        self.secrets.delete("session")?;
        let response = self
            .request(
                Method::POST,
                &path,
                Some(json!({"refresh_token":refresh})),
                false,
            )?
            .send()
            .await
            .map_err(|e| e.without_url())?;
        if !response.status().is_success() {
            if response.status() == StatusCode::UNAUTHORIZED {
                self.secrets.delete("session")?;
            }
            return Err(response_error(response).await);
        }
        let session: Session = serde_json::from_slice(&bounded_body(response, 64 * 1024).await?)
            .map_err(|_| anyhow!("invalid session response"))?;
        if session.owner_wallet != old.owner_wallet
            || session.session_id != old.session_id
            || session.account_id != old.account_id
            || session.scope != old.scope
            || session.access_token.starts_with("pcli_a_")
                != old.access_token.starts_with("pcli_a_")
        {
            return Err(anyhow!("refreshed session identity mismatch"));
        }
        self.store_session(&session)?;
        Ok(())
    }
    pub(crate) fn store_session(&self, session: &Session) -> Result<()> {
        if session.access_token.starts_with("pcli_") || session.refresh_token.starts_with("pcli_") {
            crate::wallet_auth::validate_session(
                session,
                session
                    .scope
                    .as_deref()
                    .context("platform session lacks granted scopes")?,
            )?;
        }
        if session.access_token.len() < 32
            || session.refresh_token.len() < 64
            || session.token_type != "Bearer"
            || !(1..=900).contains(&session.expires_in)
            || !(1..=2592000).contains(&session.refresh_expires_in)
        {
            return Err(anyhow!("invalid CLI session response"));
        }
        if self
            .session()?
            .is_some_and(|old| old.owner_wallet != session.owner_wallet)
        {
            self.secrets.delete("s3_access_key")?;
        }
        self.secrets
            .set("session", &serde_json::to_string(session)?)?;
        Ok(())
    }
    pub async fn login(
        &self,
        wallet_argument: Option<&str>,
        device_label: Option<&str>,
    ) -> Result<Value> {
        let secret = zeroize::Zeroizing::new(wallet_secret(&self.secrets, wallet_argument)?);
        let signing = signing_key(&secret)?;
        let wallet = hex::encode(signing.verifying_key().to_bytes());
        let challenge_value = self
            .request(
                Method::POST,
                "/v1/customer/cli/auth/challenge",
                Some(json!({
                    "wallet":wallet,
                    "client_version":env!("CARGO_PKG_VERSION"),
                    "device_label":device_label.unwrap_or("")
                })),
                false,
            )?
            .send()
            .await?;
        if !challenge_value.status().is_success() {
            return Err(response_error(challenge_value).await);
        }
        let challenge: Challenge =
            serde_json::from_slice(&bounded_body(challenge_value, 64 * 1024).await?)
                .map_err(|_| anyhow!("invalid challenge response"))?;
        if challenge.owner_wallet != wallet {
            return Err(anyhow!("server returned a mismatched wallet challenge"));
        }
        validate_challenge(&challenge.message, &wallet)?;
        let signature = hex::encode(signing.sign(challenge.message.as_bytes()).to_bytes());
        let response = self
            .request(
                Method::POST,
                "/v1/customer/cli/auth/session",
                Some(json!({
                    "challenge_id":challenge.challenge_id,
                    "signature":signature,
                    "client_version":env!("CARGO_PKG_VERSION"),
                    "device_label":device_label.unwrap_or("")
                })),
                false,
            )?
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(response_error(response).await);
        }
        let session: Session = serde_json::from_slice(&bounded_body(response, 64 * 1024).await?)
            .map_err(|_| anyhow!("invalid session response"))?;
        if session.owner_wallet != wallet {
            return Err(anyhow!("session wallet mismatch"));
        }
        self.store_session(&session)?;
        Ok(
            json!({"owner_wallet":session.owner_wallet,"wallet_address":bs58::encode(signing.verifying_key().to_bytes()).into_string(),"session_id":session.session_id,"expires_in":session.expires_in,"refresh_expires_in":session.refresh_expires_in}),
        )
    }
    pub async fn logout(&self) -> Result<Value> {
        let value = self
            .post(&format!("{}/logout", self.auth_base()?), json!({}))
            .await?;
        self.secrets.delete("session")?;
        Ok(value)
    }
    pub fn current_wallet(&self) -> Result<String> {
        anyhow::ensure!(
            std::env::var_os("PIPE_CLI_TOKEN").is_none(),
            "select an explicit wallet for automation; stored wallet context is not inherited"
        );
        if let Some(session) = self.session()? {
            return Ok(session.owner_wallet);
        }
        self.secrets
            .get("owner_wallet")?
            .ok_or_else(|| anyhow!("not logged in; run 'pipe auth login'"))
    }
    /// Save the active S3 credential as one keyring item. Older profiles that
    /// stored the access key and secret separately remain readable.
    pub fn save_active_s3_credential(&self, access_key: &str, secret: &str) -> Result<()> {
        self.secrets.set(
            "s3_access_key",
            &serde_json::to_string(&StoredS3Credential {
                access_key_id: access_key.to_owned(),
                secret_access_key: secret.to_owned(),
            })?,
        )
    }

    pub(crate) fn active_s3_access_key(&self) -> Result<Option<String>> {
        let Some(active) = self.secrets.get("s3_access_key")? else {
            return Ok(None);
        };
        if let Ok(stored) = serde_json::from_str::<StoredS3Credential>(&active) {
            return Ok(Some(stored.access_key_id));
        }
        Ok(Some(active))
    }

    pub fn active_s3_credential(&self) -> Result<Option<(String, String)>> {
        let Some(active_key) = self.active_s3_access_key()? else {
            return Ok(None);
        };
        let active = self
            .secrets
            .get("s3_access_key")?
            .ok_or_else(|| anyhow!("active S3 credential disappeared while reading it"))?;
        if let Ok(stored) = serde_json::from_str::<StoredS3Credential>(&active) {
            if stored.access_key_id.is_empty() || stored.secret_access_key.is_empty() {
                return Err(anyhow!(
                    "stored active S3 credential is incomplete; create a new credential"
                ));
            }
            return Ok(Some((stored.access_key_id, stored.secret_access_key)));
        }
        let secret = self.s3_secret(&active_key)?;
        // Migrate the legacy two-entry layout after a successful read. The
        // first command may touch both old items; later commands use one item.
        if let Err(error) = self.save_active_s3_credential(&active_key, &secret) {
            eprintln!(
                "warning: could not consolidate the legacy S3 credential in the OS keychain ({error}); continuing with the existing credential"
            );
        }
        Ok(Some((active_key, secret)))
    }

    pub fn s3_secret(&self, access_key: &str) -> Result<String> {
        if let Some(active) = self.secrets.get("s3_access_key")? {
            if let Ok(stored) = serde_json::from_str::<StoredS3Credential>(&active) {
                if stored.access_key_id == access_key {
                    return Ok(stored.secret_access_key);
                }
            }
        }
        self.secrets.get(&format!("s3:{access_key}"))?.ok_or_else(|| anyhow!("secret for S3 credential {access_key} is not available; create a new credential"))
    }
}

pub(crate) fn wallet_secret(secrets: &SecretStore, argument: Option<&str>) -> Result<String> {
    if let Some(value) = argument {
        let value = read_wallet_file(Path::new(value))
            .context("--wallet must name a private wallet file")?;
        let value = value.trim().to_owned();
        signing_key(&value)?;
        secrets.set("wallet_private_key", &value)?;
        return Ok(value);
    }
    if let Some(value) = secrets.get("wallet_private_key")? {
        signing_key(&value)?;
        return Ok(value);
    }
    let signing = SigningKey::generate(&mut OsRng);
    let value = hex::encode(signing.to_bytes());
    secrets.set("wallet_private_key", &value)?;
    eprintln!(
        "Generated wallet {} and stored its private key in the secret store.",
        bs58::encode(signing.verifying_key().to_bytes()).into_string()
    );
    Ok(value)
}

pub(crate) fn signing_key(value: &str) -> Result<SigningKey> {
    let bytes: [u8; 32] = hex::decode(value.trim())
        .map_err(|_| anyhow!("wallet private key must be 32-byte hex"))?
        .try_into()
        .map_err(|_| anyhow!("wallet private key must be 32-byte hex"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub(crate) fn read_wallet_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => Value::String(String::from_utf8(bytes).context("wallet file is not UTF-8")?),
    };
    if let Some(array) = value.as_array() {
        let bytes: Vec<u8> = array
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|v| u8::try_from(v).ok())
                    .ok_or_else(|| anyhow!("invalid wallet byte array"))
            })
            .collect::<Result<_>>()?;
        if bytes.len() != 64 && bytes.len() != 32 {
            return Err(anyhow!("wallet array must contain 32 or 64 bytes"));
        }
        let secret = hex::encode(&bytes[..32]);
        if bytes.len() == 64 && signing_key(&secret)?.verifying_key().as_bytes() != &bytes[32..] {
            return Err(anyhow!("wallet public and private keys disagree"));
        }
        return Ok(secret);
    }
    value
        .get("secret_key_hex")
        .or_else(|| value.get("secret"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| value.as_str().map(str::to_owned))
        .ok_or_else(|| anyhow!("wallet file does not contain secret_key_hex"))
}

fn validate_challenge(message: &str, wallet: &str) -> Result<()> {
    let lines: Vec<_> = message.lines().collect();
    if lines.len() != 8
        || lines[0] != "Pipe Storage authorization"
        || lines[1] != "domain: pipe-cli"
        || lines[2]
            .strip_prefix("mesh: ")
            .is_none_or(|v| Uuid::parse_str(v).is_err())
        || lines[3] != "action: cli_login"
        || lines[4] != format!("owner: {wallet}")
        || !lines[5]
            .strip_prefix("nonce: ")
            .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(anyhow!("invalid pipe-cli authorization challenge"));
    }
    let issued = lines[6]
        .strip_prefix("issued_at: ")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("invalid challenge timestamp"))?;
    let expires = lines[7]
        .strip_prefix("expires_at: ")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("invalid challenge expiry"))?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    if issued > now + 60 || expires <= now || expires <= issued || expires - issued > 300 {
        return Err(anyhow!("challenge is expired or has invalid lifetime"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod contract_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wallet_signature_is_lowercase_hex() {
        let signing = SigningKey::generate(&mut OsRng);
        let signature = hex::encode(signing.sign(b"pipe-cli").to_bytes());
        assert_eq!(signature.len(), 128);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

//! Platform login has a separate signing domain from legacy storage and payments.
use crate::{
    auth::{read_wallet_file, signing_key, ControlClient, Session},
    error::{bounded_body, response_error},
};
use anyhow::{ensure, Result};
use ed25519_dalek::Signer;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Deserialize)]
struct Challenge {
    challenge_id: Uuid,
    owner_wallet: String,
    account_id: Option<String>,
    scope: String,
    message: String,
    issued_at: u64,
    expires_at: u64,
}

pub(crate) fn normalized_scope(scope: &str) -> String {
    let mut parts: Vec<_> = scope.split_ascii_whitespace().collect();
    parts.sort_unstable();
    parts.dedup();
    parts.join(" ")
}

fn validate(challenge: &Challenge, wallet: &str, scope: &str, label: &str) -> Result<()> {
    let lines: Vec<_> = challenge.message.lines().collect();
    ensure!(lines.len() == 12, "invalid platform wallet challenge");
    let mesh = lines[2].strip_prefix("mesh: ").unwrap_or("");
    let mesh = Uuid::parse_str(mesh)?;
    let nonce = lines[9].strip_prefix("nonce: ").unwrap_or("");
    ensure!(
        nonce.len() == 64 && nonce.bytes().all(|v| v.is_ascii_hexdigit()),
        "invalid challenge nonce"
    );
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    ensure!(
        challenge.issued_at <= now + 60
            && challenge.expires_at > now
            && challenge.expires_at > challenge.issued_at
            && challenge.expires_at - challenge.issued_at <= 300,
        "expired or invalid wallet challenge lifetime"
    );
    ensure!(
        challenge.owner_wallet == wallet && challenge.scope == normalized_scope(scope),
        "wallet challenge grants mismatch"
    );
    let expected = format!(
        "Pipe Platform authorization\ndomain: pipe-cli-v3\nmesh: {mesh}\naction: wallet_login\nowner: {wallet}\naccount: {}\nscopes: {}\nclient: pipe-cli\ndevice: {}\nnonce: {nonce}\nissued_at: {}\nexpires_at: {}\n",
        json!(challenge.account_id), challenge.scope, json!(label), challenge.issued_at, challenge.expires_at
    );
    ensure!(
        challenge.message == expected,
        "wallet challenge domain, context or metadata mismatch"
    );
    Ok(())
}

pub(crate) fn validate_session(session: &Session, scope: &str) -> Result<()> {
    for (token, prefix, bytes) in [
        (&session.access_token, "pcli_a_", 64),
        (&session.refresh_token, "pcli_r_", 128),
    ] {
        ensure!(
            token
                .strip_prefix(prefix)
                .is_some_and(|v| v.len() == bytes && v.bytes().all(|b| b.is_ascii_hexdigit())),
            "invalid platform session credential type"
        );
    }
    ensure!(
        session.scope.as_deref() == Some(normalized_scope(scope).as_str()),
        "platform session grants mismatch"
    );
    Ok(())
}

pub async fn login(
    client: &ControlClient,
    wallet_file: &str,
    label: &str,
    scope: &str,
) -> Result<Value> {
    // Importing the key verifies secret storage before any remote session is created.
    let secret = zeroize::Zeroizing::new(read_wallet_file(std::path::Path::new(wallet_file))?);
    let signing = signing_key(&secret)?;
    let owner = hex::encode(signing.verifying_key().to_bytes());
    client.secrets.set(&format!("wallet:{owner}"), &secret)?;
    if let Some(old) = client.secrets.get("wallet_private_key")? {
        let old = zeroize::Zeroizing::new(old);
        let owner = hex::encode(signing_key(&old)?.verifying_key().to_bytes());
        client.secrets.set(&format!("wallet:{owner}"), &old)?;
    }
    let response = client
        .http
        .post(client.url("/v1/cli/auth/wallet/challenge"))
        .json(&json!({"wallet":owner,"scope":normalized_scope(scope),"device_label":label}))
        .send()
        .await
        .map_err(|e| e.without_url())?;
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    let challenge: Challenge = serde_json::from_slice(&bounded_body(response, 16384).await?)?;
    validate(&challenge, &owner, scope, label)?;
    let signature = hex::encode(signing.sign(challenge.message.as_bytes()).to_bytes());
    let response = client
        .http
        .post(client.url("/v1/cli/auth/wallet/session"))
        .json(&json!({"challenge_id":challenge.challenge_id,"signature":signature}))
        .send()
        .await
        .map_err(|e| e.without_url())?;
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    let session: Session = serde_json::from_slice(&bounded_body(response, 65536).await?)?;
    validate_session(&session, scope)?;
    ensure!(
        session.owner_wallet == owner && session.account_id == challenge.account_id,
        "wallet session context mismatch"
    );
    client.store_session(&session)?;
    client.secrets.set("wallet_private_key", &secret)?;
    Ok(
        json!({"session_id":session.session_id,"owner_wallet":owner,"account_id":session.account_id,"scope":session.scope,"expires_in":session.expires_in}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_bind_every_grant_and_cannot_cross_domains() {
        let now = chrono::Utc::now().timestamp() as u64;
        let scope = "compute.read storage.read";
        let label = "test device";
        let owner = "a".repeat(64);
        let mut c = Challenge {challenge_id: Uuid::new_v4(), owner_wallet: owner.clone(), account_id: None,
            scope: scope.into(), message: format!("Pipe Platform authorization\ndomain: pipe-cli-v3\nmesh: {}\naction: wallet_login\nowner: {owner}\naccount: null\nscopes: {scope}\nclient: pipe-cli\ndevice: {}\nnonce: {}\nissued_at: {now}\nexpires_at: {}\n", Uuid::new_v4(), json!(label), "b".repeat(64), now+300), issued_at: now, expires_at: now+300};
        validate(&c, &owner, "storage.read compute.read storage.read", label).unwrap();
        let original = c.message.clone();
        for (from, to) in [
            ("pipe-cli-v3", "pipe-cli"),
            ("wallet_login", "transfer"),
            ("compute.read", "compute.write"),
            ("account: null", "account: \"other\""),
            ("client: pipe-cli", "client: website"),
        ] {
            c.message = original.replace(from, to);
            assert!(validate(&c, &owner, scope, label).is_err(), "{from}");
        }
        c.message = original;
        assert!(validate(&c, &owner, "compute.write", label).is_err());
        assert!(validate(&c, &owner, scope, "different device").is_err());
        c.expires_at += 1;
        assert!(validate(&c, &owner, scope, label).is_err());
    }
}

use crate::{auth::ControlClient, solana};
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const BODY_LIMIT: usize = 256 * 1024;
const PAYMENT_HEADER_LIMIT: usize = 128 * 1024;
const JOURNAL_LIMIT: u64 = 32 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Intent {
    method: String,
    wallet: String,
    payer: String,
    amount_atoms: u64,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    intent: Intent,
    invoice_id: Option<Uuid>,
    /// Immutable original invoice/requirements; status must not overwrite it.
    invoice: Option<Value>,
    state: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct JournalData {
    entries: BTreeMap<Uuid, Entry>,
    /// Includes external submissions. A different payload for an invoice is
    /// refused, including after timeout or an apparently terminal response.
    submissions: BTreeMap<Uuid, Value>,
}

struct Journal {
    path: PathBuf,
    _lock: File,
    data: JournalData,
}

impl Journal {
    fn open(client: &ControlClient) -> Result<Self> {
        // SecretStore's directory is scoped to its storage namespace/profile.
        // Additionally bind to the endpoint, including any control API prefix.
        let endpoint = hex::encode(Sha256::digest(client.url("").as_bytes()));
        Self::at(
            &client
                .secrets
                .state_directory()
                .join(format!("payments-{endpoint}.json")),
        )
    }

    fn at(path: &Path) -> Result<Self> {
        fs::create_dir_all(path.parent().context("journal has no parent")?)?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.with_extension("lock"))?;
        // Do not block the async executor behind another CLI process.
        lock.try_lock_exclusive()
            .context("payment journal is in use; retry when the other payment command finishes")?;
        let data = match File::open(path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(JOURNAL_LIMIT + 1).read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() as u64 <= JOURNAL_LIMIT,
                    "payment journal is too large"
                );
                serde_json::from_slice(&bytes)
                    .context("payment journal is corrupt; preserve it for recovery")?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => JournalData::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
            data,
        })
    }

    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.data)?;
        ensure!(
            bytes.len() as u64 <= JOURNAL_LIMIT,
            "payment journal is full; preserve/archive it before continuing"
        );
        crate::keyring::atomic_private_write(&self.path, &bytes)
            .context("persist payment recovery journal")
    }

    fn prepare(&mut self, intent: Intent, requested: Option<Uuid>) -> Result<Uuid> {
        let key = requested
            .or_else(|| {
                self.data.entries.iter().find_map(|(key, entry)| {
                    let terminal = entry.state.as_deref() == Some("credited")
                        || (matches!(entry.state.as_deref(), Some("expired" | "failed"))
                            && !entry
                                .invoice_id
                                .is_some_and(|id| self.data.submissions.contains_key(&id)));
                    (entry.intent == intent && !terminal).then_some(*key)
                })
            })
            .unwrap_or_else(Uuid::new_v4);
        if let Some(entry) = self.data.entries.get(&key) {
            ensure!(
                entry.intent == intent,
                "idempotency key already belongs to different payment terms"
            );
        } else {
            self.data.entries.insert(
                key,
                Entry {
                    intent,
                    invoice_id: None,
                    invoice: None,
                    state: None,
                },
            );
        }
        self.save()?; // Recovery key MUST survive a crash before HTTP.
        eprintln!("Payment recovery id (Idempotency-Key): {key}");
        Ok(key)
    }

    fn record(&mut self, key: Uuid, invoice: &Value, x402: bool) -> Result<()> {
        let id = if x402 && invoice.get("accepts").is_some() {
            x402_invoice_id(invoice)?
        } else {
            invoice_id(invoice)?
        };
        let entry = self
            .data
            .entries
            .get_mut(&key)
            .context("missing payment intent")?;
        ensure!(
            entry.invoice_id.is_none_or(|old| old == id),
            "server changed the invoice for an idempotency key"
        );
        if !x402 {
            solana::validate(
                invoice,
                id,
                &entry.intent.wallet,
                &entry.intent.payer,
                entry.intent.amount_atoms,
            )?;
        } else if invoice.get("accepts").is_some() {
            validate_x402(invoice, entry.intent.amount_atoms)?;
        }
        if let Some(original) = &entry.invoice {
            if !x402 {
                ensure!(
                    original["terms"] == invoice["terms"]
                        && original["unsignedTransaction"] == invoice["unsignedTransaction"],
                    "server changed the saved invoice terms"
                );
            } else if invoice.get("accepts").is_some() {
                ensure!(
                    original == invoice,
                    "server changed the saved x402 requirements"
                );
            }
        } else {
            entry.invoice = Some(invoice.clone());
        }
        entry.invoice_id = Some(id);
        entry.state = invoice["state"].as_str().map(str::to_owned);
        self.save()?;
        eprintln!("Payment invoice: {id}");
        Ok(())
    }

    fn submission(&mut self, id: Uuid, payload: Value) -> Result<Value> {
        if let Some(saved) = self.data.submissions.get(&id) {
            ensure!(
                saved == &payload,
                "invoice already has a saved submission; retry that exact signed payload"
            );
        } else {
            self.data.submissions.insert(id, payload.clone());
        }
        self.save()?; // Never send signed bytes before durable rename/fsync.
        Ok(payload)
    }

    fn observe(&mut self, id: Uuid, value: &Value) -> Result<()> {
        ensure!(
            invoice_id(value)? == id,
            "status returned a different invoice ID"
        );
        for entry in self
            .data
            .entries
            .values_mut()
            .filter(|e| e.invoice_id == Some(id))
        {
            entry.state = value["state"].as_str().map(str::to_owned);
        }
        self.save()
    }
}

fn invoice_id(value: &Value) -> Result<Uuid> {
    Uuid::parse_str(
        value["invoice_id"]
            .as_str()
            .context("response omitted invoice_id")?,
    )
    .context("invalid invoice ID")
}

fn parse_id(id: &str) -> Result<Uuid> {
    Uuid::parse_str(id).map_err(|_| anyhow!("invoice/recovery id must be a UUID"))
}

fn output(mut value: Value, key: Uuid, id: Option<Uuid>) -> Value {
    value["idempotency_key"] = json!(key);
    if let Some(id) = id {
        value["invoice_id"] = json!(id);
    }
    value
}

pub async fn config(client: &ControlClient) -> Result<Value> {
    client.get("/v1/payments/config").await
}

pub async fn create(
    client: &ControlClient,
    amount_atoms: u64,
    payer: Option<&str>,
    idempotency: Option<Uuid>,
) -> Result<Value> {
    ensure!(amount_atoms > 0, "amount_atoms must be positive");
    let wallet = client.current_wallet()?;
    let default_payer = solana::payer_from_wallet(&wallet)?;
    let payer = payer.unwrap_or(&default_payer);
    solana::pubkey(payer)?;
    let mut journal = Journal::open(client)?;
    let key = journal.prepare(
        Intent {
            method: "solana_wallet".into(),
            wallet: wallet.clone(),
            payer: payer.into(),
            amount_atoms,
        },
        idempotency,
    )?;
    let value = client
        .post_idempotent(
            "/v1/payments/wallet-topups",
            json!({"wallet":wallet,"payer":payer,"amount_atoms":amount_atoms}),
            key,
        )
        .await?;
    journal.record(key, &value, false)?;
    Ok(output(value, key, journal.data.entries[&key].invoice_id))
}

pub async fn status(client: &ControlClient, id: &str) -> Result<Value> {
    let mut journal = Journal::open(client)?;
    let supplied = parse_id(id)?;
    let id = match journal.data.entries.get(&supplied) {
        Some(entry) => entry.invoice_id.context("invoice response was not received; repeat create with the same amount/payer or --idempotency-key to recover it")?,
        None => supplied,
    };
    let value = client.get(&format!("/v1/payments/topups/{id}")).await?;
    journal.observe(id, &value)?;
    Ok(value)
}

pub async fn submit(
    client: &ControlClient,
    id: &str,
    transaction: Option<&str>,
    signature: Option<&str>,
) -> Result<Value> {
    let id = parse_id(id)?;
    let body = match (transaction, signature) {
        (Some(value), None) => {
            ensure!(
                value.len() <= 1644 && STANDARD.decode(value)?.len() <= 1232,
                "transaction exceeds Solana wire limit"
            );
            json!({"transaction":value})
        }
        (None, Some(value)) => {
            ensure!(
                value.len() <= 88 && bs58::decode(value).into_vec()?.len() == 64,
                "invalid Solana signature"
            );
            json!({"signature":value})
        }
        _ => {
            return Err(anyhow!(
                "provide exactly one of --transaction or --signature"
            ))
        }
    };
    let mut journal = Journal::open(client)?;
    let body = journal.submission(id, body)?;
    eprintln!("Payment invoice: {id}; signed submission saved for recovery");
    let value = client
        .post(&format!("/v1/payments/wallet-topups/{id}/submit"), body)
        .await?;
    journal.observe(id, &value)?;
    Ok(value)
}

/// Only sign invoices created and pinned in this profile's journal. Retries
/// submit the original wire even if its unsigned blockhash has since expired.
pub async fn pay(client: &ControlClient, id: &str) -> Result<Value> {
    let supplied = parse_id(id)?;
    let mut journal = Journal::open(client)?;
    let (key, entry) = journal.data.entries.iter().find(|(key, entry)| **key == supplied || entry.invoice_id == Some(supplied))
        .context("invoice is not in this profile's journal; recover using create and its original idempotency key")?;
    let key = *key;
    let id = entry
        .invoice_id
        .context("repeat create to recover the invoice before paying")?;
    let intent = entry.intent.clone();
    let original = entry
        .invoice
        .clone()
        .context("invoice terms were not saved")?;
    ensure!(
        intent.method == "solana_wallet",
        "use submit-x402 with an externally signed payment payload file"
    );
    ensure!(
        intent.wallet == client.current_wallet()?,
        "invoice belongs to another credit wallet"
    );
    eprintln!("Payment recovery id (Idempotency-Key): {key}; invoice: {id}");
    let current = client.get(&format!("/v1/payments/topups/{id}")).await?;
    ensure!(
        current["terms"] == original["terms"]
            && current["unsignedTransaction"] == original["unsignedTransaction"],
        "server changed the saved invoice terms"
    );
    let wire = solana::validate(
        &current,
        id,
        &intent.wallet,
        &intent.payer,
        intent.amount_atoms,
    )?;
    journal.observe(id, &current)?;
    if current["state"] == "credited" {
        return Ok(output(current, key, Some(id)));
    }
    let body = if let Some(saved) = journal.data.submissions.get(&id) {
        saved.clone()
    } else {
        ensure!(
            current["state"] == "created",
            "invoice is not awaiting a new signature; inspect its status"
        );
        ensure!(
            current["terms"]["expiresAt"]
                .as_i64()
                .is_some_and(|expiry| expiry > chrono::Utc::now().timestamp()),
            "invoice expired; refusing to create a new signature"
        );
        let signing = client.wallet_signing_key()?;
        let transaction = solana::sign(&wire, &signing)?;
        journal.submission(id, json!({"transaction":transaction}))?
    };
    let value = client
        .post(&format!("/v1/payments/wallet-topups/{id}/submit"), body)
        .await?;
    journal.observe(id, &value)?;
    Ok(output(value, key, Some(id)))
}

fn x402_invoice_id(value: &Value) -> Result<Uuid> {
    let memo = value["accepts"][0]["extra"]["memo"]
        .as_str()
        .context("x402 requirements omitted invoice memo")?;
    let id = parse_id(
        memo.strip_prefix("pipe-credit:")
            .context("invalid x402 invoice memo")?,
    )?;
    ensure!(
        memo == format!("pipe-credit:{id}"),
        "noncanonical invoice memo"
    );
    Ok(id)
}

fn validate_x402(value: &Value, amount: u64) -> Result<()> {
    ensure!(
        value["x402Version"] == 2 && value["accepts"].as_array().is_some_and(|a| a.len() == 1),
        "expected one x402 v2 payment requirement"
    );
    let accepted = &value["accepts"][0];
    ensure!(
        accepted["scheme"] == "exact"
            && accepted["network"] == solana::MAINNET
            && accepted["asset"] == solana::USDC,
        "x402 requires exact canonical mainnet USDC"
    );
    ensure!(
        accepted["amount"].as_str() == Some(amount.to_string().as_str())
            && amount > 0
            && accepted["extra"]["decimals"] == 6,
        "x402 amount/decimals mismatch"
    );
    solana::pubkey(
        accepted["payTo"]
            .as_str()
            .context("x402 recipient missing")?,
    )?;
    solana::pubkey(
        accepted["extra"]["feePayer"]
            .as_str()
            .context("x402 fee payer missing")?,
    )?;
    x402_invoice_id(value)?;
    Ok(())
}

/// The initial 402 is a successful negotiation of exact invoice requirements.
pub async fn create_x402(
    client: &ControlClient,
    amount_atoms: u64,
    idempotency: Option<Uuid>,
) -> Result<Value> {
    ensure!(amount_atoms > 0, "amount_atoms must be positive");
    let wallet = client.current_wallet()?;
    let mut journal = Journal::open(client)?;
    let key = journal.prepare(
        Intent {
            method: "x402".into(),
            wallet: wallet.clone(),
            payer: String::new(),
            amount_atoms,
        },
        idempotency,
    )?;
    let value = x402_request(
        client,
        json!({"wallet":wallet,"amount_atoms":amount_atoms}),
        key,
        None,
    )
    .await?;
    journal.record(key, &value, true)?;
    Ok(output(value, key, journal.data.entries[&key].invoice_id))
}

/// File: x402 v2 JSON PaymentPayload or base64 PAYMENT-SIGNATURE header.
/// No signing key or local transaction builder is used. `id` accepts either
/// the invoice UUID or its original idempotency/recovery UUID.
pub async fn submit_x402(client: &ControlClient, id: &str, payload_file: &Path) -> Result<Value> {
    let supplied = parse_id(id)?;
    let mut journal = Journal::open(client)?;
    let (key, entry) = journal
        .data
        .entries
        .iter()
        .find(|(key, entry)| **key == supplied || entry.invoice_id == Some(supplied))
        .context(
            "x402 invoice is not in this profile's journal; repeat create-x402 to recover it",
        )?;
    let key = *key;
    let id = entry
        .invoice_id
        .context("repeat create-x402 to recover invoice requirements")?;
    ensure!(
        entry.intent.method == "x402" && entry.intent.wallet == client.current_wallet()?,
        "x402 invoice method/wallet mismatch"
    );
    let invoice = entry
        .invoice
        .as_ref()
        .context("missing x402 requirements")?;
    validate_x402(invoice, entry.intent.amount_atoms)?;
    let body = json!({"wallet":entry.intent.wallet,"amount_atoms":entry.intent.amount_atoms});
    let mut bytes = Vec::new();
    File::open(payload_file)?
        .take(PAYMENT_HEADER_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= PAYMENT_HEADER_LIMIT,
        "payment payload file is too large"
    );
    let value: Value = if let Ok(value) = serde_json::from_slice(&bytes) {
        value
    } else {
        serde_json::from_slice(&STANDARD.decode(std::str::from_utf8(&bytes)?.trim())?)?
    };
    ensure!(
        value["x402Version"] == 2 && value["accepted"] == invoice["accepts"][0],
        "signed x402 payload does not match the saved exact invoice requirements"
    );
    ensure!(
        value["resource"].is_null() || value["resource"] == invoice["resource"],
        "x402 resource mismatch"
    );
    ensure!(
        value["payload"].is_object(),
        "x402 payload must contain an externally signed payment object"
    );
    let encoded = STANDARD.encode(serde_json::to_vec(&value)?);
    ensure!(
        encoded.len() <= PAYMENT_HEADER_LIMIT,
        "PAYMENT-SIGNATURE is too large"
    );
    journal.submission(id, json!({"payment-signature":encoded}))?;
    eprintln!("Payment recovery id (Idempotency-Key): {key}; invoice: {id}; signed payload saved");
    let value = x402_request(client, body, key, Some(&encoded)).await?;
    journal.observe(id, &value)?;
    Ok(output(value, key, Some(id)))
}

async fn x402_request(
    client: &ControlClient,
    body: Value,
    key: Uuid,
    payload: Option<&str>,
) -> Result<Value> {
    for attempt in 0..2 {
        let mut request = client
            .http
            .post(client.url("/v1/payments/topups"))
            .header("idempotency-key", key.to_string())
            .header("x-request-id", Uuid::new_v4().to_string())
            .json(&body);
        if let Some(session) = client.secrets.get("session")? {
            let session: Value = serde_json::from_str(&session)?;
            if let Some(token) = session["access_token"].as_str() {
                request = request.bearer_auth(token);
            }
        }
        if let Some(payload) = payload {
            request = request.header("payment-signature", payload);
        }
        let response = request
            .send()
            .await
            .context("x402 request; repeat with the saved recovery id after a timeout")?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
            client.refresh().await?;
            continue;
        }
        if !status.is_success() && status != reqwest::StatusCode::PAYMENT_REQUIRED {
            return Err(crate::error::response_error(response).await);
        }
        let required = response
            .headers()
            .get("payment-required")
            .map(|v| v.to_str().map(str::to_owned))
            .transpose()?;
        let value: Value =
            serde_json::from_slice(&crate::error::bounded_body(response, BODY_LIMIT).await?)?;
        if let Some(required) = required {
            ensure!(
                required.len() <= PAYMENT_HEADER_LIMIT,
                "PAYMENT-REQUIRED is too large"
            );
            let header: Value = serde_json::from_slice(&STANDARD.decode(required)?)?;
            ensure!(header == value, "x402 header/body requirements disagree");
        }
        if status == reqwest::StatusCode::PAYMENT_REQUIRED {
            ensure!(
                value.get("accepts").is_some() || (payload.is_some() && value["state"] == "failed"),
                "unexpected x402 402 response"
            );
        }
        return Ok(value);
    }
    Err(anyhow!("x402 authentication retry exhausted"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;
    use ed25519_dalek::SigningKey;
    use std::time::Duration;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn client(server: &MockServer, directory: &Path) -> ControlClient {
        let client = ControlClient::for_test(Profile::new(server.uri()), directory).unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        client
            .secrets
            .set("wallet_private_key", &hex::encode(key.to_bytes()))
            .unwrap();
        client
            .secrets
            .set("owner_wallet", &hex::encode(key.verifying_key().to_bytes()))
            .unwrap();
        client
    }

    fn fixture(id: Uuid) -> Value {
        crate::openapi_contract::invoice_fixture(id, &SigningKey::from_bytes(&[7; 32]))
    }

    #[test]
    fn journal_is_private_atomic_locked_and_reuses_unresolved_intents() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("payments.json");
        let intent = Intent {
            method: "solana_wallet".into(),
            wallet: "wallet".into(),
            payer: "payer".into(),
            amount_atoms: 1,
        };
        let mut journal = Journal::at(&path).unwrap();
        let key = journal.prepare(intent.clone(), None).unwrap();
        assert!(Journal::at(&path).is_err());
        drop(journal);
        let mut journal = Journal::at(&path).unwrap();
        assert_eq!(key, journal.prepare(intent.clone(), None).unwrap());
        let mut changed = intent;
        changed.amount_atoms = 2;
        assert!(journal.prepare(changed, Some(key)).is_err());
        let id = Uuid::new_v4();
        journal
            .submission(id, json!({"signature":"saved"}))
            .unwrap();
        assert!(journal
            .submission(id, json!({"signature":"different"}))
            .is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.with_extension("lock"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(journal);
        assert_eq!(
            Journal::at(&path).unwrap().data.submissions[&id],
            json!({"signature":"saved"})
        );
    }

    #[tokio::test]
    async fn create_timeout_persists_key_before_http_and_reuses_it_after_restart() {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let mut first = client(&server, directory.path());
        first.http = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let id = Uuid::new_v4();
        let invoice = fixture(id);
        let journal_path = Journal::open(&first).unwrap().path;
        let observed_path = journal_path.clone();
        let delayed = invoice.clone();
        Mock::given(method("POST"))
            .and(path("/v1/payments/wallet-topups"))
            .respond_with(move |request: &wiremock::Request| {
                let data: JournalData =
                    serde_json::from_slice(&fs::read(&observed_path).unwrap()).unwrap();
                let key =
                    Uuid::parse_str(request.headers["idempotency-key"].to_str().unwrap()).unwrap();
                assert!(
                    data.entries.contains_key(&key),
                    "key was not durable before HTTP"
                );
                ResponseTemplate::new(200)
                    .set_body_json(&delayed)
                    .set_delay(Duration::from_millis(200))
            })
            .mount(&server)
            .await;
        assert!(create(&first, 1_000_000, None, None).await.is_err());
        let data: JournalData = serde_json::from_slice(&fs::read(journal_path).unwrap()).unwrap();
        let key = *data.entries.keys().next().unwrap();
        assert!(data.entries[&key].invoice_id.is_none());
        drop(first);
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/v1/payments/wallet-topups"))
            .and(header("idempotency-key", key.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(&invoice))
            .expect(1)
            .mount(&server)
            .await;
        let restarted = client(&server, directory.path());
        let result = create(&restarted, 1_000_000, None, None).await.unwrap();
        assert_eq!(result["idempotency_key"], key.to_string());
        let requests = server.received_requests().await.unwrap();
        let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["payer"], invoice["terms"]["payer"]);
        assert_ne!(body["payer"], body["wallet"]);
    }

    #[tokio::test]
    async fn pay_persists_signed_wire_before_http_and_replays_without_key() {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let mut client = client(&server, directory.path());
        let id = Uuid::new_v4();
        let invoice = fixture(id);
        Mock::given(method("POST"))
            .and(path("/v1/payments/wallet-topups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&invoice))
            .mount(&server)
            .await;
        create(&client, 1_000_000, None, None).await.unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/v1/payments/topups/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&invoice))
            .mount(&server)
            .await;
        let journal_path = Journal::open(&client).unwrap().path;
        Mock::given(method("POST"))
            .and(path(format!("/v1/payments/wallet-topups/{id}/submit")))
            .respond_with(move |request: &wiremock::Request| {
                let data: JournalData =
                    serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(
                    data.submissions[&id], body,
                    "signed wire was not durable before HTTP"
                );
                ResponseTemplate::new(200)
                    .set_body_json(json!({"invoice_id":id,"state":"confirming"}))
                    .set_delay(Duration::from_millis(200))
            })
            .expect(2)
            .mount(&server)
            .await;
        client.http = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        assert!(pay(&client, &id.to_string()).await.is_err());
        let saved = Journal::open(&client).unwrap().data.submissions[&id].clone();
        client.secrets.delete("wallet_private_key").unwrap();
        client.http = reqwest::Client::new();
        assert_eq!(
            pay(&client, &id.to_string()).await.unwrap()["state"],
            "confirming"
        );
        let requests = server.received_requests().await.unwrap();
        let submissions: Vec<Value> = requests
            .iter()
            .filter(|r| r.url.path().ends_with("/submit"))
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect();
        assert_eq!(submissions, vec![saved.clone(), saved]);
    }

    #[tokio::test]
    async fn pay_refuses_changed_terms_and_wrong_local_signer_without_submission() {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let client = client(&server, directory.path());
        let id = Uuid::new_v4();
        let mut invoice = fixture(id);
        Mock::given(method("POST"))
            .and(path("/v1/payments/wallet-topups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&invoice))
            .mount(&server)
            .await;
        create(&client, 1_000_000, None, None).await.unwrap();
        client
            .secrets
            .set("wallet_private_key", &hex::encode([8; 32]))
            .unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/v1/payments/topups/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&invoice))
            .mount(&server)
            .await;
        assert!(pay(&client, &id.to_string())
            .await
            .unwrap_err()
            .to_string()
            .contains("signing key"));
        client
            .secrets
            .set("wallet_private_key", &hex::encode([7; 32]))
            .unwrap();
        server.reset().await;
        invoice["terms"]["amount"] = json!("2000000");
        Mock::given(method("GET"))
            .and(path(format!("/v1/payments/topups/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&invoice))
            .mount(&server)
            .await;
        assert!(pay(&client, &id.to_string())
            .await
            .unwrap_err()
            .to_string()
            .contains("changed"));
        assert!(Journal::open(&client).unwrap().data.submissions.is_empty());
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET"));
    }

    fn x402_invoice(id: Uuid) -> Value {
        json!({"x402Version":2,"resource":{"url":"https://example.test/v1/payments/topups","description":"test","mimeType":"application/json","serviceName":"Pipe Storage"},
            "accepts":[{"scheme":"exact","network":solana::MAINNET,"asset":solana::USDC,"amount":"1000000","payTo":solana::USDC,"maxTimeoutSeconds":120,
                "extra":{"feePayer":solana::USDC,"decimals":6,"memo":format!("pipe-credit:{id}")}}]})
    }

    #[tokio::test]
    async fn x402_402_negotiation_pins_terms_and_submits_external_payload_with_same_key() {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let mut client = client(&server, directory.path());
        let id = Uuid::new_v4();
        let required = x402_invoice(id);
        Mock::given(method("POST"))
            .and(path("/v1/payments/topups"))
            .respond_with(
                ResponseTemplate::new(402)
                    .insert_header(
                        "payment-required",
                        STANDARD.encode(serde_json::to_vec(&required).unwrap()),
                    )
                    .set_body_json(&required),
            )
            .mount(&server)
            .await;
        let result = create_x402(&client, 1_000_000, None).await.unwrap();
        assert_eq!(result["invoice_id"], id.to_string());
        let key = result["idempotency_key"].as_str().unwrap();
        assert_eq!(result["accepts"], required["accepts"]);
        let file = directory.path().join("payload.json");
        let mut payload = json!({"x402Version":2,"accepted":required["accepts"][0],"resource":required["resource"],"payload":{"transaction":"externally-signed-test-fixture"}});
        payload["accepted"]["amount"] = json!("2000000");
        crate::keyring::atomic_private_write(&file, &serde_json::to_vec(&payload).unwrap())
            .unwrap();
        assert!(submit_x402(&client, &id.to_string(), &file).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        payload["accepted"]["amount"] = json!("1000000");
        crate::keyring::atomic_private_write(&file, &serde_json::to_vec(&payload).unwrap())
            .unwrap();
        server.reset().await;
        let journal_path = Journal::open(&client).unwrap().path;
        Mock::given(method("POST"))
            .and(path("/v1/payments/topups"))
            .and(header("idempotency-key", key))
            .respond_with(move |request: &wiremock::Request| {
                let data: JournalData =
                    serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
                assert_eq!(
                    data.submissions[&id]["payment-signature"],
                    request.headers["payment-signature"].to_str().unwrap()
                );
                ResponseTemplate::new(202)
                    .set_body_json(json!({"invoice_id":id,"state":"confirming"}))
                    .set_delay(Duration::from_millis(200))
            })
            .expect(2)
            .mount(&server)
            .await;
        client.http = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        assert!(submit_x402(&client, key, &file).await.is_err());
        // Both file representations must replay the exact durable header.
        let encoded = STANDARD.encode(serde_json::to_vec(&payload).unwrap());
        crate::keyring::atomic_private_write(&file, encoded.as_bytes()).unwrap();
        client.secrets.delete("wallet_private_key").unwrap();
        client.http = reqwest::Client::new();
        assert_eq!(
            submit_x402(&client, &id.to_string(), &file).await.unwrap()["state"],
            "confirming"
        );
    }

    #[tokio::test]
    async fn x402_rejects_conflicting_header_terms_without_losing_recovery_key() {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let client = client(&server, directory.path());
        let required = x402_invoice(Uuid::new_v4());
        let mut conflicting = required.clone();
        conflicting["accepts"][0]["amount"] = json!("2000000");
        Mock::given(method("POST"))
            .and(path("/v1/payments/topups"))
            .respond_with(
                ResponseTemplate::new(402)
                    .insert_header(
                        "payment-required",
                        STANDARD.encode(serde_json::to_vec(&conflicting).unwrap()),
                    )
                    .set_body_json(&required),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(create_x402(&client, 1_000_000, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("disagree"));
        let journal = Journal::open(&client).unwrap();
        assert_eq!(journal.data.entries.len(), 1);
        assert!(journal
            .data
            .entries
            .values()
            .next()
            .unwrap()
            .invoice
            .is_none());
        assert!(journal.data.submissions.is_empty());
    }

    #[tokio::test]
    async fn endpoint_and_profile_directories_isolate_journals() {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let a = client(&server, &directory.path().join("a"));
        let mut b = client(&server, &directory.path().join("a"));
        b.profile.control_api_url.push_str("/different-api");
        let c = client(&server, &directory.path().join("c"));
        let a = Journal::open(&a).unwrap();
        let b = Journal::open(&b).unwrap();
        let c = Journal::open(&c).unwrap();
        assert_ne!(a.path, b.path);
        assert_ne!(a.path, c.path);
    }
}

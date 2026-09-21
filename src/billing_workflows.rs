//! Hosted payments and legacy invoice recovery. Creating a URL never transfers funds.
use crate::{auth::ControlClient, compute_journal::ContextBinding, output, platform, secure_state};
use anyhow::{ensure, Context, Result};
use clap::Subcommand;
use pipe_api::billing::Request;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Subcommand, Debug)]
pub enum Card {
    Config,
    List,
    /// Create a hosted card checkout. Amount is whole USD cents; payment occurs in the browser.
    Checkout {
        #[arg(long)]
        wallet: String,
        #[arg(long,value_parser=clap::value_parser!(i64).range(500..=1_000_000))]
        amount_cents: i64,
    },
    Reconcile {
        id: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum Solana {
    /// Retained Solana Pay flow, available only where explicitly enabled. Never signs or sends funds.
    Create {
        org: String,
        #[arg(long,value_parser=clap::value_parser!(i64).range(500..=1_000_000))]
        amount_cents: i64,
    },
    /// Verify an already submitted transaction signature against the original invoice.
    Verify {
        org: String,
        id: String,
        #[arg(long)]
        signature: String,
    },
    Sync {
        org: String,
        id: String,
    },
}
#[derive(Debug, thiserror::Error)]
#[error("billing outcome unknown for request {request_id}; use pipe billing resume {request_id}; do not submit a replacement")]
pub struct UnknownOutcome {
    pub request_id: Uuid,
}
const SPEC: secure_state::Spec<'static> = secure_state::Spec {
    file: "billing-state-v1.enc",
    key: "billing-journal-key-v1",
    magic: b"PIPEBIL1",
    limit: 16 * 1024 * 1024,
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    binding: ContextBinding,
    request: Request,
    state: String,
    response: Option<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    requests: BTreeMap<Uuid, Entry>,
}
impl Journal {
    fn load(c: &ControlClient) -> Result<Self> {
        let Some(clear) = secure_state::read(c, &SPEC)? else {
            return Ok(Self {
                version: 1,
                requests: BTreeMap::new(),
            });
        };
        let s: Self = serde_json::from_slice(&clear)
            .context("invalid billing journal; original preserved")?;
        ensure!(
            s.version == 1,
            "unsupported billing journal; original preserved"
        );
        Ok(s)
    }
    fn save(&self, c: &ControlClient) -> Result<()> {
        secure_state::write(
            c,
            &SPEC,
            &zeroize::Zeroizing::new(serde_json::to_vec(self)?),
        )
    }
    fn metadata(&self) -> Value {
        json!({"requests":self.requests.iter().map(|(id,e)|json!({"request_id":id,"context":e.binding,"operation":e.request.operation().0,"state":e.state})).collect::<Vec<_>>()})
    }
}
async fn binding(c: &ControlClient) -> Result<ContextBinding> {
    let v = c.get("/v1/cli/context").await?;
    platform::validate_response("platformCliContext", "200", &v)?;
    Ok(ContextBinding {
        endpoint: c.url(""),
        owner_wallet: v["principal"]["owner_wallet"]
            .as_str()
            .context("missing canonical owner")?
            .into(),
        account_id: v["principal"]["account_id"].as_str().map(str::to_owned),
    })
}
fn identifier(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn public_key(v: &str, n: usize) -> bool {
    bs58::decode(v).into_vec().map(|b| b.len()).ok() == Some(n)
}
fn validate(r: &Request) -> Result<()> {
    use Request::*;
    ensure!(
        r.org().is_none_or(identifier),
        "invalid organization identifier"
    );
    match r {
        CardCheckout {
            wallet,
            amount_cents,
        } => ensure!(
            wallet.len() == 64
                && wallet
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && (500..=1_000_000).contains(amount_cents),
            "choose a linked wallet and 500–1000000 whole USD cents"
        ),
        Checkout { amount_cents, .. } | SolanaCreate { amount_cents, .. } => ensure!(
            (500..=1_000_000).contains(amount_cents),
            "amount must be 500–1000000 whole USD cents"
        ),
        Settings {
            enabled,
            threshold_cents,
            amount_cents,
            ..
        } => {
            ensure!(
                threshold_cents.is_none_or(|v| v > 0 && v <= 1_000_000)
                    && amount_cents.is_none_or(|v| (500..=1_000_000).contains(&v)),
                "invalid recharge USD cents"
            );
            ensure!(
                !enabled
                    || (threshold_cents.is_some()
                        && amount_cents.is_some()
                        && amount_cents >= threshold_cents),
                "enable recharge only with an amount at least the positive threshold"
            );
        }
        PlanCheckout { plan, .. } => ensure!(identifier(plan), "invalid plan identifier"),
        _ => {}
    }
    match r {
        SolanaCreate { id, reference, .. } => ensure!(
            id.len() == 39
                && id.starts_with("solpay_")
                && identifier(id)
                && public_key(reference, 32),
            "invalid original Solana invoice material"
        ),
        SolanaVerify { id, signature, .. } => ensure!(
            identifier(id) && public_key(signature, 64),
            "invalid payment ID or transaction signature"
        ),
        SolanaSync { id, .. } => ensure!(identifier(id), "invalid payment ID"),
        _ => {}
    }
    let (op, _, _) = r.operation();
    if let Some(body) = r.body() {
        let (_, _, operation) = platform::operation(op)?;
        platform::validate(
            &operation["requestBody"]["content"]["application/json"]["schema"],
            &body,
        )?;
    }
    Ok(())
}
fn safe_url(v: &str, portal: bool) -> bool {
    reqwest::Url::parse(v).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str()
                == Some(if portal {
                    "billing.stripe.com"
                } else {
                    "checkout.stripe.com"
                })
            && u.username().is_empty()
            && u.password().is_none()
            && u.port().is_none()
    })
}
fn cents(v: &Value) -> Option<i64> {
    let text = v.as_number()?.to_string();
    let negative = text.starts_with('-');
    let text = text.strip_prefix('-').unwrap_or(&text);
    let mut parts = text.split('.');
    let whole = parts.next()?.parse::<i128>().ok()?;
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some() || fraction.len() > 2 || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let f = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<i128>().ok()? * 10,
        _ => fraction.parse::<i128>().ok()?,
    };
    let value = whole.checked_mul(100)?.checked_add(f)?;
    i64::try_from(if negative { -value } else { value }).ok()
}

fn validate_receipt(r: &Request, v: &Value) -> Result<()> {
    use Request::*;
    platform::validate_response(r.operation().0, "200", v)?;
    match r {
        Checkout { .. } | PlanCheckout { .. } | Portal { .. } => ensure!(
            v["url"]
                .as_str()
                .is_some_and(|s| safe_url(s, matches!(r, Portal { .. })))
                && v["id"].as_str().is_some_and(identifier),
            "hosted billing receipt has an invalid destination or identifier"
        ),
        CardCheckout {
            wallet,
            amount_cents,
        } => {
            ensure!(
                v["wallet"] == *wallet && v["amount_cents"].as_i64() == Some(*amount_cents),
                "card checkout receipt differs from saved terms"
            );
            ensure!(
                v["checkout_url"].is_null()
                    || v["checkout_url"]
                        .as_str()
                        .is_some_and(|s| safe_url(s, false)),
                "invalid card checkout destination"
            );
        }
        CardHistory => {
            ensure!(
                v["topups"]
                    .as_array()
                    .is_some_and(|a| a.iter().all(|v| v["checkout_url"].is_null()
                        || v["checkout_url"]
                            .as_str()
                            .is_some_and(|u| safe_url(u, false)))),
                "invalid checkout destination in card history"
            );
        }
        Settings { org, .. } => {
            ensure!(
                v["org_id"] == *org,
                "billing settings response belongs to another organization"
            );
            let body = r.body().unwrap();
            ensure!(
                body.as_object()
                    .unwrap()
                    .iter()
                    .all(|(k, expected)| if expected.is_number() {
                        cents(expected) == cents(&v[k])
                    } else {
                        expected == &v[k]
                    }),
                "billing settings differ from saved terms"
            );
        }
        CardReconcile { id } => ensure!(
            v["id"] == id.to_string(),
            "card reconciliation returned another order"
        ),
        SolanaCreate {
            id,
            reference,
            amount_cents,
            ..
        } => {
            ensure!(
                v["org_id"].as_str() == r.org()
                    && v["id"] == *id
                    && v["reference"] == *reference
                    && cents(&v["amount_usd"]) == Some(*amount_cents)
                    && cents(&v["amount_usdc"]) == Some(*amount_cents),
                "Solana invoice differs from saved original terms"
            );
            let recipient = v["recipient_wallet"]
                .as_str()
                .context("missing recipient")?;
            let mint = v["spl_token_mint"].as_str().context("missing mint")?;
            ensure!(
                public_key(recipient, 32) && public_key(mint, 32),
                "invalid Solana recipient or mint"
            );
            let u = reqwest::Url::parse(v["payment_url"].as_str().context("missing payment URL")?)?;
            let pairs: Vec<_> = u.query_pairs().collect();
            let exactly = |key: &str, expected: &str| {
                pairs.iter().filter(|(k, _)| k == key).count() == 1
                    && pairs.iter().any(|(k, v)| k == key && v == expected)
            };
            ensure!(
                u.scheme() == "solana"
                    && u.path() == recipient
                    && u.fragment().is_none()
                    && exactly(
                        "amount",
                        &format!("{}.{:02}", amount_cents / 100, amount_cents % 100)
                    )
                    && exactly("spl-token", mint)
                    && exactly("reference", reference)
                    && exactly("memo", id),
                "Solana payment URL differs from the validated invoice"
            );
        }
        SolanaVerify { org, id, signature } => ensure!(
            v["org_id"] == *org
                && v["id"] == *id
                && (v["status"] != "paid" || v["signature"] == *signature),
            "Solana verification receipt differs from saved submission"
        ),
        SolanaSync { org, id } => ensure!(
            v["org_id"] == *org && v["id"] == *id,
            "Solana reconciliation returned another invoice"
        ),
        _ => {}
    }
    Ok(())
}
async fn send(c: &ControlClient, r: &Request, id: Uuid) -> Result<Value> {
    let (_, method, path) = r.operation();
    let v = if method == "GET" {
        c.get(&path).await?
    } else {
        c.send_idempotent(
            reqwest::Method::POST,
            &path,
            r.body().unwrap_or(json!({})),
            id,
            reqwest::StatusCode::OK,
        )
        .await?
    };
    validate_receipt(r, &v)?;
    Ok(v)
}
async fn commit(c: &ControlClient, s: &mut Journal, id: Uuid) -> Result<Value> {
    let r = s.requests[&id].request.clone();
    match send(c, &r, id).await {
        Ok(v) => {
            let e = s.requests.get_mut(&id).unwrap();
            e.state = "complete".into();
            e.response = Some(v.clone());
            s.save(c).map_err(|_| UnknownOutcome { request_id: id })?;
            Ok(json!({"request_id":id,"state":"complete","data":v}))
        }
        Err(error) => {
            // Authentication/authorization and payload rejection occur before side
            // effects. Conflicts and server/transport errors remain unknown.
            if error
                .downcast_ref::<crate::error::ApiError>()
                .is_some_and(|e| matches!(e.status.as_u16(), 400 | 401 | 403 | 404 | 422))
            {
                let e = s.requests.get_mut(&id).unwrap();
                e.state = "rejected".into();
                s.save(c)?;
                return Err(error);
            }
            Err(anyhow::Error::new(UnknownOutcome { request_id: id }).context(error))
        }
    }
}
fn unavailable(message: &str) -> anyhow::Error {
    crate::error::ApiError {
        status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
        code: "feature_unavailable".into(),
        message: message.into(),
        request_id: None,
    }
    .into()
}
pub async fn run(c: &ControlClient, r: Request, json_output: bool) -> Result<()> {
    validate(&r)?;
    if r.operation().1 == "GET" {
        return output::print(&send(c, &r, Uuid::nil()).await?, json_output);
    }
    // Availability is read before saving intent. It is never inferred from a 404.
    if matches!(r, Request::CardCheckout { .. }) {
        let available = send(c, &Request::CardConfig, Uuid::nil()).await?;
        if available["available"] != true {
            return Err(unavailable(
                "card checkout is unavailable in this deployment",
            ));
        }
    }
    if let Request::SolanaCreate { org, .. } = &r {
        let value = c
            .get(&format!("/v1/platform/organizations/{org}/billing"))
            .await?;
        platform::validate_response("platform.billing.summary", "200", &value)?;
        if value["solana_usdc_enabled"] != true {
            return Err(unavailable("legacy Solana payment creation is unavailable in this deployment; existing invoices can still be reconciled"));
        }
    }
    let b = binding(c).await?;
    let mut s = Journal::load(c)?;
    ensure!(
        s.requests.len() < 4096,
        "billing journal limit reached; preserve recovery records"
    );
    for (id, e) in &s.requests {
        ensure!(e.binding!=b||e.state!="unknown","unresolved billing request {id}; use pipe billing resume {id} before another billing mutation");
    }
    let id = Uuid::new_v4();
    s.requests.insert(
        id,
        Entry {
            binding: b,
            request: r,
            state: "unknown".into(),
            response: None,
        },
    );
    s.save(c)?;
    output::print(&commit(c, &mut s, id).await?, json_output)
}
pub async fn requests(c: &ControlClient, json_output: bool) -> Result<()> {
    output::print(&Journal::load(c)?.metadata(), json_output)
}
pub async fn resume(c: &ControlClient, id: Uuid, json_output: bool) -> Result<()> {
    let b = binding(c).await?;
    let mut s = Journal::load(c)?;
    let e = s
        .requests
        .get(&id)
        .context("saved billing request not found")?;
    ensure!(
        e.binding == b,
        "billing request belongs to another account or endpoint"
    );
    if e.state != "unknown" {
        return output::print(
            &json!({"request_id":id,"state":e.state,"data":e.response}),
            json_output,
        );
    }
    validate(&e.request)?;
    if let Request::SolanaCreate {
        org, id: payment, ..
    } = &e.request
    {
        let current = c
            .get(&format!("/v1/platform/organizations/{org}/billing"))
            .await?;
        platform::validate_response("platform.billing.summary", "200", &current)?;
        if let Some(value) = current["solana_usdc_payments"]
            .as_array()
            .and_then(|items| items.iter().find(|v| v["id"] == *payment))
            .cloned()
        {
            validate_receipt(&e.request, &value)?;
            let e = s.requests.get_mut(&id).unwrap();
            e.state = "observed".into();
            e.response = Some(value.clone());
            s.save(c)?;
            return output::print(
                &json!({"request_id":id,"state":"observed","data":value}),
                json_output,
            );
        }
    }
    if let Request::Settings { org, .. } = &e.request {
        let current = c
            .get(&format!("/v1/platform/organizations/{org}/billing"))
            .await?;
        platform::validate_response("platform.billing.summary", "200", &current)?;
        let expected = e.request.body().unwrap();
        let matches = expected.as_object().unwrap().iter().all(|(k, v)| {
            if v.is_number() {
                cents(v) == cents(&current["customer"][k])
            } else {
                v == &current["customer"][k]
            }
        });
        if matches {
            let value = current["customer"].clone();
            let e = s.requests.get_mut(&id).unwrap();
            e.state = "observed".into();
            e.response = Some(value.clone());
            s.save(c)?;
            return output::print(
                &json!({"request_id":id,"state":"observed","data":value}),
                json_output,
            );
        }
        return Err(UnknownOutcome { request_id: id }.into());
    }
    // Explicit resume reuses the saved idempotency key, original invoice ID,
    // reference and signature. The backend bounds provider replay to 23 hours.
    ensure!(e.request.safe_resume(), "request cannot be repeated safely");
    output::print(&commit(c, &mut s, id).await?, json_output)
}
pub async fn card(c: &ControlClient, cmd: Card, j: bool) -> Result<()> {
    run(
        c,
        match cmd {
            Card::Config => Request::CardConfig,
            Card::List => Request::CardHistory,
            Card::Checkout {
                wallet,
                amount_cents,
            } => Request::CardCheckout {
                wallet,
                amount_cents,
            },
            Card::Reconcile { id } => Request::CardReconcile { id },
        },
        j,
    )
    .await
}
pub async fn solana(c: &ControlClient, cmd: Solana, j: bool) -> Result<()> {
    run(
        c,
        match cmd {
            Solana::Create { org, amount_cents } => Request::SolanaCreate {
                org,
                amount_cents,
                id: format!("solpay_{}", Uuid::new_v4().simple()),
                reference: bs58::encode(rand::random::<[u8; 32]>()).into_string(),
            },
            Solana::Verify { org, id, signature } => Request::SolanaVerify { org, id, signature },
            Solana::Sync { org, id } => Request::SolanaSync { org, id },
        },
        j,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_money_and_hosted_destinations_reject_substitution() {
        for cents_value in [
            0,
            1,
            501,
            999,
            1_000_000,
            9_007_199_254_740_993,
            i64::MIN,
            i64::MAX,
        ] {
            assert_eq!(
                cents(&Value::Number(pipe_api::billing::dollars(cents_value))),
                Some(cents_value)
            );
        }
        assert_eq!(cents(&json!("5.01")), None);
        assert_eq!(
            cents(&serde_json::from_str::<Value>("5.001").unwrap()),
            None
        );
        for value in [
            "http://checkout.stripe.com/c/pay/a",
            "https://checkout.stripe.com.evil.test/a",
            "https://checkout.stripe.com@evil.test/a",
            "https://checkout.stripe.com:444/a",
            "https://billing.stripe.com/a",
        ] {
            assert!(!safe_url(value, false));
        }
        assert!(safe_url(
            "https://checkout.stripe.com/c/pay/cs_test#safe",
            false
        ));
        assert!(safe_url(
            "https://billing.stripe.com/session/bps_test",
            true
        ));
        for (field, value) in [
            ("url", json!("https://checkout.stripe.com.evil.test/a")),
            ("id", json!("cs_test/../other")),
        ] {
            let mut receipt =
                json!({"id":"cs_test","url":"https://checkout.stripe.com/c/pay/cs_test"});
            receipt[field] = value;
            assert!(validate_receipt(
                &Request::Checkout {
                    org: "org_test".into(),
                    amount_cents: 501
                },
                &receipt
            )
            .is_err());
        }
    }
}

//! Canonical account, organization and billing workflows. No implicit balance conversion.
use crate::{
    auth::ControlClient, compute_journal::ContextBinding, customer_state::State, error::ApiError,
    output, platform,
};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use pipe_api::account::{History, Request};
use serde_json::{json, Value};
use std::{collections::HashSet, path::PathBuf};
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
#[error("outcome unknown for customer request {request_id}; use pipe account resume {request_id}; do not submit a replacement")]
pub struct UnknownOutcome {
    pub request_id: Uuid,
}
#[derive(Subcommand, Debug)]
pub enum Account {
    Keys {
        #[command(subcommand)]
        command: crate::account_keys::Commands,
    },
    /// Canonical platform profile; requires a linked platform account.
    Get,
    Identities,
    Wallets,
    /// Preserved infrastructure account and credit identities.
    Infrastructure,
    Update {
        #[arg(
            long,
            required_unless_present = "clear_name",
            conflicts_with = "clear_name"
        )]
        display_name: Option<String>,
        #[arg(long)]
        clear_name: bool,
    },
    Referrals,
    RotateReferral,
    Requests,
    Resume {
        request_id: Uuid,
    },
    /// Acknowledge an inspected outcome; this does not undo or retry server work.
    Acknowledge {
        request_id: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum Org {
    Audit {
        org: String,
        #[arg(long)]
        before: Option<u64>,
    },
    List,
    Create {
        name: String,
    },
    Members {
        org: String,
        #[command(subcommand)]
        command: Members,
    },
    Invites {
        org: String,
        #[command(subcommand)]
        command: Invites,
    },
    /// The invitation token is read from a private file, never a process argument.
    Accept {
        #[arg(long)]
        token_file: PathBuf,
    },
    Requests,
    Resume {
        request_id: Uuid,
    },
    Acknowledge {
        request_id: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum Members {
    List,
    Update {
        account: String,
        #[arg(long,value_parser=["owner","admin","billing_admin","member","developer","auditor"])]
        role: String,
    },
    Delete {
        account: String,
    },
}
#[derive(Subcommand, Debug)]
pub enum Invites {
    List,
    Create {
        email: String,
        #[arg(long,default_value="member",value_parser=["owner","admin","billing_admin","member","developer","auditor"])]
        role: String,
    },
    Revoke {
        id: String,
    },
    /// Export the locally saved acceptance token only with --show-secret.
    Export {
        request_id: Uuid,
    },
}
#[derive(Args, Debug)]
pub struct Page {
    #[arg(long,default_value_t=100,value_parser=clap::value_parser!(u32).range(1..=1000))]
    limit: u32,
    #[arg(long)]
    cursor: Option<String>,
    /// Follow at most 100 pages; a remaining cursor is always returned.
    #[arg(long)]
    all: bool,
    #[arg(long)]
    from: Option<String>,
    #[arg(long)]
    to: Option<String>,
    #[arg(long)]
    search: Option<String>,
}
#[derive(Subcommand, Debug)]
pub enum Billing {
    Card {
        #[command(subcommand)]
        command: crate::billing_workflows::Card,
    },
    /// Hosted purchase of platform billing credits. Amount is whole USD cents.
    Checkout {
        org: String,
        #[arg(long,value_parser=clap::value_parser!(i64).range(500..=1_000_000))]
        amount_cents: i64,
    },
    PlanCheckout {
        org: String,
        #[arg(long)]
        plan: String,
    },
    Portal {
        org: String,
    },
    Settings {
        org: String,
        #[arg(long,action=clap::ArgAction::Set,required=true)]
        enabled: bool,
        #[arg(long)]
        threshold_cents: Option<i64>,
        #[arg(long)]
        amount_cents: Option<i64>,
    },
    Solana {
        #[command(subcommand)]
        command: crate::billing_workflows::Solana,
    },
    Requests,
    Resume {
        request_id: Uuid,
    },

    /// Platform billing credits, with separate USD fields. No infrastructure credits.
    Balance {
        #[arg(long)]
        org: Option<String>,
    },
    Ledger {
        #[arg(long)]
        org: Option<String>,
        #[command(flatten)]
        page: Page,
        #[arg(long,value_parser=["credit","charge","reservation","release","credit_expiration"])]
        entry_type: Option<String>,
    },
    Usage {
        #[arg(long)]
        org: Option<String>,
        #[command(flatten)]
        page: Page,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long,value_parser=["model","project"])]
        group_by: Option<String>,
    },
    Get {
        org: String,
    },
    Invoices {
        org: String,
    },
    Subscriptions {
        org: String,
    },
}
pub fn billing_confirmation(c: &Billing) -> bool {
    matches!(
        c,
        Billing::Checkout { .. }
            | Billing::PlanCheckout { .. }
            | Billing::Portal { .. }
            | Billing::Settings { .. }
            | Billing::Card {
                command: crate::billing_workflows::Card::Checkout { .. }
                    | crate::billing_workflows::Card::Reconcile { .. }
            }
            | Billing::Solana { .. }
            | Billing::Resume { .. }
    )
}
pub fn account_confirmation(c: &Account) -> bool {
    if let Account::Keys { command } = c {
        return crate::account_keys::confirmation(command);
    }
    matches!(
        c,
        Account::Update { .. } | Account::RotateReferral | Account::Acknowledge { .. }
    )
}
pub fn org_confirmation(c: &Org) -> bool {
    matches!(
        c,
        Org::Create { .. }
            | Org::Members {
                command: Members::Update { .. } | Members::Delete { .. },
                ..
            }
            | Org::Invites {
                command: Invites::Create { .. } | Invites::Revoke { .. },
                ..
            }
            | Org::Accept { .. }
            | Org::Acknowledge { .. }
    )
}
pub(crate) async fn binding(c: &ControlClient) -> Result<ContextBinding> {
    let v = c.get("/v1/cli/context").await?;
    platform::validate_response("platformCliContext", "200", &v)?;
    let account = v["principal"]["account_id"]
        .as_str()
        .context("a canonical platform account is required")?
        .to_owned();
    Ok(ContextBinding {
        endpoint: c.url(""),
        owner_wallet: v["principal"]["owner_wallet"]
            .as_str()
            .context("missing canonical owner")?
            .into(),
        account_id: Some(account),
    })
}
fn validate(r: &Request) -> Result<String> {
    for id in r.identifiers() {
        ensure!(
            !id.is_empty()
                && id.len() <= 256
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid account, organization or invitation identifier"
        );
    }
    match r {
        Request::CreateApiKey { settings, .. } | Request::UpdateApiKey { settings, .. } => {
            if let Request::CreateApiKey { api_key, .. } = r {
                ensure!(
                    api_key.len() == 36
                        && api_key.starts_with("api_")
                        && api_key[4..]
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "invalid generated account API key"
                );
            }
            if let pipe_api::keys::Field::Value(label) = &settings.label {
                ensure!(
                    label.len() <= 200,
                    "key label must be at most 200 UTF-8 bytes"
                );
            }
            if let Some(models) = &settings.allowed_models {
                ensure!(
                    models.len() <= 32
                        && models
                            .iter()
                            .all(|s| !s.is_empty() && s.trim() == s && s.len() <= 128),
                    "invalid model allowlist"
                );
            }
        }
        Request::CreateOrg { id, name } => {
            ensure!(
                name.trim() == name && !name.is_empty() && name.len() <= 200,
                "organization name must contain 1 to 200 UTF-8 bytes"
            );
            ensure!(
                id.len() == 36 && id.starts_with("org_"),
                "invalid generated organization ID"
            );
        }
        Request::Profile { display_name } => ensure!(
            display_name.as_ref().is_none_or(|s| s.len() <= 200),
            "display name is too long"
        ),
        Request::CreateInvite {
            id,
            email,
            accept_token,
            ..
        } => {
            ensure!(
                id.len() == 39 && id.starts_with("invite_") && accept_token.len() == 32,
                "invalid generated invitation material"
            );
            ensure!(
                email.len() <= 254
                    && email.split('@').count() == 2
                    && !email.starts_with('@')
                    && !email.ends_with('@')
                    && !email.chars().any(|c| c.is_whitespace() || c.is_control()),
                "invalid invitation email"
            );
        }
        _ => {}
    }
    let (id, verb, path) = r.operation();
    let (_, method, op) = platform::operation(id)?;
    ensure!(
        method.eq_ignore_ascii_case(verb),
        "request method differs from contract"
    );
    if let Some(body) = r.body() {
        platform::validate(
            &op["requestBody"]["content"]["application/json"]["schema"],
            &body,
        )?;
    }
    let mut url = reqwest::Url::parse("https://contract.invalid")?;
    url.set_path(&path);
    if let Some(h) = r.history() {
        ensure!((1..=1000).contains(&h.limit), "limit must be 1 to 1000");
        for date in [&h.created_at_from, &h.created_at_to].into_iter().flatten() {
            chrono::DateTime::parse_from_rfc3339(date).context("invalid RFC3339 history time")?;
        }
        if let (Some(a), Some(b)) = (&h.created_at_from, &h.created_at_to) {
            ensure!(
                chrono::DateTime::parse_from_rfc3339(a)?
                    <= chrono::DateTime::parse_from_rfc3339(b)?,
                "from must not be after to"
            );
        }
        for (name, value) in h.pairs() {
            let p = op["parameters"]
                .as_array()
                .context("missing history parameters")?
                .iter()
                .find(|p| p["in"] == "query" && p["name"] == name)
                .context("unsupported history parameter")?;
            platform::validate(
                &p["schema"],
                &if name == "limit" {
                    json!(h.limit)
                } else {
                    json!(value)
                },
            )?;
            url.query_pairs_mut().append_pair(&name, &value);
        }
    }
    Ok(format!(
        "{}{}",
        url.path(),
        url.query().map(|q| format!("?{q}")).unwrap_or_default()
    ))
}
pub(crate) async fn read(c: &ControlClient, r: &Request) -> Result<Value> {
    ensure!(
        r.operation().1 == "GET",
        "read helper does not submit mutations"
    );
    let v = c.get(&validate(r)?).await?;
    platform::validate_response(r.operation().0, "200", &v)?;
    Ok(v)
}
fn public_receipt(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(m) = v.as_object_mut() {
        m.remove("accept_token");
        m.remove("accept_url");
        m.remove("api_key");
    }
    v
}
pub(crate) async fn mutate(c: &ControlClient, b: &ContextBinding, r: Request) -> Result<Value> {
    let path = validate(&r)?;
    let id = Uuid::new_v4();
    let mut s = State::load(c)?;
    s.prepare(c, id, b.clone(), r.clone())?;
    let method = reqwest::Method::from_bytes(r.operation().1.as_bytes())?;
    let result = c
        .send_idempotent(
            method,
            &path,
            r.body().unwrap_or(json!({})),
            id,
            reqwest::StatusCode::OK,
        )
        .await;
    match result {
        Ok(v) => {
            if platform::validate_response(r.operation().0, "200", &v).is_err() {
                return Err(anyhow::Error::new(UnknownOutcome{request_id:id}).context(format!("customer request {id} returned an incompatible response; use account resume {id}")));
            }
            if let Request::CreateInvite {
                id: expected,
                accept_token,
                ..
            } = &r
            {
                if v["invite"]["id"] != *expected || v["accept_token"] != *accept_token {
                    return Err(anyhow::Error::new(UnknownOutcome{request_id:id}).context(format!("customer request {id} returned different invitation material; inspect before proceeding")));
                }
            }
            if let Request::CreateApiKey {
                id: expected,
                api_key,
                ..
            } = &r
            {
                if v["api_key_id"] != expected.to_string() || v["api_key"] != *api_key {
                    return Err(anyhow::Error::new(UnknownOutcome { request_id: id })
                        .context("account API key receipt differs from securely saved material"));
                }
            }
            s.finish(c, id, "complete", Some(public_receipt(&v)))?;
            Ok(json!({"request_id":id,"state":"complete","data":public_receipt(&v)}))
        }
        Err(e) => {
            if e.downcast_ref::<ApiError>().is_some_and(|e| {
                matches!(
                    e.status.as_u16(),
                    400 | 401 | 403 | 404 | 405 | 409 | 410 | 413 | 422 | 429
                )
            }) {
                s.finish(c, id, "rejected", None)?;
                return Err(e);
            }
            Err(
                anyhow::Error::new(UnknownOutcome { request_id: id }).context(format!(
                    "customer request {id} has an unknown outcome; use account resume {id}"
                )),
            )
        }
    }
}
async fn resume(c: &ControlClient, b: &ContextBinding, id: Uuid) -> Result<Value> {
    let mut s = State::load(c)?;
    let e = s
        .requests
        .get(&id)
        .context("customer request not found")?
        .clone();
    ensure!(
        &e.binding == b,
        "customer request belongs to another account or endpoint"
    );
    if e.state != "unknown" {
        return Ok(json!({"request_id":id,"state":e.state,"data":e.response}));
    }
    use Request::*;
    let observed = match &e.request {
        CreateApiKey {
            id: key,
            api_key,
            settings,
        } => {
            let keys = read(c, &ApiKeys).await?;
            keys.as_array()
                .unwrap()
                .iter()
                .find(|v| {
                    v["id"] == key.to_string()
                        && api_key
                            .get(..12)
                            .is_some_and(|prefix| v["key_prefix"] == prefix)
                        && v["revoked_at"].is_null()
                        && settings.matches(v, true)
                })
                .cloned()
        }
        UpdateApiKey { id: key, settings } => {
            let keys = read(c, &ApiKeys).await?;
            keys.as_array()
                .unwrap()
                .iter()
                .find(|v| {
                    v["id"] == key.to_string()
                        && v["revoked_at"].is_null()
                        && settings.matches(v, false)
                })
                .cloned()
        }
        RevokeApiKey { id: key } => {
            let keys = read(c, &ApiKeys).await?;
            keys.as_array()
                .unwrap()
                .iter()
                .find(|v| v["id"] == key.to_string() && !v["revoked_at"].is_null())
                .cloned()
        }
        CreateOrg { id: org, name } => read(c, &Organizations)
            .await?
            .as_array()
            .unwrap()
            .iter()
            .find(|v| {
                v["organization"]["id"] == *org
                    && v["organization"]["name"] == *name
                    && v["organization"]["created_by_account_id"].as_str()
                        == b.account_id.as_deref()
            })
            .cloned(),
        Profile { display_name } => {
            let v = read(c, &Account).await?;
            (v["account"]["display_name"].as_str() == display_name.as_deref()).then_some(v)
        }
        UpdateMember { org, account, role } => {
            let v = read(c, &Members { org: org.clone() }).await?;
            v.as_array()
                .unwrap()
                .iter()
                .any(|v| v["account_id"] == *account && v["role"] == *role)
                .then(|| json!({"ok":true}))
        }
        RemoveMember { org, account } => {
            let v = read(c, &Members { org: org.clone() }).await?;
            (!v.as_array()
                .unwrap()
                .iter()
                .any(|v| v["account_id"] == *account))
            .then(|| json!({"ok":true}))
        }
        CreateInvite {
            org,
            id: invite,
            email,
            role,
            ..
        } => {
            let v = read(c, &Invites { org: org.clone() }).await?;
            v.as_array()
                .unwrap()
                .iter()
                .find(|v| {
                    v["id"] == *invite
                        && v["email"] == *email
                        && v["role"] == *role
                        && v["accepted_at"].is_null()
                        && v["invited_by_account_id"].as_str() == b.account_id.as_deref()
                        && v["expires_at"]
                            .as_str()
                            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                            .is_some_and(|d| d > chrono::Utc::now())
                })
                .map(|v| json!({"invite":v,"secret_status":"saved_before_submission"}))
        }
        RevokeInvite { org, id: invite } => {
            let v = read(c, &Invites { org: org.clone() }).await?;
            (!v.as_array().unwrap().iter().any(|v| v["id"] == *invite)).then(|| json!({"ok":true}))
        }
        // Neither a later referral code nor membership proves this submission committed.
        RotateReferral | AcceptInvite { .. } => None,
        _ => None,
    };
    if let Some(v) = observed {
        s.finish(c, id, "observed", Some(v.clone()))?;
        return Ok(
            json!({"request_id":id,"state":"observed","recovery":"current_state_observed_without_replaying","data":v}),
        );
    }
    Err(anyhow::Error::new(UnknownOutcome{request_id:id}).context(format!("customer request {id} remains unknown; no mutation was repeated. Inspect current account/organization state, then explicitly acknowledge the outcome if resolved")))
}
async fn acknowledge(c: &ControlClient, b: &ContextBinding, id: Uuid) -> Result<Value> {
    let mut s = State::load(c)?;
    ensure!(
        s.requests.get(&id).is_some_and(|e| &e.binding == b),
        "customer request belongs to another account or endpoint"
    );
    s.finish(c, id, "acknowledged", None)?;
    Ok(json!({"request_id":id,"state":"acknowledged"}))
}
pub async fn account(c: &ControlClient, cmd: Account, json_output: bool) -> Result<()> {
    if matches!(cmd, Account::Infrastructure) {
        return output::print(
            &json!({"context":"infrastructure","data":crate::account::account(c).await?}),
            json_output,
        );
    }
    if matches!(cmd, Account::Requests) {
        return output::print(&State::load(c)?.metadata(), json_output);
    }
    let value = match cmd {
        Account::Keys { command } => {
            return crate::account_keys::run(c, command, json_output).await
        }
        Account::Get => read(c, &Request::Account).await?,
        Account::Identities => read(c, &Request::Identities).await?,
        Account::Wallets => read(c, &Request::Wallets).await?,
        Account::Referrals => read(c, &Request::Referrals).await?,
        Account::Update { display_name, .. } => {
            mutate(
                c,
                &binding(c).await?,
                Request::Profile {
                    display_name: display_name
                        .map(|v| v.trim().to_owned())
                        .filter(|v| !v.is_empty()),
                },
            )
            .await?
        }
        Account::RotateReferral => mutate(c, &binding(c).await?, Request::RotateReferral).await?,
        Account::Resume { request_id } => resume(c, &binding(c).await?, request_id).await?,
        Account::Acknowledge { request_id } => {
            acknowledge(c, &binding(c).await?, request_id).await?
        }
        _ => unreachable!(),
    };
    output::print(&value, json_output)
}
fn read_token_file(path: &std::path::Path) -> Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).context("open invitation token file")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "invitation token must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "invitation token file must be private (chmod 600)"
        );
    }
    let mut text = String::new();
    file.take(4097).read_to_string(&mut text)?;
    ensure!(text.len() <= 4096, "invitation token file is too large");
    Ok(text)
}
pub async fn org(c: &ControlClient, cmd: Org, json_output: bool) -> Result<()> {
    let r = match cmd {
        Org::Audit { org, before } => {
            ensure!(
                org.starts_with("org_")
                    && org.len() <= 100
                    && org.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "invalid organization ID"
            );
            let mut path = format!("/v1/platform/organizations/{org}/audit");
            if let Some(before) = before {
                path.push_str(&format!("?before={before}"));
            }
            let value = c.get(&path).await?;
            platform::validate_response("platform.organization_audit", "200", &value)?;
            return output::print(&value, json_output);
        }
        Org::Requests => return output::print(&State::load(c)?.metadata(), json_output),
        Org::Resume { request_id } => {
            return output::print(
                &resume(c, &binding(c).await?, request_id).await?,
                json_output,
            )
        }
        Org::Acknowledge { request_id } => {
            return output::print(
                &acknowledge(c, &binding(c).await?, request_id).await?,
                json_output,
            )
        }
        Org::List => Request::Organizations,
        Org::Create { name } => Request::CreateOrg {
            id: format!("org_{}", Uuid::new_v4().simple()),
            name: name.trim().to_owned(),
        },
        Org::Members { org, command } => match command {
            Members::List => Request::Members { org },
            Members::Update { account, role } => Request::UpdateMember { org, account, role },
            Members::Delete { account } => Request::RemoveMember { org, account },
        },
        Org::Invites { org, command } => match command {
            Invites::List => Request::Invites { org },
            Invites::Revoke { id } => Request::RevokeInvite { org, id },
            Invites::Create { email, role } => {
                use base64::Engine;
                use rand::RngCore;
                let mut bytes = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                Request::CreateInvite {
                    org,
                    id: format!("invite_{}", Uuid::new_v4().simple()),
                    email: email.trim().to_lowercase(),
                    role,
                    accept_token: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
                }
            }
            Invites::Export { request_id } => {
                let b = binding(c).await?;
                let s = State::load(c)?;
                let e = s
                    .requests
                    .get(&request_id)
                    .context("saved invitation not found")?;
                ensure!(
                    e.binding == b,
                    "invitation belongs to another account or endpoint"
                );
                let Request::CreateInvite {
                    org: expected,
                    id,
                    accept_token,
                    ..
                } = &e.request
                else {
                    anyhow::bail!("request is not an invitation")
                };
                ensure!(
                    expected == &org,
                    "invitation belongs to another organization"
                );
                let live = read(c, &Request::Invites { org }).await?;
                ensure!(
                    live.as_array().unwrap().iter().any(|v| v["id"] == *id
                        && v["accepted_at"].is_null()
                        && v["expires_at"]
                            .as_str()
                            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                            .is_some_and(|d| d > chrono::Utc::now())),
                    "invitation is unavailable, accepted or expired"
                );
                return output::print_automation(
                    &json!({"request_id":request_id,"invitation_id":id,"secret":accept_token}),
                    json_output,
                );
            }
        },
        Org::Accept { token_file } => {
            let token = read_token_file(&token_file)?;
            Request::AcceptInvite {
                token: token.trim().to_owned(),
            }
        }
    };
    let value = if r.operation().1 == "GET" {
        read(c, &r).await?
    } else {
        mutate(c, &binding(c).await?, r).await?
    };
    output::print(&value, json_output)
}
fn history(p: Page) -> (History, bool) {
    let all = p.all;
    (
        History {
            limit: p.limit,
            cursor: p.cursor,
            created_at_from: p.from,
            created_at_to: p.to,
            search: p.search,
            ..History::default()
        },
        all,
    )
}
pub async fn billing(c: &ControlClient, cmd: Billing, json_output: bool) -> Result<()> {
    use crate::billing_workflows as flows;
    use pipe_api::billing::Request as Payment;
    let (mut r, all) = match cmd {
        Billing::Card { command } => return flows::card(c, command, json_output).await,
        Billing::Solana { command } => return flows::solana(c, command, json_output).await,
        Billing::Checkout { org, amount_cents } => {
            return flows::run(c, Payment::Checkout { org, amount_cents }, json_output).await
        }
        Billing::PlanCheckout { org, plan } => {
            return flows::run(c, Payment::PlanCheckout { org, plan }, json_output).await
        }
        Billing::Portal { org } => {
            return flows::run(c, Payment::Portal { org }, json_output).await
        }
        Billing::Settings {
            org,
            enabled,
            threshold_cents,
            amount_cents,
        } => {
            return flows::run(
                c,
                Payment::Settings {
                    org,
                    enabled,
                    threshold_cents,
                    amount_cents,
                },
                json_output,
            )
            .await
        }
        Billing::Requests => return flows::requests(c, json_output).await,
        Billing::Resume { request_id } => return flows::resume(c, request_id, json_output).await,
        Billing::Balance { org } => (Request::Balance { org }, false),
        Billing::Get { org } => (Request::Billing { org }, false),
        Billing::Invoices { org } => (Request::Invoices { org }, false),
        Billing::Subscriptions { org } => (Request::Subscriptions { org }, false),
        Billing::Ledger {
            org,
            page,
            entry_type,
        } => {
            let (mut h, all) = history(page);
            h.entry_type = entry_type;
            (Request::Ledger { org, history: h }, all)
        }
        Billing::Usage {
            org,
            page,
            model,
            project,
            group_by,
        } => {
            let (mut h, all) = history(page);
            h.model = model;
            h.project_id = project;
            h.group_by = group_by;
            (Request::Usage { org, history: h }, all)
        }
    };
    let mut pages = Vec::new();
    let mut seen = HashSet::new();
    let mut total_bytes = 0;
    let mut cursor: Option<String> = None;
    for n in 0..100 {
        let v = read(c, &r).await?;
        cursor = match &r {
            Request::Usage { .. } => v["next_cursor"].as_str().map(str::to_owned),
            Request::Ledger { history, .. } => v
                .as_array()
                .filter(|v| v.len() == history.limit as usize)
                .and_then(|v| v.last())
                .map(|v| {
                    format!(
                        "{}|{}",
                        v["created_at"].as_str().unwrap(),
                        v["id"].as_str().unwrap()
                    )
                }),
            _ => None,
        };
        let page = json!({"billing_system":"platform","units":{"balance":"billing_credit","billing_credit_usd":"0.04","usd_fields":"USD"},"data":v,"next_cursor":cursor,"page":n+1});
        if output::is_jsonl() {
            output::print_application(&page, json_output)?;
        } else {
            let bytes = serde_json::to_vec(&page)?.len();
            if !pages.is_empty() && total_bytes + bytes > 16 * 1024 * 1024 {
                // This read was not emitted. Resume at its input cursor, not after it.
                cursor = r.history().and_then(|h| h.cursor.clone());
                break;
            }
            total_bytes += bytes;
            pages.push(page);
        }
        if !all || cursor.is_none() || total_bytes >= 16 * 1024 * 1024 {
            break;
        }
        ensure!(
            seen.insert(cursor.clone()),
            "repeated history cursor; stop pagination"
        );
        match &mut r {
            Request::Ledger { history, .. } | Request::Usage { history, .. } => {
                history.cursor = cursor.clone()
            }
            _ => break,
        }
    }
    if output::is_jsonl() {
        Ok(())
    } else if pages.len() == 1 {
        output::print_application(&pages[0], json_output)
    } else {
        output::print_application(
            &json!({"pages":pages,"next_cursor":cursor,"truncated":cursor.is_some()}),
            json_output,
        )
    }
}
#[cfg(test)]
#[path = "customer_tests.rs"]
mod tests;

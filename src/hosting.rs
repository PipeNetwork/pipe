use crate::{
    auth::ControlClient,
    compute_journal::ContextBinding,
    error::ApiError,
    hosting_state::{self, Binding, Credential, Deployment, State},
    output, platform,
};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use pipe_api::hosting::Request;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
#[derive(Args, Debug, Clone, Default)]
pub struct Access {
    #[arg(long, env = "PIPE_HOSTING_CREDENTIAL")]
    credential: Option<Uuid>,
}
#[derive(Args, Debug, Clone)]
pub struct Target {
    #[command(flatten)]
    access: Access,
    #[arg(long)]
    request_id: Option<Uuid>,
    #[command(flatten)]
    wait: Wait,
}
#[derive(Args, Debug, Clone)]
pub struct Wait {
    #[arg(long)]
    wait: bool,
    #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=86400))]
    timeout: u64,
}
#[derive(Subcommand, Debug)]
pub enum Commands {
    Pricing,
    Account {
        #[command(subcommand)]
        command: Option<Account>,
    },
    Plans {
        #[command(subcommand)]
        command: Option<Plans>,
    },
    Billing {
        #[command(flatten)]
        access: Access,
    },
    Credentials {
        #[command(subcommand)]
        command: Keys,
    },
    Sites {
        #[command(subcommand)]
        command: Sites,
    },
    Releases {
        #[command(subcommand)]
        command: Releases,
    },
    Domains {
        #[command(subcommand)]
        command: Domains,
    },
    /// Upload a saved bundle, optionally migrate, then activate with an explicit expected release.
    Deploy {
        site: Uuid,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        expected_active: String,
        #[arg(long)]
        migrate: bool,
        #[command(flatten)]
        target: Target,
    },
    Requests,
    Resume {
        request_id: Uuid,
        #[command(flatten)]
        wait: Wait,
    },
    /// Record manual inspection; retain the uncertainty without resubmitting.
    Acknowledge {
        request_id: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum Account {
    Get,
    Register {
        #[arg(long)]
        wallet: String,
        #[command(flatten)]
        target: Target,
    },
}
#[derive(Subcommand, Debug)]
pub enum Plans {
    List,
    Purchase {
        plan: String,
        #[arg(long)]
        price_version: String,
        #[command(flatten)]
        target: Target,
    },
}
#[derive(Subcommand, Debug)]
pub enum Keys {
    List,
    Create {
        #[arg(long)]
        label: String,
        #[arg(long)]
        write: bool,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    Revoke {
        id: Uuid,
        #[command(flatten)]
        target: Target,
    },
    Import {
        id: Uuid,
        #[arg(long)]
        account: Uuid,
        #[arg(long)]
        secret_file: PathBuf,
    },
    Export {
        id: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum Sites {
    List {
        #[command(flatten)]
        access: Access,
    },
    Get {
        id: Uuid,
        #[command(flatten)]
        access: Access,
    },
    Create {
        #[arg(long)]
        slug: String,
        #[command(flatten)]
        target: Target,
    },
    Delete {
        id: Uuid,
        #[command(flatten)]
        target: Target,
    },
    Activate {
        id: Uuid,
        release: String,
        #[arg(long)]
        expected_active: String,
        #[command(flatten)]
        target: Target,
    },
    Deactivate {
        id: Uuid,
        #[arg(long)]
        expected_active: String,
        #[command(flatten)]
        target: Target,
    },
    Migrate {
        id: Uuid,
        release: String,
        #[arg(long)]
        expected_active: String,
        #[command(flatten)]
        target: Target,
    },
    Storage {
        id: Uuid,
        bytes: u64,
        #[command(flatten)]
        target: Target,
    },
    Logs {
        id: Uuid,
        #[command(flatten)]
        access: Access,
    },
}
#[derive(Subcommand, Debug)]
pub enum Releases {
    List {
        site: Uuid,
        #[command(flatten)]
        access: Access,
    },
    Upload {
        site: Uuid,
        bundle: PathBuf,
        #[command(flatten)]
        target: Target,
    },
    Delete {
        site: Uuid,
        release: String,
        #[command(flatten)]
        target: Target,
    },
}
#[derive(Subcommand, Debug)]
pub enum Domains {
    List {
        site: Uuid,
        #[command(flatten)]
        access: Access,
    },
    Create {
        site: Uuid,
        hostname: String,
        #[command(flatten)]
        target: Target,
    },
    Delete {
        site: Uuid,
        id: Uuid,
        #[command(flatten)]
        target: Target,
    },
    Verify {
        site: Uuid,
        id: Uuid,
        #[command(flatten)]
        target: Target,
    },
}
pub fn needs_confirmation(c: &Commands) -> bool {
    matches!(
        c,
        Commands::Plans {
            command: Some(Plans::Purchase { .. })
        } | Commands::Credentials {
            command: Keys::Create { .. } | Keys::Revoke { .. }
        } | Commands::Sites {
            command: Sites::Delete { .. }
                | Sites::Activate { .. }
                | Sites::Deactivate { .. }
                | Sites::Migrate { .. }
                | Sites::Storage { .. }
        } | Commands::Releases {
            command: Releases::Delete { .. }
        } | Commands::Domains {
            command: Domains::Delete { .. }
        } | Commands::Deploy { .. }
            | Commands::Resume { .. }
            | Commands::Acknowledge { .. }
    )
}
#[derive(Debug, thiserror::Error)]
#[error("hosting outcome unknown for request {id}; inspect pipe hosting requests and resume the original request; preserve its saved bundle and context")]
pub struct Unknown {
    pub id: Uuid,
}
#[derive(Debug, thiserror::Error)]
#[error("hosting wait deadline reached for request {id}; server work may continue; run pipe hosting resume {id} --wait --yes")]
pub struct Timeout {
    pub id: Uuid,
}
fn hash(v: &str) -> Result<()> {
    ensure!(
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected lowercase SHA-256 release ID"
    );
    Ok(())
}
fn expected(v: String) -> Result<Option<String>> {
    if v == "none" {
        Ok(None)
    } else {
        hash(&v)?;
        Ok(Some(v))
    }
}
fn file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut v = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut v)?;
    ensure!(v.len() <= limit, "input exceeds {limit} bytes");
    Ok(v)
}
fn valid_secret(s: &str) -> bool {
    s.starts_with("pipe_host_")
        && s.len() == 74
        && s[10..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
async fn binding(c: &ControlClient, a: &Access) -> Result<Binding> {
    if let Some(id) = a.credential {
        let s = State::load(c)?;
        let k = s
            .credentials
            .get(&id)
            .context("hosting credential is not saved")?;
        ensure!(
            k.endpoint == c.url(""),
            "credential belongs to another endpoint"
        );
        return Ok(Binding::Product {
            endpoint: k.endpoint.clone(),
            account: k.account,
            credential: id,
        });
    }
    let v = c.get("/v1/cli/context").await?;
    platform::validate_response("platformCliContext", "200", &v)?;
    Ok(Binding::Customer {
        context: ContextBinding {
            endpoint: c.url(""),
            owner_wallet: v["principal"]["owner_wallet"]
                .as_str()
                .context("missing owner")?
                .into(),
            account_id: v["principal"]["account_id"].as_str().map(str::to_owned),
        },
    })
}
async fn current_binding(c: &ControlClient, b: &Binding) -> Result<Binding> {
    let a = Access {
        credential: match b {
            Binding::Product { credential, .. } => Some(*credential),
            _ => None,
        },
    };
    let current = binding(c, &a).await?;
    ensure!(
        &current == b,
        "hosting request belongs to another account or credential"
    );
    Ok(current)
}
async fn send(
    c: &ControlClient,
    b: Option<&Binding>,
    method: &str,
    path: &str,
    body: Option<Vec<u8>>,
    zip: bool,
    id: Option<Uuid>,
) -> Result<(u16, Value)> {
    let product = if let Some(Binding::Product {
        credential,
        endpoint,
        account,
    }) = b
    {
        ensure!(
            endpoint == &c.url("") && path.starts_with("/v1/hosting/"),
            "product credential cannot access customer management"
        );
        let s = State::load(c)?;
        let k = s
            .credentials
            .get(credential)
            .context("missing hosting credential")?;
        ensure!(
            k.endpoint == *endpoint && k.account == *account && valid_secret(&k.secret),
            "credential binding differs"
        );
        Some(k.secret.clone())
    } else {
        None
    };
    for attempt in 0..2 {
        let mut request = if let Some(token) = &product {
            c.http
                .request(method.parse()?, c.url(path))
                .bearer_auth(token)
        } else {
            c.request(method.parse()?, path, None, true)?
        };
        if let Some(data) = &body {
            request = request
                .header(
                    "content-type",
                    if zip {
                        "application/zip"
                    } else {
                        "application/json"
                    },
                )
                .body(data.clone())
        }
        if let Some(id) = id {
            request = request.header("idempotency-key", id.to_string())
        }
        let response = request.send().await.map_err(|e| e.without_url())?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            && product.is_none()
            && attempt == 0
            && std::env::var_os("PIPE_CLI_TOKEN").is_none()
            && c.refresh().await.is_ok()
        {
            continue;
        }
        if !response.status().is_success() {
            return Err(crate::error::response_error(response).await);
        }
        let status = response.status().as_u16();
        let bytes = crate::error::bounded_body(response, 2 * 1024 * 1024).await?;
        return Ok((
            status,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes)?
            },
        ));
    }
    unreachable!()
}
fn response(op: &str, status: u16, v: &Value) -> Result<()> {
    let (_, _, spec) = platform::operation(op)?;
    let contract = &spec["responses"][status.to_string()];
    ensure!(!contract.is_null(), "unexpected hosting response status");
    if contract.get("content").is_none() {
        ensure!(v.is_null(), "expected an empty hosting response");
        Ok(())
    } else {
        platform::validate_response(op, &status.to_string(), v)
    }
}
async fn read(c: &ControlClient, b: Option<&Binding>, op: &str, path: &str) -> Result<Value> {
    let (status, v) = send(c, b, "GET", path, None, false, None).await?;
    response(op, status, &v)?;
    Ok(v)
}
fn request_body(c: &ControlClient, s: &State, r: &Request) -> Result<Option<Vec<u8>>> {
    if let Request::Upload { sha256, bytes, .. } = r {
        let data = hosting_state::bundle(c, sha256, None)?;
        ensure!(data.len() as u64 == *bytes, "saved bundle length differs");
        return Ok(Some(data.to_vec()));
    }
    let mut body = r.body();
    if let Request::CreateKey { id, .. } = r {
        body.as_mut().unwrap()["secret"] = json!(
            s.credentials
                .get(id)
                .context("credential was not saved")?
                .secret
        )
    }
    body.map(|v| serde_json::to_vec(&v).map_err(Into::into))
        .transpose()
}
fn validate(r: &Request, body: &Option<Vec<u8>>, b: &Binding) -> Result<()> {
    let (op, _, path) = r.operation();
    if matches!(b, Binding::Product { .. }) {
        ensure!(
            path.starts_with("/v1/hosting/"),
            "product keys cannot manage account, billing purchases or credentials"
        )
    }
    match r {
        Request::Upload { sha256, bytes, .. } => {
            hash(sha256)?;
            ensure!(
                *bytes > 0 && *bytes <= 32 * 1024 * 1024,
                "bundle size is outside the contract limit"
            );
        }
        Request::Migrate {
            release_id,
            expected_active,
            ..
        }
        | Request::Activate {
            release_id,
            expected_active,
            ..
        } => {
            hash(release_id)?;
            if let Some(v) = expected_active {
                hash(v)?
            }
        }
        Request::Deactivate {
            expected_active: Some(v),
            ..
        }
        | Request::DeleteRelease { release: v, .. } => hash(v)?,
        Request::CreateSite { slug } => ensure!(
            !slug.is_empty()
                && slug.len() <= 63
                && slug
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid site slug"
        ),
        _ => {}
    }
    if !matches!(r, Request::Upload { .. }) {
        if let Some(body) = body {
            ensure!(body.len() <= 64 * 1024, "hosting JSON exceeds 64 KiB");
            let (_, _, op) = platform::operation(op)?;
            platform::validate(
                &op["requestBody"]["content"]["application/json"]["schema"],
                &serde_json::from_slice(body)?,
            )?;
        }
    }
    Ok(())
}
// Observation never overwrites a later activation, allocation or domain decision.
async fn reconcile(c: &ControlClient, b: &Binding, r: &Request, id: Uuid) -> Result<Value> {
    let v = match r {
        Request::CreateSite { slug } => {
            let v = read(c, Some(b), "listHostingSites", "/v1/hosting/sites").await?;
            let site = v["sites"]
                .as_array()
                .context("missing sites")?
                .iter()
                .find(|s| s["slug"] == *slug)
                .context("site is not visible")?;
            json!({"site":site,"reconciled":true})
        }
        Request::Activate {
            site, release_id, ..
        } => {
            let v = read(
                c,
                Some(b),
                "getHostingSite",
                &format!("/v1/hosting/sites/{site}"),
            )
            .await?;
            ensure!(
                v["site"]["active_release"] == *release_id,
                "active release differs"
            );
            json!({"active_release":release_id,"reconciled":true})
        }
        Request::Deactivate { site, .. } => {
            let v = read(
                c,
                Some(b),
                "getHostingSite",
                &format!("/v1/hosting/sites/{site}"),
            )
            .await?;
            ensure!(v["site"]["active_release"].is_null(), "site is active");
            json!({"active_release":null,"reconciled":true})
        }
        Request::Allocate { site, bytes } => {
            let v = read(c, Some(b), "getHostingBilling", "/v1/hosting/billing").await?;
            ensure!(
                v["storage_allocations"]
                    .as_array()
                    .context("missing allocations")?
                    .iter()
                    .any(|v| v["site_id"] == site.to_string() && v["bytes"] == *bytes),
                "allocation differs"
            );
            json!({"bytes":bytes,"reconciled":true})
        }
        Request::CreateDomain { site, hostname } => {
            let v = read(
                c,
                Some(b),
                "listHostingDomains",
                &format!("/v1/hosting/sites/{site}/domains"),
            )
            .await?;
            let domain = v["domains"]
                .as_array()
                .context("missing domains")?
                .iter()
                .find(|v| v["hostname"] == *hostname)
                .context("domain is not visible")?;
            json!({"domain":domain,"reconciled":true})
        }
        Request::VerifyDomain { site, domain } => {
            let v = read(
                c,
                Some(b),
                "listHostingDomains",
                &format!("/v1/hosting/sites/{site}/domains"),
            )
            .await?;
            let domain = v["domains"]
                .as_array()
                .context("missing domains")?
                .iter()
                .find(|v| v["id"] == domain.to_string())
                .context("domain is not visible")?;
            ensure!(
                domain["verified_until"]
                    .as_i64()
                    .is_some_and(|v| v > chrono::Utc::now().timestamp()),
                "domain ownership is not verified"
            );
            json!({"hostname":domain["hostname"],"verified_until":domain["verified_until"],"reconciled":true})
        }
        Request::DeleteRelease { site, release } => {
            let v = read(
                c,
                Some(b),
                "listHostingReleases",
                &format!("/v1/hosting/sites/{site}/releases"),
            )
            .await?;
            ensure!(
                !v["releases"]
                    .as_array()
                    .context("missing releases")?
                    .iter()
                    .any(|v| v["id"] == *release),
                "release remains"
            );
            json!({"deleted":true,"reconciled":true})
        }
        Request::DeleteDomain { site, domain } => {
            let v = read(
                c,
                Some(b),
                "listHostingDomains",
                &format!("/v1/hosting/sites/{site}/domains"),
            )
            .await?;
            ensure!(
                !v["domains"]
                    .as_array()
                    .context("missing domains")?
                    .iter()
                    .any(|v| v["id"] == domain.to_string()),
                "domain remains"
            );
            json!({"deleted":true,"reconciled":true})
        }
        _ => return Err(Unknown { id }.into()),
    };
    Ok(v)
}
async fn submit(c: &ControlClient, b: &Binding, id: Uuid, r: Option<Request>) -> Result<Value> {
    let mut s = State::load(c)?;
    let fresh = if let Some(r) = r {
        let body = request_body(c, &s, &r)?;
        validate(&r, &body, b)?;
        s.prepare(c, id, b.clone(), r)?
    } else {
        false
    };
    let e = s
        .requests
        .get(&id)
        .context("hosting request not found")?
        .clone();
    ensure!(
        &e.binding == b,
        "hosting request belongs to another context"
    );
    ensure!(
        !matches!(e.state.as_str(), "rejected" | "acknowledged_unknown"),
        "hosting request was rejected or acknowledged; inspect before creating another"
    );
    if e.state == "accepted" {
        return e.response.context("missing saved receipt");
    }
    if !fresh && !e.request.replay_safe() {
        let v = reconcile(c, b, &e.request, id)
            .await
            .map_err(|_| Unknown { id })?;
        let receipt = json!({"request_id":id,"http_status":null,"pending":false,"response":v});
        s.finish(c, id, "accepted", Some(receipt.clone()))?;
        return Ok(receipt);
    }
    let r = &e.request;
    let body = request_body(c, &s, r)?;
    validate(r, &body, b)?;
    let (op, method, path) = r.operation();
    eprintln!("Hosting request {id} saved; recover with pipe hosting resume {id} --yes");
    let (status, mut v) = match send(
        c,
        Some(b),
        method,
        &path,
        body,
        matches!(r, Request::Upload { .. }),
        Some(id),
    )
    .await
    {
        Ok(v) => v,
        Err(error) => {
            // A successful prior deletion may have removed the ownership tombstone.
            if !fresh
                && matches!(r, Request::DeleteSite { .. })
                && error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|e| e.status.as_u16() == 404)
            {
                let v = json!({"deleted":true,"resource_absent":true,"cleanup_status":"not_observable"});
                s.finish(c, id, "accepted", Some(v.clone()))?;
                return Ok(v);
            }
            let definite = error.downcast_ref::<ApiError>().is_some_and(|e| {
                matches!(
                    e.status.as_u16(),
                    400 | 401 | 402 | 403 | 404 | 409 | 413 | 415 | 422 | 429
                ) && e.code != "idempotency_conflict"
            });
            if fresh && definite {
                s.finish(c, id, "rejected", None)?;
                return Err(error);
            }
            return Err(Unknown { id }.into());
        }
    };
    response(op, status, &v).map_err(|_| Unknown { id })?;
    let mut check = || -> Result<()> {
        if let Request::CreateKey { id, .. } = r {
            ensure!(
                v["id"] == id.to_string() && v["secret"] == s.credentials[id].secret,
                "credential receipt differs from saved material"
            );
            v.as_object_mut()
                .context("invalid credential response")?
                .remove("secret");
        }
        if let Request::Upload { sha256, site, .. } = r {
            ensure!(
                v["release_id"] == *sha256 && v["site_id"] == site.to_string(),
                "upload receipt differs from saved bundle"
            );
        }
        Ok(())
    };
    check().map_err(|_| Unknown { id })?;
    let pending = status == 202;
    if v.is_null() {
        v = json!({"deleted":true,"pending":pending,"cleanup_status":if pending{"pending"}else{"complete"}})
    }
    let result = json!({"request_id":id,"http_status":status,"pending":pending,"response":v});
    s.finish(
        c,
        id,
        if pending { "pending" } else { "accepted" },
        Some(result.clone()),
    )
    .map_err(|_| Unknown { id })?;
    Ok(result)
}
async fn waited(c: &ControlClient, b: &Binding, id: Uuid, mut v: Value, w: &Wait) -> Result<Value> {
    if !w.wait {
        return Ok(v);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(w.timeout);
    while v["pending"] == true {
        eprintln!("Hosting request {id} pending; server work continues");
        tokio::time::sleep(
            Duration::from_millis(500)
                .min(deadline.saturating_duration_since(tokio::time::Instant::now())),
        )
        .await;
        if tokio::time::Instant::now() >= deadline {
            return Err(Timeout { id }.into());
        }
        v = tokio::time::timeout_at(deadline, submit(c, b, id, None))
            .await
            .map_err(|_| Timeout { id })??;
    }
    Ok(v)
}
async fn manage(c: &ControlClient, r: Request, t: Target, j: bool) -> Result<()> {
    let b = binding(c, &t.access).await?;
    let id = t.request_id.unwrap_or_else(Uuid::new_v4);
    let v = submit(c, &b, id, Some(r)).await?;
    output::print(&waited(c, &b, id, v, &t.wait).await?, j)
}
async fn show(c: &ControlClient, a: Access, op: &str, path: String, j: bool) -> Result<()> {
    let b = binding(c, &a).await?;
    let v = read(c, Some(&b), op, &path).await?;
    output::print(&v, j)
}
fn save_bundle(c: &ControlClient, path: &Path) -> Result<(String, u64)> {
    let data = zeroize::Zeroizing::new(file(path, 32 * 1024 * 1024)?);
    ensure!(!data.is_empty(), "bundle is empty");
    let hash = crate::sigv4::sha256_hex(&data);
    hosting_state::bundle(c, &hash, Some(&data))?;
    Ok((hash, data.len() as u64))
}
fn deployment_unresolved(s: &State, d: &Deployment) -> bool {
    let steps = d
        .steps
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1 || d.migrate)
        .map(|(_, id)| s.requests.get(id))
        .collect::<Vec<_>>();
    if steps
        .iter()
        .flatten()
        .any(|e| matches!(e.state.as_str(), "rejected" | "acknowledged_unknown"))
    {
        return steps
            .iter()
            .flatten()
            .any(|e| matches!(e.state.as_str(), "unknown" | "pending"));
    }
    steps
        .iter()
        .any(|e| e.is_none_or(|e| e.state != "accepted"))
}
async fn deploy_with_deadline(
    c: &ControlClient,
    id: Uuid,
    d: Deployment,
    seconds: u64,
) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(seconds), deploy(c, id, d))
        .await
        .map_err(|_| Timeout { id })?
}
async fn deploy(c: &ControlClient, id: Uuid, d: Deployment) -> Result<Value> {
    let b = current_binding(c, &d.binding).await?;
    let upload = submit(
        c,
        &b,
        d.steps[0],
        Some(Request::Upload {
            site: d.site,
            sha256: d.sha256.clone(),
            bytes: d.bytes,
        }),
    )
    .await?;
    if d.migrate {
        submit(
            c,
            &b,
            d.steps[1],
            Some(Request::Migrate {
                site: d.site,
                release_id: d.sha256.clone(),
                expected_active: d.expected_active.clone(),
            }),
        )
        .await?;
    }
    let activate = submit(
        c,
        &b,
        d.steps[2],
        Some(Request::Activate {
            site: d.site,
            release_id: d.sha256.clone(),
            expected_active: d.expected_active,
        }),
    )
    .await?;
    Ok(
        json!({"deployment_id":id,"site_id":d.site,"release_id":d.sha256,"upload":upload,"activation":activate}),
    )
}
pub async fn run(c: &ControlClient, cmd: Commands, j: bool) -> Result<()> {
    match cmd {
        Commands::Pricing
        | Commands::Plans {
            command: None | Some(Plans::List),
        } => output::print(
            &read(c, None, "getHostingPricing", "/v1/hosting/pricing").await?,
            j,
        ),
        Commands::Account {
            command: None | Some(Account::Get),
        } => {
            let b = binding(c, &Access::default()).await?;
            output::print(
                &read(
                    c,
                    Some(&b),
                    "getHostingAccount",
                    "/v1/customer/hosting/account",
                )
                .await?,
                j,
            )
        }
        Commands::Account {
            command: Some(Account::Register { wallet, target }),
        } => {
            let raw = if wallet.len() == 64 && wallet.bytes().all(|v| v.is_ascii_hexdigit()) {
                hex::decode(wallet)?
            } else {
                bs58::decode(wallet).into_vec()?
            };
            ensure!(raw.len() == 32, "invalid credit wallet");
            manage(
                c,
                Request::Register {
                    wallet: hex::encode(raw),
                },
                target,
                j,
            )
            .await
        }
        Commands::Plans {
            command:
                Some(Plans::Purchase {
                    plan,
                    price_version,
                    target,
                }),
        } => {
            manage(
                c,
                Request::Purchase {
                    plan,
                    price_version,
                },
                target,
                j,
            )
            .await
        }
        Commands::Billing { access } => {
            show(
                c,
                access,
                "getHostingBilling",
                "/v1/hosting/billing".into(),
                j,
            )
            .await
        }
        Commands::Credentials {
            command: Keys::List,
        } => {
            let b = binding(c, &Access::default()).await?;
            let v = read(
                c,
                Some(&b),
                "getHostingAccount",
                "/v1/customer/hosting/account",
            )
            .await?;
            output::print(&v["credentials"], j)
        }
        Commands::Credentials {
            command:
                Keys::Create {
                    label,
                    write,
                    request_id,
                },
        } => {
            let b = binding(c, &Access::default()).await?;
            let v = read(
                c,
                Some(&b),
                "getHostingAccount",
                "/v1/customer/hosting/account",
            )
            .await?;
            let account = v["id"]
                .as_str()
                .context("missing hosting account")?
                .parse()?;
            let id = request_id.unwrap_or_else(Uuid::new_v4);
            let mut s = State::load(c)?;
            if let Some(k) = s.credentials.get(&id) {
                ensure!(
                    k.endpoint == c.url("") && k.account == account,
                    "credential belongs to another account"
                )
            } else {
                s.credentials.insert(
                    id,
                    Credential {
                        secret: format!("pipe_host_{}", hex::encode(rand::random::<[u8; 32]>())),
                        endpoint: c.url(""),
                        account,
                    },
                );
                s.save(c)?;
            }
            let v = submit(
                c,
                &b,
                id,
                Some(Request::CreateKey {
                    id,
                    label,
                    can_write: write,
                }),
            )
            .await?;
            output::print(&v, j)
        }
        Commands::Credentials {
            command: Keys::Revoke { id, target },
        } => manage(c, Request::RevokeKey { id }, target, j).await,
        Commands::Credentials {
            command:
                Keys::Import {
                    id,
                    account,
                    secret_file,
                },
        } => {
            let secret = String::from_utf8(file(&secret_file, 128)?)?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            ensure!(
                valid_secret(&secret),
                "expected pipe_host_ secret; other credentials are rejected"
            );
            let mut s = State::load(c)?;
            if let Some(k) = s.credentials.get(&id) {
                ensure!(
                    k.secret == secret && k.account == account && k.endpoint == c.url(""),
                    "credential already bound to another context"
                )
            } else {
                s.credentials.insert(
                    id,
                    Credential {
                        secret,
                        account,
                        endpoint: c.url(""),
                    },
                );
                s.save(c)?;
            }
            output::print(&json!({"id":id,"account":account,"saved":true}), j)
        }
        Commands::Credentials {
            command: Keys::Export { id },
        } => {
            let s = State::load(c)?;
            let k = s.credentials.get(&id).context("credential not saved")?;
            output::print_automation(
                &json!({"id":id,"account":k.account,"endpoint":k.endpoint,"secret":k.secret}),
                j,
            )
        }
        Commands::Sites { command } => match command {
            Sites::List { access } => {
                show(c, access, "listHostingSites", "/v1/hosting/sites".into(), j).await
            }
            Sites::Get { id, access } => {
                show(
                    c,
                    access,
                    "getHostingSite",
                    format!("/v1/hosting/sites/{id}"),
                    j,
                )
                .await
            }
            Sites::Logs { id, access } => {
                show(
                    c,
                    access,
                    "getHostingLogs",
                    format!("/v1/hosting/sites/{id}/logs"),
                    j,
                )
                .await
            }
            Sites::Create { slug, target } => {
                manage(c, Request::CreateSite { slug }, target, j).await
            }
            Sites::Delete { id, target } => {
                manage(c, Request::DeleteSite { site: id }, target, j).await
            }
            Sites::Activate {
                id,
                release,
                expected_active,
                target,
            } => {
                manage(
                    c,
                    Request::Activate {
                        site: id,
                        release_id: release,
                        expected_active: expected(expected_active)?,
                    },
                    target,
                    j,
                )
                .await
            }
            Sites::Migrate {
                id,
                release,
                expected_active,
                target,
            } => {
                manage(
                    c,
                    Request::Migrate {
                        site: id,
                        release_id: release,
                        expected_active: expected(expected_active)?,
                    },
                    target,
                    j,
                )
                .await
            }
            Sites::Deactivate {
                id,
                expected_active,
                target,
            } => {
                manage(
                    c,
                    Request::Deactivate {
                        site: id,
                        expected_active: expected(expected_active)?,
                    },
                    target,
                    j,
                )
                .await
            }
            Sites::Storage { id, bytes, target } => {
                manage(c, Request::Allocate { site: id, bytes }, target, j).await
            }
        },
        Commands::Releases { command } => match command {
            Releases::List { site, access } => {
                show(
                    c,
                    access,
                    "listHostingReleases",
                    format!("/v1/hosting/sites/{site}/releases"),
                    j,
                )
                .await
            }
            Releases::Upload {
                site,
                bundle,
                target,
            } => {
                let (hash, bytes) = save_bundle(c, &bundle)?;
                manage(
                    c,
                    Request::Upload {
                        site,
                        sha256: hash,
                        bytes,
                    },
                    target,
                    j,
                )
                .await
            }
            Releases::Delete {
                site,
                release,
                target,
            } => manage(c, Request::DeleteRelease { site, release }, target, j).await,
        },
        Commands::Domains { command } => match command {
            Domains::List { site, access } => {
                show(
                    c,
                    access,
                    "listHostingDomains",
                    format!("/v1/hosting/sites/{site}/domains"),
                    j,
                )
                .await
            }
            Domains::Create {
                site,
                hostname,
                target,
            } => {
                manage(
                    c,
                    Request::CreateDomain {
                        site,
                        hostname: hostname.trim_end_matches('.').to_ascii_lowercase(),
                    },
                    target,
                    j,
                )
                .await
            }
            Domains::Delete { site, id, target } => {
                manage(c, Request::DeleteDomain { site, domain: id }, target, j).await
            }
            Domains::Verify { site, id, target } => {
                manage(c, Request::VerifyDomain { site, domain: id }, target, j).await
            }
        },
        Commands::Deploy {
            site,
            bundle,
            expected_active,
            migrate,
            target,
        } => {
            let b = binding(c, &target.access).await?;
            let (hash, bytes) = save_bundle(c, &bundle)?;
            let id = target.request_id.unwrap_or_else(Uuid::new_v4);
            let expected = expected(expected_active)?;
            let mut s = State::load(c)?;
            let d = if let Some(old) = s.deployments.get(&id) {
                ensure!(
                    old.binding == b
                        && old.site == site
                        && old.sha256 == hash
                        && old.expected_active == expected
                        && old.migrate == migrate,
                    "deployment ID belongs to a different intent"
                );
                old.clone()
            } else {
                ensure!(
                    s.deployments.len() < 128,
                    "deployment journal limit reached"
                );
                ensure!(
                    !s.deployments
                        .values()
                        .any(|d| d.binding == b && d.site == site && deployment_unresolved(&s, d)),
                    "unresolved deployment for this site; resume its original ID"
                );
                let d = Deployment {
                    binding: b,
                    site,
                    sha256: hash,
                    bytes,
                    expected_active: expected,
                    migrate,
                    steps: [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
                };
                s.deployments.insert(id, d.clone());
                s.save(c)?;
                d
            };
            eprintln!("Deployment {id} saved; resume with pipe hosting resume {id} --yes");
            output::print(
                &deploy_with_deadline(c, id, d, target.wait.timeout).await?,
                j,
            )
        }
        Commands::Requests => output::print(&State::load(c)?.metadata(), j),
        Commands::Resume { request_id, wait } => {
            let s = State::load(c)?;
            if let Some(d) = s.deployments.get(&request_id) {
                return output::print(
                    &deploy_with_deadline(c, request_id, d.clone(), wait.timeout).await?,
                    j,
                );
            }
            let e = s
                .requests
                .get(&request_id)
                .context("hosting request not found")?;
            let b = current_binding(c, &e.binding).await?;
            let v = submit(c, &b, request_id, None).await?;
            output::print(&waited(c, &b, request_id, v, &wait).await?, j)
        }
        Commands::Acknowledge { request_id } => {
            let mut s = State::load(c)?;
            let e = s
                .requests
                .get(&request_id)
                .context("hosting request not found")?;
            current_binding(c, &e.binding).await?;
            ensure!(
                !e.request.replay_safe() && e.state == "unknown",
                "this request requires managed recovery"
            );
            s.finish(c, request_id, "acknowledged_unknown", None)?;
            output::print(
                &json!({"request_id":request_id,"state":"acknowledged_unknown","replayed":false}),
                j,
            )
        }
    }
}

#[cfg(test)]
#[path = "hosting_tests.rs"]
mod tests;

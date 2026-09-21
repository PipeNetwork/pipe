use crate::{
    auth::ControlClient,
    compute_journal::ContextBinding,
    durable_state::{Binding, Credential, State},
    error::ApiError,
    output, platform,
};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Subcommand};
use pipe_api::durable::{Action, Create, Execute, Operation, Request, Statement};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
#[derive(Args, Debug, Clone, Default)]
pub struct Wait {
    #[arg(long)]
    wait: bool,
    #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=86400))]
    timeout: u64,
}
#[derive(Args, Debug, Clone)]
pub struct Target {
    #[arg(long)]
    namespace: Uuid,
    #[arg(long)]
    object: String,
    /// Explicit product credential; otherwise use the current customer principal.
    #[arg(long)]
    credential: Option<Uuid>,
    #[arg(long)]
    request_id: Option<Uuid>,
    #[command(flatten)]
    wait: Wait,
}
#[derive(Subcommand, Debug)]
pub enum Commands {
    Pricing,
    Namespaces {
        #[command(subcommand)]
        command: Option<Namespaces>,
    },
    Credentials {
        #[command(subcommand)]
        command: Credentials,
    },
    Objects {
        namespace: Uuid,
    },
    Activity {
        namespace: Uuid,
    },
    Operation {
        id: Uuid,
        #[arg(long)]
        credential: Option<Uuid>,
        #[command(flatten)]
        wait: Wait,
        #[arg(long)]
        destination: Option<PathBuf>,
    },
    State {
        #[command(subcommand)]
        command: StateCommands,
    },
    Sql {
        #[arg(long)]
        statements_file: PathBuf,
        #[command(flatten)]
        target: Target,
    },
    Migrate {
        version: u64,
        #[arg(long)]
        statements_file: PathBuf,
        #[command(flatten)]
        target: Target,
    },
    Blobs {
        #[command(subcommand)]
        command: Blobs,
    },
    DeleteObject {
        #[command(flatten)]
        target: Target,
    },
    Requests,
    Resume {
        request_id: Uuid,
        #[command(flatten)]
        wait: Wait,
        #[arg(long)]
        destination: Option<PathBuf>,
    },
    /// Record inspection of an uncertain spending-limit update; never resubmit it.
    Acknowledge {
        request_id: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum Namespaces {
    List,
    Get {
        id: Uuid,
    },
    Create {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        price_version: String,
        #[arg(long)]
        spending_limit_atoms: String,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    Delete {
        id: Uuid,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    Limit {
        id: Uuid,
        #[arg(long)]
        spending_limit_atoms: String,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
}
#[derive(Subcommand, Debug)]
pub enum Credentials {
    List {
        namespace: Uuid,
    },
    Create {
        namespace: Uuid,
        #[arg(long)]
        label: String,
        #[arg(long)]
        write: bool,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    Revoke {
        id: Uuid,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    Import {
        id: Uuid,
        #[arg(long)]
        namespace: Uuid,
        #[arg(long)]
        secret_file: PathBuf,
    },
    Export {
        id: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum StateCommands {
    Put {
        key: String,
        #[arg(long)]
        value_file: PathBuf,
        #[command(flatten)]
        target: Target,
    },
    Get {
        key: String,
        #[command(flatten)]
        target: Target,
    },
    Delete {
        key: String,
        #[command(flatten)]
        target: Target,
    },
    List {
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, default_value = "")]
        after: String,
        #[arg(long)]
        all: bool,
        #[arg(long,default_value_t=100,value_parser=clap::value_parser!(u32).range(1..=1000))]
        max_pages: u32,
        #[command(flatten)]
        target: Target,
    },
}
#[derive(Subcommand, Debug)]
pub enum Blobs {
    Put {
        key: String,
        file: PathBuf,
        #[command(flatten)]
        target: Target,
    },
    Get {
        key: String,
        #[arg(long)]
        destination: Option<PathBuf>,
        #[command(flatten)]
        target: Target,
    },
    Delete {
        key: String,
        #[command(flatten)]
        target: Target,
    },
    List {
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, default_value = "")]
        after: String,
        #[arg(long)]
        all: bool,
        #[arg(long,default_value_t=100,value_parser=clap::value_parser!(u32).range(1..=1000))]
        max_pages: u32,
        #[command(flatten)]
        target: Target,
    },
}
pub fn needs_confirmation(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Namespaces {
            command: Some(
                Namespaces::Create { .. } | Namespaces::Delete { .. } | Namespaces::Limit { .. }
            )
        } | Commands::Credentials {
            command: Credentials::Create { .. } | Credentials::Revoke { .. }
        } | Commands::Resume { .. }
            | Commands::Acknowledge { .. }
            | Commands::DeleteObject { .. }
            | Commands::State {
                command: StateCommands::Delete { .. }
            }
            | Commands::Blobs {
                command: Blobs::Delete { .. }
            }
            | Commands::Migrate { .. }
    )
}
#[derive(Debug, thiserror::Error)]
#[error("Durable outcome unknown for request {id}; inspect pipe durable requests and run pipe durable resume {id}; preserve its original payload and key")]
pub struct Unknown {
    pub id: Uuid,
}
#[derive(Debug, thiserror::Error)]
#[error("deadline reached for Durable operation {id}; server work can continue; inspect pipe durable operation {id}")]
pub struct Timeout {
    pub id: Uuid,
}
#[derive(Debug, thiserror::Error)]
#[error("Durable operation {id} completed with application status {status}")]
pub struct ApplicationError {
    pub id: Uuid,
    pub status: u16,
}
#[derive(Debug, thiserror::Error)]
#[error("Durable operation {id} completed but its application result expired; do not create a replacement operation")]
pub struct Expired {
    pub id: Uuid,
}
async fn read(c: &ControlClient, id: &str, path: &str) -> Result<Value> {
    let v = c.get(path).await?;
    platform::validate_response(id, "200", &v)?;
    Ok(v)
}
async fn binding(
    c: &ControlClient,
    credential: Option<Uuid>,
    namespace: Option<Uuid>,
) -> Result<Binding> {
    if let Some(id) = credential {
        let s = State::load(c)?;
        let key = s
            .credentials
            .get(&id)
            .context("Durable credential is not saved in this profile")?;
        ensure!(
            key.endpoint == c.url("") && namespace.is_none_or(|v| v == key.namespace),
            "product credential belongs to another namespace or endpoint"
        );
        Ok(Binding::Product {
            endpoint: key.endpoint.clone(),
            namespace: key.namespace,
            credential: id,
        })
    } else {
        let v = read(c, "platformCliContext", "/v1/cli/context").await?;
        Ok(Binding::Customer {
            context: ContextBinding {
                endpoint: c.url(""),
                owner_wallet: v["principal"]["owner_wallet"]
                    .as_str()
                    .context("missing canonical identity")?
                    .into(),
                account_id: v["principal"]["account_id"].as_str().map(str::to_owned),
            },
        })
    }
}
fn valid_secret(s: &str) -> bool {
    s.starts_with("pido_") && s.len() == 69 && s[5..].bytes().all(|b| b.is_ascii_hexdigit())
}
async fn send(
    c: &ControlClient,
    b: &Binding,
    method: &str,
    path: &str,
    body: Option<Value>,
    id: Option<Uuid>,
) -> Result<Value> {
    if let Binding::Product {
        credential,
        endpoint,
        ..
    } = b
    {
        ensure!(endpoint == &c.url(""), "saved endpoint differs");
        ensure!(
            path.starts_with("/v1/durable/namespaces/")
                || path.starts_with("/v1/durable/requests/"),
            "product credentials cannot call customer management operations"
        );
        let s = State::load(c)?;
        let key = s
            .credentials
            .get(credential)
            .context("saved product credential is missing")?;
        ensure!(
            valid_secret(&key.secret),
            "invalid saved Durable credential"
        );
        let mut r = c
            .http
            .request(method.parse::<reqwest::Method>()?, c.url(path))
            .bearer_auth(&key.secret);
        if let Some(body) = body {
            r = r.json(&body);
        }
        if let Some(id) = id {
            r = r.header("idempotency-key", id.to_string());
        }
        let response = r.send().await.map_err(|e| e.without_url())?;
        if !response.status().is_success() {
            return Err(crate::error::response_error(response).await);
        }
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "unexpected Durable response status"
        );
        Ok(serde_json::from_slice(
            &crate::error::bounded_body(response, 128 * 1024).await?,
        )?)
    } else if method == "GET" {
        c.get(path).await
    } else {
        c.send_idempotent(
            method.parse()?,
            path,
            body.unwrap_or_else(|| json!({})),
            id.context("missing durable intent ID")?,
            reqwest::StatusCode::OK,
        )
        .await
    }
}
fn bytes(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut v = Vec::new();
    if path == Path::new("-") {
        std::io::stdin()
            .take(limit as u64 + 1)
            .read_to_end(&mut v)?;
    } else {
        std::fs::File::open(path)?
            .take(limit as u64 + 1)
            .read_to_end(&mut v)?;
    }
    ensure!(v.len() <= limit, "input exceeds {limit} bytes");
    Ok(v)
}
fn name(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        "invalid name: expected 1..{max} printable bytes"
    );
    Ok(())
}
fn atoms(value: &str) -> Result<()> {
    let n = value.parse::<u64>()?;
    ensure!(
        n.to_string() == value && (1..=1_000_000_000).contains(&n),
        "spending limit requires 1..1000000000 decimal USDC atoms"
    );
    Ok(())
}
fn validate(r: &Request, body: &Value, product: bool) -> Result<()> {
    let (id, method, _) = r.operation(product);
    if product {
        ensure!(
            matches!(r, Request::Execute { .. }),
            "product keys can only execute and inspect their own operations"
        );
    }
    if method == "POST" {
        let (_, _, op) = platform::operation(id)?;
        platform::validate(
            &op["requestBody"]["content"]["application/json"]["schema"],
            body,
        )?;
    }
    if let Request::Execute { body, .. } = r {
        name(&body.object, 128)?;
        ensure!(
            serde_json::to_vec(body)?.len() <= 64 * 1024,
            "Durable request exceeds 64 KiB"
        );
    }
    Ok(())
}
fn request_body(s: &State, request: &Request) -> Result<Value> {
    Ok(match request {
        Request::Create(r) => serde_json::to_value(r)?,
        Request::Limit {
            spending_limit_atoms,
            ..
        } => json!({"spending_limit_atoms":spending_limit_atoms}),
        Request::CreateKey {
            id,
            label,
            can_write,
            ..
        } => {
            let key = s
                .credentials
                .get(id)
                .context("credential material is missing; preserve recovery state")?;
            json!({"id":id,"label":label,"can_write":can_write,"secret":key.secret})
        }
        Request::Execute { body, .. } => serde_json::to_value(body)?,
        _ => json!({}),
    })
}
async fn submit(
    c: &ControlClient,
    request: Option<Request>,
    id: Uuid,
    b: Binding,
) -> Result<Value> {
    let mut s = State::load(c)?;
    let fresh = if let Some(r) = request {
        validate(
            &r,
            &request_body(&s, &r)?,
            matches!(b, Binding::Product { .. }),
        )?;
        s.prepare(c, id, b.clone(), r)?
    } else {
        false
    };
    let entry = s
        .requests
        .get(&id)
        .context("request is absent from this profile")?
        .clone();
    ensure!(
        entry.binding == b,
        "request belongs to another account, namespace or credential"
    );
    ensure!(
        entry.state != "rejected" && entry.state != "acknowledged_unknown",
        "request already rejected or acknowledged; inspect before a new submission"
    );
    if let Some(response) = entry.response {
        return Ok(response);
    }
    // Absolute financial settings do not have a server idempotency receipt. A lost
    // reply is reconciled by reading; replay could overwrite a later limit change.
    if !fresh {
        if let Request::Limit {
            namespace,
            spending_limit_atoms,
        } = &entry.request
        {
            let v = read(
                c,
                "listDurableNamespaces",
                "/v1/customer/durable/namespaces",
            )
            .await?;
            if v["namespaces"]
                .as_array()
                .context("missing namespaces")?
                .iter()
                .any(|v| {
                    v["id"] == namespace.to_string()
                        && v["spending_limit_atoms"] == *spending_limit_atoms
                })
            {
                let v = json!({"updated":true,"reconciled":true});
                s.finish(c, id, "accepted", Some(v.clone()))?;
                return Ok(v);
            }
            return Err(Unknown { id }.into());
        }
    }
    let product = matches!(b, Binding::Product { .. });
    let (operation, method, path) = entry.request.operation(product);
    let body = request_body(&s, &entry.request)?;
    validate(&entry.request, &body, product)?;
    eprintln!(
        "Durable request {id} saved before sending; recover with: pipe durable resume {id} --yes"
    );
    let mut response = match send(c, &b, method, &path, Some(body), Some(id)).await {
        Ok(v) => v,
        Err(e) => {
            if e.downcast_ref::<ApiError>().is_some_and(|e| {
                matches!(e.status.as_u16(), 400 | 401 | 402 | 403 | 404 | 422)
                    || (e.status.as_u16() == 409 && e.code != "idempotency_conflict")
            }) {
                s.finish(c, id, "rejected", None)?;
                return Err(e);
            }
            return Err(Unknown { id }.into());
        }
    };
    let check = || -> Result<()> {
        platform::validate_response(operation, "200", &response)?;
        match &entry.request {
            Request::Create(_) => {
                Uuid::parse_str(response["id"].as_str().context("missing namespace ID")?)?;
            }
            Request::CreateKey { id, .. } => ensure!(
                response["id"] == id.to_string() && response["secret"] == s.credentials[id].secret,
                "credential receipt differs from saved material"
            ),
            Request::Execute { .. } => {
                let op: Operation = serde_json::from_value(response.clone())?;
                ensure!(
                    op.status == "pending" || op.status == "complete",
                    "invalid operation state"
                );
            }
            Request::Limit { .. } => {
                ensure!(response["updated"] == true, "limit update not accepted")
            }
            Request::Revoke { .. } | Request::RevokeKey { .. } => {
                ensure!(response["revoked"] == true, "revocation not accepted")
            }
        }
        Ok(())
    };
    check().map_err(|_| Unknown { id })?;
    if let Some(object) = response.as_object_mut() {
        object.remove("secret");
    }
    s.finish(c, id, "accepted", Some(response.clone()))
        .map_err(|_| Unknown { id })?;
    Ok(response)
}
async fn poll(
    c: &ControlClient,
    b: &Binding,
    id: Uuid,
    mut value: Option<Value>,
    wait: &Wait,
) -> Result<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait.timeout);
    loop {
        let current = if let Some(v) = value.take() {
            v
        } else {
            let (operation, path) = if matches!(b, Binding::Product { .. }) {
                ("getDurableOperation", format!("/v1/durable/requests/{id}"))
            } else {
                (
                    "getCustomerDurableOperation",
                    format!("/v1/customer/durable/requests/{id}"),
                )
            };
            let fetch = send(c, b, "GET", &path, None, None);
            let v = if wait.wait {
                tokio::time::timeout_at(deadline, fetch)
                    .await
                    .map_err(|_| Timeout { id })??
            } else {
                fetch.await?
            };
            platform::validate_response(operation, "200", &v)?;
            v
        };
        let op: Operation = serde_json::from_value(current.clone())?;
        ensure!(op.operation_id == id, "operation identity changed");
        if op.status == "complete" || !wait.wait {
            return Ok(current);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Timeout { id }.into());
        }
        eprintln!("Durable operation {id} pending; server work continues");
        tokio::time::sleep(
            Duration::from_secs(1)
                .min(deadline.saturating_duration_since(tokio::time::Instant::now())),
        )
        .await;
    }
}
async fn finish(
    c: &ControlClient,
    b: &Binding,
    id: Uuid,
    value: Value,
    wait: Wait,
) -> Result<Value> {
    if value.get("operation_id").is_none() {
        return Ok(value);
    }
    let operation = Uuid::parse_str(
        value["operation_id"]
            .as_str()
            .context("invalid operation ID")?,
    )?;
    let v = poll(c, b, operation, Some(value), &wait).await?;
    let mut s = State::load(c)?;
    s.finish(c, id, "accepted", Some(v.clone()))?;
    Ok(v)
}
pub(crate) fn present(v: Value, destination: Option<PathBuf>, j: bool) -> Result<()> {
    let op = v
        .get("operation_id")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok());
    let status = v["response"]["status"].as_u64().map(|v| v as u16);
    if v["response_expired"] == true {
        let id = op.context("expired response lacks operation ID")?;
        output::print_application(
            &json!({"operation":v,"error":{"code":"response_expired","operation_id":id}}),
            j,
        )?;
        return Err(Expired { id }.into());
    }

    if let Some(path) = destination {
        ensure!(
            v["status"] == "complete" && !v["response_expired"].as_bool().unwrap_or(true),
            "blob is pending or its response expired; no file written"
        );
        ensure!(
            status.is_some_and(|s| (200..300).contains(&s)),
            "blob operation failed; no file written"
        );
        let encoded = v["response"]["result"]["data_base64"]
            .as_str()
            .context("blob not found or response is not blob data")?;
        let data = STANDARD.decode(encoded)?;
        ensure!(data.len() <= 64 * 1024, "blob response exceeds limit");
        use std::io::Write;
        let parent = path
            .parent()
            .filter(|v| !v.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut f = tempfile::NamedTempFile::new_in(parent)?;
        f.write_all(&data)?;
        f.as_file().sync_all()?;
        f.persist_noclobber(&path)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        return output::print(
            &json!({"operation_id":op,"destination":path,"bytes":data.len()}),
            j,
        );
    }
    if let (Some(id), Some(status)) = (op, status) {
        if !(200..300).contains(&status) {
            output::print_application(
                &json!({"operation":v,"error":{"code":"application_error","operation_id":id,"status":status}}),
                j,
            )?;
            return Err(ApplicationError { id, status }.into());
        }
    }
    output::print_application(&v, j)?;
    Ok(())
}
async fn action(
    c: &ControlClient,
    mut target: Target,
    action: Action,
    destination: Option<PathBuf>,
    j: bool,
) -> Result<()> {
    if let Some(p) = &destination {
        ensure!(!p.exists(), "download destination already exists");
        target.wait.wait = true;
    }
    let b = binding(c, target.credential, Some(target.namespace)).await?;
    let id = target.request_id.unwrap_or_else(Uuid::new_v4);
    let r = Request::Execute {
        namespace: target.namespace,
        body: Execute {
            object: target.object,
            action,
        },
    };
    let v = submit(c, Some(r), id, b.clone()).await?;
    let v = finish(c, &b, id, v, target.wait).await?;
    present(v, destination, j)
}
async fn manage(c: &ControlClient, r: Request, id: Option<Uuid>, j: bool) -> Result<()> {
    let b = binding(c, None, None).await?;
    let id = id.unwrap_or_else(Uuid::new_v4);
    let response = submit(c, Some(r), id, b).await?;
    output::print(&json!({"request_id":id,"response":response}), j)
}
async fn namespaces(c: &ControlClient) -> Result<Value> {
    read(
        c,
        "listDurableNamespaces",
        "/v1/customer/durable/namespaces",
    )
    .await
}
fn ns(v: &Value, id: Uuid) -> Result<&Value> {
    v["namespaces"]
        .as_array()
        .context("missing namespaces")?
        .iter()
        .find(|v| v["id"] == id.to_string())
        .context("owned namespace not found")
}
pub async fn run(c: &ControlClient, command: Commands, j: bool) -> Result<()> {
    match command {
        Commands::Pricing => output::print(
            &read(c, "getDurablePricing", "/v1/durable/pricing").await?,
            j,
        ),
        Commands::Namespaces {
            command: None | Some(Namespaces::List),
        } => output::print(&namespaces(c).await?, j),
        Commands::Namespaces {
            command: Some(Namespaces::Get { id }),
        } => output::print(ns(&namespaces(c).await?, id)?, j),
        Commands::Namespaces {
            command:
                Some(Namespaces::Create {
                    wallet,
                    name: n,
                    price_version,
                    spending_limit_atoms,
                    request_id,
                }),
        } => {
            name(&n, 64)?;
            atoms(&spending_limit_atoms)?;
            let w = if wallet.len() == 64 && wallet.bytes().all(|b| b.is_ascii_hexdigit()) {
                hex::decode(wallet)?
            } else {
                bs58::decode(wallet).into_vec()?
            };
            ensure!(w.len() == 32, "invalid wallet public key");
            manage(
                c,
                Request::Create(Create {
                    wallet: hex::encode(w),
                    name: n,
                    price_version,
                    spending_limit_atoms,
                }),
                request_id,
                j,
            )
            .await
        }
        Commands::Namespaces {
            command: Some(Namespaces::Delete { id, request_id }),
        } => manage(c, Request::Revoke { namespace: id }, request_id, j).await,
        Commands::Namespaces {
            command:
                Some(Namespaces::Limit {
                    id,
                    spending_limit_atoms,
                    request_id,
                }),
        } => {
            atoms(&spending_limit_atoms)?;
            manage(
                c,
                Request::Limit {
                    namespace: id,
                    spending_limit_atoms,
                },
                request_id,
                j,
            )
            .await
        }
        Commands::Credentials {
            command: Credentials::List { namespace },
        } => output::print(&ns(&namespaces(c).await?, namespace)?["credentials"], j),
        Commands::Credentials {
            command:
                Credentials::Create {
                    namespace,
                    label,
                    write,
                    request_id,
                },
        } => {
            name(&label, 64)?;
            let id = request_id.unwrap_or_else(Uuid::new_v4);
            let mut s = State::load(c)?;
            if let Some(old) = s.credentials.get(&id) {
                ensure!(
                    old.namespace == namespace && old.endpoint == c.url(""),
                    "credential ID belongs to another context"
                );
            } else {
                s.credentials.insert(
                    id,
                    Credential {
                        namespace,
                        endpoint: c.url(""),
                        secret: format!("pido_{}", hex::encode(rand::random::<[u8; 32]>())),
                    },
                );
                s.save(c)?;
            }
            manage(
                c,
                Request::CreateKey {
                    namespace,
                    id,
                    label,
                    can_write: write,
                },
                Some(id),
                j,
            )
            .await
        }
        Commands::Credentials {
            command: Credentials::Revoke { id, request_id },
        } => manage(c, Request::RevokeKey { id }, request_id, j).await,
        Commands::Credentials {
            command:
                Credentials::Import {
                    id,
                    namespace,
                    secret_file,
                },
        } => {
            let secret = String::from_utf8(bytes(&secret_file, 128)?)?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            ensure!(
                valid_secret(&secret),
                "expected a pido_ Durable key; other credential types are not accepted"
            );
            let mut s = State::load(c)?;
            if let Some(old) = s.credentials.get(&id) {
                ensure!(
                    old.namespace == namespace && old.endpoint == c.url("") && old.secret == secret,
                    "credential already bound to other material"
                );
            } else {
                s.credentials.insert(
                    id,
                    Credential {
                        namespace,
                        endpoint: c.url(""),
                        secret,
                    },
                );
                s.save(c)?;
            }
            output::print(&json!({"id":id,"namespace":namespace,"saved":true}), j)
        }
        Commands::Credentials {
            command: Credentials::Export { id },
        } => {
            let s = State::load(c)?;
            let key = s.credentials.get(&id).context("credential not saved")?;
            output::print_automation(
                &json!({"id":id,"namespace":key.namespace,"secret":key.secret,"endpoint":key.endpoint}),
                j,
            )
        }
        Commands::Objects { namespace } => output::print(
            &read(
                c,
                "listDurableObjects",
                &format!("/v1/customer/durable/namespaces/{namespace}/objects"),
            )
            .await?,
            j,
        ),
        Commands::Activity { namespace } => output::print(
            &read(
                c,
                "getDurableActivity",
                &format!("/v1/customer/durable/namespaces/{namespace}/activity"),
            )
            .await?,
            j,
        ),
        Commands::Operation {
            id,
            credential,
            mut wait,
            destination,
        } => {
            if let Some(p) = &destination {
                ensure!(!p.exists(), "destination already exists");
                wait.wait = true;
            }
            let b = binding(c, credential, None).await?;
            present(poll(c, &b, id, None, &wait).await?, destination, j)
        }
        Commands::State { command } => match command {
            StateCommands::Put {
                key,
                value_file,
                target,
            } => {
                action(
                    c,
                    target,
                    Action::PutState {
                        key,
                        value: serde_json::from_slice(&bytes(&value_file, 64 * 1024)?)?,
                    },
                    None,
                    j,
                )
                .await
            }
            StateCommands::Get { key, target } => {
                action(c, target, Action::GetState { key }, None, j).await
            }
            StateCommands::Delete { key, target } => {
                action(c, target, Action::DeleteState { key }, None, j).await
            }
            StateCommands::List {
                prefix,
                after,
                all,
                max_pages,
                target,
            } => pages(c, target, false, prefix, after, all, max_pages, j).await,
        },
        Commands::Sql {
            statements_file,
            target,
        } => {
            let statements: Vec<Statement> =
                serde_json::from_slice(&bytes(&statements_file, 64 * 1024)?)?;
            action(c, target, Action::Sql { statements }, None, j).await
        }
        Commands::Migrate {
            version,
            statements_file,
            target,
        } => {
            let statements: Vec<String> =
                serde_json::from_slice(&bytes(&statements_file, 64 * 1024)?)?;
            action(
                c,
                target,
                Action::Migrate {
                    version,
                    statements,
                },
                None,
                j,
            )
            .await
        }
        Commands::Blobs { command } => match command {
            Blobs::Put { key, file, target } => {
                action(
                    c,
                    target,
                    Action::PutBlob {
                        key,
                        data_base64: STANDARD.encode(bytes(&file, 48 * 1024)?),
                    },
                    None,
                    j,
                )
                .await
            }
            Blobs::Get {
                key,
                destination,
                target,
            } => action(c, target, Action::GetBlob { key }, destination, j).await,
            Blobs::Delete { key, target } => {
                action(c, target, Action::DeleteBlob { key }, None, j).await
            }
            Blobs::List {
                prefix,
                after,
                all,
                max_pages,
                target,
            } => pages(c, target, true, prefix, after, all, max_pages, j).await,
        },
        Commands::DeleteObject { target } => action(c, target, Action::DeleteObject, None, j).await,
        Commands::Requests => output::print(&State::load(c)?.metadata(), j),
        Commands::Resume {
            request_id,
            mut wait,
            destination,
        } => {
            if let Some(p) = &destination {
                ensure!(!p.exists(), "destination already exists");
                wait.wait = true;
            }
            let s = State::load(c)?;
            let e = s.requests.get(&request_id).context("request not found")?;
            let b = match e.binding {
                Binding::Customer { .. } => binding(c, None, None).await?,
                Binding::Product {
                    namespace,
                    credential,
                    ..
                } => binding(c, Some(credential), Some(namespace)).await?,
            };
            let v = submit(c, None, request_id, b.clone()).await?;
            present(finish(c, &b, request_id, v, wait).await?, destination, j)
        }
        Commands::Acknowledge { request_id } => {
            let mut s = State::load(c)?;
            ensure!(matches!(s.requests.get(&request_id).context("request not found")?.request,Request::Limit{..}),"only uncertain limit updates require manual acknowledgement; resume other operations");
            s.finish(c, request_id, "acknowledged_unknown", None)?;
            output::print(
                &json!({"request_id":request_id,"state":"acknowledged_unknown","replayed":false}),
                j,
            )
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn pages(
    c: &ControlClient,
    mut target: Target,
    blobs: bool,
    prefix: String,
    mut after: String,
    all: bool,
    max: u32,
    j: bool,
) -> Result<()> {
    if !all {
        return action(
            c,
            target,
            if blobs {
                Action::ListBlobs { prefix, after }
            } else {
                Action::ListState { prefix, after }
            },
            None,
            j,
        )
        .await;
    }
    ensure!(
        target.request_id.is_none(),
        "--all creates separately journaled page requests; use a single page with --request-id"
    );
    target.wait.wait = true;
    let b = binding(c, target.credential, Some(target.namespace)).await?;
    let mut seen = std::collections::HashSet::new();
    let mut pages = Vec::new();
    let mut total = 0;
    let mut complete = false;
    for _ in 0..max {
        ensure!(
            seen.insert(after.clone()),
            "server repeated a Durable cursor"
        );
        let id = Uuid::new_v4();
        let action = if blobs {
            Action::ListBlobs {
                prefix: prefix.clone(),
                after: after.clone(),
            }
        } else {
            Action::ListState {
                prefix: prefix.clone(),
                after: after.clone(),
            }
        };
        let v = submit(
            c,
            Some(Request::Execute {
                namespace: target.namespace,
                body: Execute {
                    object: target.object.clone(),
                    action,
                },
            }),
            id,
            b.clone(),
        )
        .await?;
        let v = finish(c, &b, id, v, target.wait.clone()).await?;
        let op: Operation = serde_json::from_value(v.clone())?;
        if op.response_expired {
            return present(v, None, j);
        }
        let response = op
            .response
            .context("completed operation lacks its application response")?;
        if !(200..300).contains(&response.status) {
            return present(v, None, j);
        }
        let next = response.result["cursor"].as_str().map(str::to_owned);
        complete = next.is_none();
        if output::is_jsonl() {
            output::print_application(&v, j)?;
        } else {
            total += serde_json::to_vec(&v)?.len();
            ensure!(
                total <= 16 * 1024 * 1024,
                "page output limit reached; use JSONL"
            );
            pages.push(v);
        }
        if let Some(next) = next {
            after = next;
        } else {
            break;
        }
    }
    if !output::is_jsonl() {
        output::print_application(
            &json!({"pages":pages,"complete":complete,"cursor":if complete{None}else{Some(after)}}),
            j,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "durable_tests.rs"]
mod tests;

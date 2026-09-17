use crate::{
    auth::ControlClient,
    compute_journal::{ContextBinding, Journal},
    error::{ApiError, UnknownOutcome, WaitTimeout},
    output, platform,
};
use anyhow::{anyhow, ensure, Context, Result};
use clap::{Args, Subcommand};
use pipe_api::compute::{Action, Billing, CreateVm, Mutation, Operation, Request};
use serde_json::{json, Value};
use std::{collections::HashSet, path::PathBuf, time::Duration};
use uuid::Uuid;

#[derive(Args, Debug, Clone, Default)]
pub struct Wait {
    /// Wait for completion; reaching the deadline does not cancel server work.
    #[arg(long)]
    pub wait: bool,
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
    pub timeout: u64,
}
#[derive(Args, Debug)]
pub struct Submit {
    /// Reuse only with the identical request and account context.
    #[arg(long)]
    pub request_id: Option<Uuid>,
    #[command(flatten)]
    pub wait: Wait,
}
#[derive(Subcommand, Debug)]
pub enum Commands {
    Projects,
    Images,
    Flavors,
    Pricing,
    #[command(alias = "vm")]
    Vms {
        #[command(subcommand)]
        command: Vms,
    },
    #[command(alias = "operation")]
    Operations {
        id: Uuid,
        #[command(flatten)]
        wait: Wait,
    },
    Usage {
        id: Uuid,
    },
    /// Connect using verified API host identity and the installed OpenSSH client.
    Ssh {
        id: Uuid,
        #[arg(long)]
        identity_file: Option<PathBuf>,
        /// Command interpreted by the remote SSH server; never a local shell.
        #[arg(long)]
        command: Option<String>,
    },
    /// List preserved requests, including unresolved submissions.
    Requests,
    /// Reconcile a saved request using its original idempotency key and body.
    Resume {
        request_id: Uuid,
        #[command(flatten)]
        wait: Wait,
    },
}
#[derive(Subcommand, Debug)]
pub enum Vms {
    List {
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
        #[arg(long)]
        cursor: Option<Uuid>,
        /// Follow up to 1000 pages, detecting repeated cursors.
        #[arg(long)]
        all: bool,
    },
    Get {
        id: Uuid,
    },
    Create {
        #[arg(long)]
        project: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long)]
        image: String,
        #[arg(long)]
        flavor: String,
        #[arg(long, required = true)]
        ssh_key: Vec<PathBuf>,
        #[arg(long)]
        price_version: Option<String>,
        #[arg(long, action=clap::ArgAction::Set)]
        auto_renew: Option<bool>,
        #[command(flatten)]
        submit: Submit,
    },
    Start {
        id: Uuid,
        #[command(flatten)]
        submit: Submit,
    },
    Stop {
        id: Uuid,
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        submit: Submit,
    },
    Reboot {
        id: Uuid,
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        submit: Submit,
    },
    Delete {
        id: Uuid,
        #[command(flatten)]
        submit: Submit,
    },
    Billing {
        id: Uuid,
        #[arg(long, required=true, action=clap::ArgAction::Set)]
        auto_renew: bool,
        #[arg(long)]
        renew: bool,
        #[arg(long)]
        price_version: String,
        #[command(flatten)]
        submit: Submit,
    },
}

pub fn needs_confirmation(cmd: &Commands) -> bool {
    matches!(
        cmd,
        Commands::Resume { .. }
            | Commands::Vms {
                command: Vms::Create { .. }
                    | Vms::Stop { .. }
                    | Vms::Reboot { .. }
                    | Vms::Delete { .. }
                    | Vms::Billing { .. }
            }
    )
}
fn validate_request(r: &Request) -> Result<()> {
    let (template, method, op) = platform::operation(&r.operation_id)?;
    ensure!(
        matches!(
            r.operation_id.as_str(),
            "createComputeVm"
                | "startComputeVm"
                | "stopComputeVm"
                | "rebootComputeVm"
                | "deleteComputeVm"
                | "updateComputeBilling"
        ),
        "operation has no managed compute workflow"
    );
    ensure!(
        r.method.eq_ignore_ascii_case(method),
        "saved method differs from pinned operation"
    );
    let expected = if let Some((start, end)) = template.split_once("{id}") {
        let id = r
            .path
            .strip_prefix(start)
            .and_then(|v| v.strip_suffix(end))
            .context("invalid saved compute path")?;
        format!("{start}{}{end}", Uuid::parse_str(id)?)
    } else {
        template.to_owned()
    };
    ensure!(
        r.path == expected,
        "saved request destination differs from pinned operation"
    );
    platform::validate(
        &op["requestBody"]["content"]["application/json"]["schema"],
        &r.body,
    )
}
async fn context(c: &ControlClient) -> Result<ContextBinding> {
    let value = c.get("/v1/cli/context").await?;
    platform::validate_response("platformCliContext", "200", &value)?;
    Ok(ContextBinding {
        endpoint: c.url(""),
        owner_wallet: value["principal"]["owner_wallet"]
            .as_str()
            .context("missing owner context")?
            .into(),
        account_id: value["principal"]["account_id"].as_str().map(str::to_owned),
    })
}
async fn submit(
    c: &ControlClient,
    r: Option<Request>,
    id: Option<Uuid>,
    wait: Wait,
    j: bool,
) -> Result<()> {
    if let Some(r) = &r {
        validate_request(r)?;
    }
    let binding = context(c).await?;
    let mut journal = Journal::open(c)?;
    let id = if let Some(r) = r {
        journal.prepare(binding.clone(), r, id)?
    } else {
        id.context("missing request ID")?
    };
    let entry = journal.get(id)?.clone();
    ensure!(
        entry.context == binding,
        "request belongs to another account or endpoint; restore its original context"
    );
    validate_request(&entry.request)?;
    ensure!(
        entry.state != "rejected",
        "request was rejected before execution; use a new request ID after correcting its cause"
    );
    eprintln!("Compute request {id} saved. Recover with: pipe compute resume {id} --yes");
    let response = if let Some(response) = entry.response {
        response
    } else {
        let request = &entry.request;
        let status = if request.operation_id == "updateComputeBilling" {
            reqwest::StatusCode::OK
        } else {
            reqwest::StatusCode::ACCEPTED
        };
        let sent = c
            .send_idempotent(
                request.method.parse()?,
                &request.path,
                request.body.clone(),
                id,
                status,
            )
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(e) => {
                if e.downcast_ref::<ApiError>().is_some_and(|e| {
                    matches!(e.status.as_u16(), 400 | 401 | 402 | 403 | 404 | 412 | 422)
                        || (e.status.as_u16() == 409
                            && matches!(
                                e.code.as_str(),
                                "price_changed"
                                    | "vm_limit_reached"
                                    | "operation_in_progress"
                                    | "vm_deleted"
                            ))
                }) {
                    journal.rejected(id)?;
                    return Err(e);
                }
                return Err(UnknownOutcome { request_id: id }.into());
            }
        };
        platform::validate_response(&request.operation_id, status.as_str(), &response)
            .map_err(|_| UnknownOutcome { request_id: id })?;
        if request.operation_id != "createComputeVm" {
            let vm = request
                .path
                .strip_prefix("/v1/compute/vms/")
                .and_then(|s| s.split('/').next())
                .context("invalid prepared VM path")?;
            // Billing's response request_id is a server-generated receipt ID,
            // distinct from this journal's Idempotency-Key.
            if response["vm_id"] != vm {
                return Err(UnknownOutcome { request_id: id }.into());
            }
        }
        journal.accepted(id, response.clone())?;
        response
    };
    let mut result = json!({"request_id":id,"acceptance":response});
    if entry.request.operation_id != "updateComputeBilling" {
        let mutation: Mutation = serde_json::from_value(response)?;
        eprintln!(
            "VM {} operation {} accepted.",
            mutation.vm_id, mutation.operation_id
        );
        if wait.wait {
            if output::is_jsonl() {
                output::print(&result, j)?;
            }
            result["operation"] = wait_operation(
                c,
                mutation.operation_id,
                Some((mutation.vm_id, mutation.generation)),
                wait.timeout,
                j,
            )
            .await?;
        }
    }
    output::print(&result, j)
}
async fn wait_operation(
    c: &ControlClient,
    id: Uuid,
    expected: Option<(Uuid, i64)>,
    timeout: u64,
    j: bool,
) -> Result<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout);
    loop {
        let response =
            tokio::time::timeout_at(deadline, c.get(&format!("/v1/compute/operations/{id}")))
                .await
                .map_err(|_| WaitTimeout { operation_id: id })??;
        platform::validate_response("getComputeOperation", "200", &response)?;
        let op: Operation = serde_json::from_value(response.clone())?;
        ensure!(
            op.operation_id == id
                && expected
                    .is_none_or(|(vm, generation)| op.vm_id == vm && op.generation == generation),
            "operation identity changed"
        );
        if output::is_jsonl() {
            output::print(&json!({"event":"operation","operation":response}), j)?;
        }
        match op.status.as_str() {
            "succeeded" => return Ok(response),
            "failed" | "cancelled" => {
                return Err(anyhow!(
                    "compute operation {id} {} (phase {}); inspect pipe compute operations {id}",
                    op.status,
                    op.phase
                ))
            }
            "queued" | "running" => {}
            _ => {
                return Err(anyhow!(
                    "unrecognized operation status for {id}; server work may continue"
                ))
            }
        }
        tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_secs(2)))
            .await
            .map_err(|_| WaitTimeout { operation_id: id })?;
    }
}
pub async fn run(c: &ControlClient, cmd: Commands, j: bool) -> Result<()> {
    let (id, path) = match cmd {
        Commands::Projects => ("listComputeProjects", "/v1/compute/projects".into()),
        Commands::Images => ("listComputeImages", "/v1/compute/images".into()),
        Commands::Flavors => ("listComputeFlavors", "/v1/compute/flavors".into()),
        Commands::Pricing => ("getComputePricing", "/v1/compute/pricing".into()),
        Commands::Usage { id } => ("getComputeUsage", format!("/v1/compute/vms/{id}/usage")),
        Commands::Ssh {
            id,
            identity_file,
            command,
        } => return ssh(c, id, identity_file, command, j).await,
        Commands::Requests => {
            return output::print(&json!({"requests":Journal::open(c)?.list()}), j)
        }
        Commands::Resume { request_id, wait } => {
            return submit(c, None, Some(request_id), wait, j).await
        }
        Commands::Operations { id, wait } => {
            if wait.wait {
                return output::print(&wait_operation(c, id, None, wait.timeout, j).await?, j);
            }
            (
                "getComputeOperation",
                format!("/v1/compute/operations/{id}"),
            )
        }
        Commands::Vms { command } => match command {
            Vms::Get { id } => ("getComputeVm", format!("/v1/compute/vms/{id}")),
            Vms::List { limit, cursor, all } => return list(c, limit, cursor, all, j).await,
            Vms::Create {
                project,
                name,
                image,
                flavor,
                ssh_key,
                price_version,
                auto_renew,
                submit: s,
            } => {
                ensure!(
                    !name.trim().is_empty()
                        && name.len() <= 128
                        && !name.chars().any(char::is_control),
                    "name must contain 1..128 printable bytes"
                );
                ensure!(
                    ssh_key.len() <= 10,
                    "supply at most ten SSH public key files"
                );
                let mut keys = Vec::new();
                for file in ssh_key {
                    use std::io::Read;
                    let mut key = String::new();
                    std::fs::File::open(&file)?
                        .take(16385)
                        .read_to_string(&mut key)?;
                    ensure!(
                        key.len() <= 16384
                            && key.trim().lines().count() == 1
                            && (key.starts_with("ssh-") || key.starts_with("ecdsa-")),
                        "file must contain one OpenSSH public key"
                    );
                    keys.push(key.trim().into());
                }
                return submit(
                    c,
                    Some(Request::create(CreateVm {
                        project_id: project,
                        name,
                        image_id: image,
                        flavor_id: flavor,
                        ssh_public_keys: keys,
                        inference_budget_usd: "0".into(),
                        price_version,
                        auto_renew,
                    })),
                    s.request_id,
                    s.wait,
                    j,
                )
                .await;
            }
            Vms::Start { id, submit: s } => {
                return submit(
                    c,
                    Some(Request::action(id, Action::Start, false)),
                    s.request_id,
                    s.wait,
                    j,
                )
                .await
            }
            Vms::Stop {
                id,
                force,
                submit: s,
            } => {
                return submit(
                    c,
                    Some(Request::action(id, Action::Stop, force)),
                    s.request_id,
                    s.wait,
                    j,
                )
                .await
            }
            Vms::Reboot {
                id,
                force,
                submit: s,
            } => {
                return submit(
                    c,
                    Some(Request::action(id, Action::Reboot, force)),
                    s.request_id,
                    s.wait,
                    j,
                )
                .await
            }
            Vms::Delete { id, submit: s } => {
                return submit(
                    c,
                    Some(Request::action(id, Action::Delete, true)),
                    s.request_id,
                    s.wait,
                    j,
                )
                .await
            }
            Vms::Billing {
                id,
                auto_renew,
                renew,
                price_version,
                submit: s,
            } => {
                return submit(
                    c,
                    Some(Request::billing(
                        id,
                        Billing {
                            auto_renew,
                            renew,
                            price_version,
                        },
                    )),
                    s.request_id,
                    s.wait,
                    j,
                )
                .await
            }
        },
    };
    let value = c.get(&path).await?;
    platform::validate_response(id, "200", &value)?;
    output::print(&value, j)
}
async fn ssh(
    c: &ControlClient,
    id: Uuid,
    identity: Option<PathBuf>,
    command: Option<String>,
    j: bool,
) -> Result<()> {
    ensure!(
        !j,
        "SSH streams remote output directly; select --output table"
    );
    if command.is_none() {
        output::require_input()?;
    }
    let value = c.get(&format!("/v1/compute/vms/{id}")).await?;
    platform::validate_response("getComputeVm", "200", &value)?;
    ensure!(value["vm_id"] == json!(id), "VM identity mismatch");
    ensure!(
        value["ssh_ready"] == true,
        "SSH is unavailable until the VM is ready"
    );
    let connection: pipe_api::compute::Ssh = serde_json::from_value(value["ssh"].clone())
        .context("SSH connection details are unavailable")?;
    let fingerprint = pipe_transports::ssh::validate(&connection)?;
    let alias = format!("pipe-vm-{id}");
    let known_hosts = c
        .secrets
        .state_directory()
        .join(format!("ssh-{id}.known_hosts"));
    if known_hosts.exists() {
        use std::io::Read;
        let mut record = String::new();
        std::fs::File::open(&known_hosts)?
            .take(16385)
            .read_to_string(&mut record)?;
        ensure!(
            record.len() <= 16384 && record.starts_with(&format!("{alias} ")),
            "invalid saved host record; preserve it for investigation"
        );
        pipe_transports::ssh::matching_key(&record, fingerprint)?;
    } else {
        let (kind, key) = pipe_transports::ssh::scan(&connection).await?;
        crate::keyring::atomic_private_write(
            &known_hosts,
            format!("{alias} {kind} {key}\n").as_bytes(),
        )?;
    }
    let status = pipe_transports::ssh::command(
        &connection,
        &alias,
        &known_hosts,
        identity.as_deref(),
        command.as_deref(),
        output::no_input(),
    )?
    .status()
    .await
    .context("OpenSSH ssh is required to connect")?;
    if status.success() {
        return Ok(());
    }
    Err(crate::error::SshExit {
        status: status
            .code()
            .and_then(|s| u8::try_from(s).ok())
            .unwrap_or(255),
    }
    .into())
}
async fn list(
    c: &ControlClient,
    limit: u32,
    mut cursor: Option<Uuid>,
    all: bool,
    j: bool,
) -> Result<()> {
    let mut seen = HashSet::new();
    if let Some(cursor) = cursor {
        seen.insert(cursor);
    }
    let mut items = Vec::new();
    let mut total_bytes = 0usize;
    for _ in 0..1000 {
        let mut path = format!("/v1/compute/vms?limit={limit}");
        if let Some(id) = cursor {
            path.push_str(&format!("&cursor={id}"));
        }
        let page = c.get(&path).await?;
        platform::validate_response("listComputeVms", "200", &page)?;
        let next: Option<Uuid> = serde_json::from_value(page["next_cursor"].clone())?;
        if !all {
            return output::print(&page, j);
        }
        if output::is_jsonl() {
            output::print(&page, j)?;
        } else {
            total_bytes = total_bytes.saturating_add(serde_json::to_vec(&page)?.len());
            ensure!(
                total_bytes <= 16 * 1024 * 1024,
                "VM result exceeds 16 MiB; use --output jsonl or resume from cursor {}",
                cursor.map(|v| v.to_string()).unwrap_or_default()
            );
            items.extend(
                page["vms"]
                    .as_array()
                    .context("missing VM page")?
                    .iter()
                    .cloned(),
            );
            ensure!(
                items.len() <= 10000,
                "VM result bound exceeded; use JSONL or resume from cursor {}",
                cursor.map(|v| v.to_string()).unwrap_or_default()
            );
        }
        if next.is_none() {
            return if output::is_jsonl() {
                Ok(())
            } else {
                output::print(
                    &json!({"vms":items,"next_cursor":null,"features":page["features"]}),
                    j,
                )
            };
        }
        cursor = next;
        ensure!(
            seen.insert(next.unwrap()),
            "server repeated pagination cursor; resume from a verified cursor"
        );
    }
    Err(anyhow!(
        "page limit reached; resume with --cursor {}",
        cursor.unwrap()
    ))
}

#[cfg(test)]
#[path = "compute_tests.rs"]
mod tests;

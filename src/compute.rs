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
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};
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

#[derive(Args, Debug)]
pub struct VmSubmit {
    /// Reuse only with the identical request and account context.
    #[arg(long)]
    pub request_id: Option<Uuid>,
    /// Stop waiting after this many seconds.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
    pub timeout: u64,
    /// Return after the request is accepted instead of waiting for completion.
    #[arg(long)]
    pub no_wait: bool,
    /// Kept as a hidden compatibility alias; short VM commands wait by default.
    #[arg(long, hide = true)]
    pub wait: bool,
}

impl VmSubmit {
    fn into_submit(self) -> Result<Submit> {
        ensure!(
            !(self.wait && self.no_wait),
            "choose either --wait or --no-wait"
        );
        Ok(Submit {
            request_id: self.request_id,
            wait: Wait {
                wait: !self.no_wait,
                timeout: self.timeout,
            },
        })
    }
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

/// Short, name-oriented VM commands for the common customer workflow.
#[derive(Subcommand, Debug)]
pub enum VmCommands {
    /// List owned VMs.
    List {
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
        #[arg(long)]
        cursor: Option<Uuid>,
        /// Follow up to 1000 pages.
        #[arg(long)]
        all: bool,
        /// Include VMs whose desired or observed state is deleted.
        #[arg(long)]
        include_deleted: bool,
    },
    /// Show one VM. Accepts its UUID or exact name.
    Get { selector: String },
    /// Create a VM with a human-readable name.
    Create {
        name: String,
        #[arg(long)]
        project: Option<Uuid>,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        flavor: Option<String>,
        /// Add a public key; defaults to the first local SSH key pair.
        #[arg(long)]
        ssh_key: Vec<PathBuf>,
        #[arg(long)]
        price_version: Option<String>,
        #[arg(long, action=clap::ArgAction::Set)]
        auto_renew: Option<bool>,
        #[command(flatten)]
        submit: VmSubmit,
    },
    /// Start a VM by UUID or exact name.
    Start {
        selector: String,
        #[command(flatten)]
        submit: VmSubmit,
    },
    /// Stop a VM by UUID or exact name.
    Stop {
        selector: String,
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        submit: VmSubmit,
    },
    /// Reboot a VM by UUID or exact name.
    Reboot {
        selector: String,
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        submit: VmSubmit,
    },
    /// Delete a VM by UUID or exact name.
    Delete {
        selector: String,
        #[command(flatten)]
        submit: VmSubmit,
    },
    /// Open an interactive SSH session, waiting for the VM to become ready.
    Connect {
        /// VM UUID or exact VM name.
        selector: String,
        #[arg(long)]
        identity_file: Option<PathBuf>,
        /// Execute this command remotely instead of opening an interactive shell.
        #[arg(long)]
        command: Option<String>,
        /// Stop waiting after this many seconds.
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
        timeout: u64,
        /// Fail immediately when SSH is not ready.
        #[arg(long)]
        no_wait: bool,
    },
    /// Execute one remote command, waiting for the VM to become ready.
    Exec {
        /// VM UUID or exact VM name.
        selector: String,
        command: String,
        #[arg(long)]
        identity_file: Option<PathBuf>,
        /// Stop waiting after this many seconds.
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
        timeout: u64,
        /// Fail immediately when SSH is not ready.
        #[arg(long)]
        no_wait: bool,
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

pub fn vm_needs_confirmation(cmd: &VmCommands) -> bool {
    matches!(
        cmd,
        VmCommands::Create { .. }
            | VmCommands::Stop { .. }
            | VmCommands::Reboot { .. }
            | VmCommands::Delete { .. }
    )
}

pub fn preflight_vm(cmd: &VmCommands) -> Result<()> {
    if let VmCommands::Create { ssh_key, .. } = cmd {
        if ssh_key.is_empty() {
            default_public_identity_file().ok_or_else(|| {
                anyhow!(
                    "no default SSH key pair found; supply --ssh-key PATH or create a key pair in ~/.ssh"
                )
            })?;
        }
    }
    Ok(())
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

pub async fn run_vm(c: &ControlClient, cmd: VmCommands, j: bool) -> Result<()> {
    match &cmd {
        VmCommands::Create { .. } => {
            c.authorize_compute_writes(true, false).await?;
            require_vm_scopes(c, &["compute.write", "billing.write"], "create a VM").await?
        }
        VmCommands::Start { .. }
        | VmCommands::Stop { .. }
        | VmCommands::Reboot { .. }
        | VmCommands::Delete { .. } => {
            c.authorize_compute_writes(false, false).await?;
            require_vm_scopes(c, &["compute.write"], "change VM state").await?
        }
        VmCommands::List { .. }
        | VmCommands::Get { .. }
        | VmCommands::Connect { .. }
        | VmCommands::Exec { .. } => {}
    }
    match cmd {
        VmCommands::List {
            limit,
            cursor,
            all,
            include_deleted,
        } => list_vm(c, limit, cursor, all, include_deleted, j).await,
        VmCommands::Get { selector } => {
            let id = resolve_vm_id(c, &selector).await?;
            let value = get_vm(c, id).await?;
            output::print(&value, j)
        }
        VmCommands::Create {
            name,
            project,
            image,
            flavor,
            mut ssh_key,
            price_version,
            auto_renew,
            submit,
        } => {
            let submit = submit.into_submit()?;
            if ssh_key.is_empty() {
                ssh_key.push(default_public_identity_file().context(
                    "no default SSH key pair found; supply --ssh-key PATH or create a key pair in ~/.ssh",
                )?);
            }
            let project = match project {
                Some(project) => project,
                None => default_project(c).await?,
            };
            let image = match image {
                Some(image) => image,
                None => default_image(c).await?,
            };
            let flavor = match flavor {
                Some(flavor) => flavor,
                None => default_flavor(c).await?,
            };
            // The legacy dev flavor has no billing contract. Paid personal
            // plans require both the current price version and an explicit
            // renewal choice; default renewal off so a first VM never opts a
            // customer into recurring charges without saying so.
            let discovered_price_version =
                if flavor != LEGACY_PILOT_FLAVOR && price_version.is_none() {
                    Some(default_price_version(c).await?)
                } else {
                    None
                };
            let (price_version, auto_renew) =
                choose_create_terms(&flavor, price_version, auto_renew, discovered_price_version)?;
            run(
                c,
                Commands::Vms {
                    command: Vms::Create {
                        project,
                        name,
                        image,
                        flavor,
                        ssh_key,
                        price_version,
                        auto_renew,
                        submit,
                    },
                },
                j,
            )
            .await
        }
        VmCommands::Start { selector, submit } => {
            let submit = submit.into_submit()?;
            let id = resolve_vm_id(c, &selector).await?;
            run(
                c,
                Commands::Vms {
                    command: Vms::Start { id, submit },
                },
                j,
            )
            .await
        }
        VmCommands::Stop {
            selector,
            force,
            submit,
        } => {
            let submit = submit.into_submit()?;
            let id = resolve_vm_id(c, &selector).await?;
            run(
                c,
                Commands::Vms {
                    command: Vms::Stop { id, force, submit },
                },
                j,
            )
            .await
        }
        VmCommands::Reboot {
            selector,
            force,
            submit,
        } => {
            let submit = submit.into_submit()?;
            let id = resolve_vm_id(c, &selector).await?;
            run(
                c,
                Commands::Vms {
                    command: Vms::Reboot { id, force, submit },
                },
                j,
            )
            .await
        }
        VmCommands::Delete { selector, submit } => {
            let submit = submit.into_submit()?;
            let id = resolve_vm_id(c, &selector).await?;
            run(
                c,
                Commands::Vms {
                    command: Vms::Delete { id, submit },
                },
                j,
            )
            .await
        }
        VmCommands::Connect {
            selector,
            identity_file,
            command,
            timeout,
            no_wait,
        } => {
            ensure!(!j, "SSH streams remote output; select --output table");
            if command.is_none() {
                output::require_input()?;
            }
            let id = resolve_vm_id(c, &selector).await?;
            if !no_wait {
                wait_for_ssh(c, id, timeout).await?;
            }
            ssh(c, id, identity_file, command, false).await
        }
        VmCommands::Exec {
            selector,
            command,
            identity_file,
            timeout,
            no_wait,
        } => {
            ensure!(!j, "SSH streams remote output; select --output table");
            let id = resolve_vm_id(c, &selector).await?;
            if !no_wait {
                wait_for_ssh(c, id, timeout).await?;
            }
            ssh(c, id, identity_file, Some(command), false).await
        }
    }
}

async fn require_vm_scopes(c: &ControlClient, required: &[&str], action: &str) -> Result<()> {
    let value = c.get("/v1/cli/context").await?;
    platform::validate_response("platformCliContext", "200", &value)?;
    let scopes = value["principal"]["scopes"]
        .as_array()
        .context("authenticated context is missing scopes")?;
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|required| !scopes.iter().any(|scope| scope.as_str() == Some(required)))
        .collect();
    ensure!(
        missing.is_empty(),
        "cannot {action}: active session lacks {}. Run `pipe init` to authorize write access, then retry",
        missing.join(" and ")
    );
    Ok(())
}

async fn get_vm(c: &ControlClient, id: Uuid) -> Result<Value> {
    let value = c.get(&format!("/v1/compute/vms/{id}")).await?;
    platform::validate_response("getComputeVm", "200", &value)?;
    ensure!(value["vm_id"] == json!(id), "VM identity mismatch");
    Ok(value)
}

async fn resolve_vm_id(c: &ControlClient, selector: &str) -> Result<Uuid> {
    if let Ok(id) = Uuid::parse_str(selector) {
        return Ok(id);
    }
    ensure!(
        !selector.trim().is_empty() && selector.len() <= 128,
        "VM name must contain 1..128 characters"
    );

    let mut cursor: Option<Uuid> = None;
    let mut seen = HashSet::new();
    let mut matches = Vec::new();
    for _ in 0..1000 {
        let mut path = "/v1/compute/vms?limit=100".to_owned();
        if let Some(cursor) = cursor {
            path.push_str(&format!("&cursor={cursor}"));
        }
        let page = c.get(&path).await?;
        platform::validate_response("listComputeVms", "200", &page)?;
        for vm in page["vms"].as_array().context("missing VM list")? {
            if vm["name"].as_str() == Some(selector) {
                let id = vm["vm_id"]
                    .as_str()
                    .context("VM list entry is missing vm_id")?
                    .parse::<Uuid>()?;
                matches.push(id);
            }
        }
        cursor = serde_json::from_value(page["next_cursor"].clone())?;
        let Some(next) = cursor else { break };
        ensure!(seen.insert(next), "server repeated pagination cursor");
    }
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(anyhow!(
            "VM '{selector}' was not found; run 'pipe vm list' to see available VMs"
        )),
        _ => Err(anyhow!(
            "VM name '{selector}' is ambiguous; use its UUID from 'pipe vm list'"
        )),
    }
}

async fn default_project(c: &ControlClient) -> Result<Uuid> {
    let value = c.get("/v1/compute/projects").await?;
    platform::validate_response("listComputeProjects", "200", &value)?;
    let projects = value["projects"]
        .as_array()
        .context("missing project list")?;
    match projects.as_slice() {
        [project] => project["project_id"]
            .as_str()
            .context("project is missing project_id")?
            .parse()
            .context("project_id is not a UUID"),
        [] => Err(anyhow!(
            "no eligible compute project was found; use --project PROJECT_UUID"
        )),
        _ => Err(anyhow!(
            "multiple compute projects are available; use --project PROJECT_UUID"
        )),
    }
}

async fn default_image(c: &ControlClient) -> Result<String> {
    let value = c.get("/v1/compute/images").await?;
    platform::validate_response("listComputeImages", "200", &value)?;
    let images = value["images"].as_array().context("missing image list")?;
    match images.as_slice() {
        [image] => image["id"]
            .as_str()
            .map(str::to_owned)
            .context("image is missing id"),
        [] => Err(anyhow!(
            "no eligible compute image was found; use --image IMAGE_ID"
        )),
        _ => Err(anyhow!(
            "multiple compute images are available; use --image IMAGE_ID"
        )),
    }
}

async fn default_flavor(c: &ControlClient) -> Result<String> {
    let value = c.get("/v1/compute/flavors").await?;
    platform::validate_response("listComputeFlavors", "200", &value)?;
    let flavors = value["flavors"].as_array().context("missing flavor list")?;
    choose_default_flavor(flavors)
}

async fn default_price_version(c: &ControlClient) -> Result<String> {
    let value = c.get("/v1/compute/pricing").await?;
    platform::validate_response("getComputePricing", "200", &value)?;
    choose_default_price_version(&value)
}

const LEGACY_PILOT_FLAVOR: &str = "dev-4";

fn choose_create_terms(
    flavor: &str,
    price_version: Option<String>,
    auto_renew: Option<bool>,
    discovered_price_version: Option<String>,
) -> Result<(Option<String>, Option<bool>)> {
    if flavor == LEGACY_PILOT_FLAVOR {
        return Ok((price_version, auto_renew));
    }
    Ok((
        Some(price_version.or(discovered_price_version).context(
            "current compute pricing has no version; supply --price-version PRICE_VERSION",
        )?),
        Some(auto_renew.unwrap_or(false)),
    ))
}

fn choose_default_price_version(value: &Value) -> Result<String> {
    value["version"]
        .as_str()
        .filter(|version| !version.is_empty())
        .map(str::to_owned)
        .context("current compute pricing has no version; supply --price-version PRICE_VERSION")
}

fn choose_default_flavor(flavors: &[Value]) -> Result<String> {
    if flavors.iter().any(|flavor| flavor["id"] == json!("dev-4")) {
        return Ok("dev-4".into());
    }
    flavors
        .iter()
        .min_by(|left, right| {
            let left_key = (
                left["vcpus"].as_u64().unwrap_or(u64::MAX),
                left["memory_mib"].as_u64().unwrap_or(u64::MAX),
                left["disk_gib"].as_u64().unwrap_or(u64::MAX),
                left["id"].as_str().unwrap_or(""),
            );
            let right_key = (
                right["vcpus"].as_u64().unwrap_or(u64::MAX),
                right["memory_mib"].as_u64().unwrap_or(u64::MAX),
                right["disk_gib"].as_u64().unwrap_or(u64::MAX),
                right["id"].as_str().unwrap_or(""),
            );
            left_key.cmp(&right_key)
        })
        .and_then(|flavor| flavor["id"].as_str())
        .map(str::to_owned)
        .context("no eligible compute flavor was found; use --flavor FLAVOR_ID")
}

async fn wait_for_ssh(c: &ControlClient, id: Uuid, timeout: u64) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout);
    let mut announced = false;
    loop {
        let value = get_vm(c, id).await?;
        if value["ssh_ready"] == true {
            return Ok(());
        }
        let desired = value["desired_state"].as_str().unwrap_or("unknown");
        if matches!(desired, "stopped" | "deleted") {
            return Err(anyhow!("VM {id} is {desired}; start it before connecting"));
        }
        if !announced {
            eprintln!("Waiting for VM {id} SSH to become ready...");
            announced = true;
        }
        tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_secs(2)))
            .await
            .map_err(|_| WaitTimeout {
                operation_id: value["operation_id"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(id),
            })?;
    }
}

fn default_identity_file() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    default_identity_file_in(&home)
}

fn default_identity_file_in(home: &Path) -> Option<PathBuf> {
    let candidates = default_identity_candidates(home);
    candidates
        .iter()
        .find(|path| path.is_file() && path.with_extension("pub").is_file())
        .cloned()
        .or_else(|| candidates.into_iter().find(|path| path.is_file()))
}

fn default_public_identity_file() -> Option<PathBuf> {
    dirs::home_dir().and_then(|home| default_public_identity_file_in(&home))
}

fn default_public_identity_file_in(home: &Path) -> Option<PathBuf> {
    default_identity_candidates(home)
        .into_iter()
        .find(|private| private.is_file() && private.with_extension("pub").is_file())
        .map(|private| private.with_extension("pub"))
}

fn default_identity_candidates(home: &Path) -> Vec<PathBuf> {
    ["id_ed25519", "id_ecdsa", "id_rsa", "google_compute_engine"]
        .into_iter()
        .map(|name| home.join(".ssh").join(name))
        .collect()
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
    let value = get_vm(c, id).await?;
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
    let identity = identity.or_else(default_identity_file);
    if let Some(identity) = identity.as_ref() {
        eprintln!("Using SSH identity {}", identity.display());
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

async fn list_vm(
    c: &ControlClient,
    limit: u32,
    mut cursor: Option<Uuid>,
    all: bool,
    include_deleted: bool,
    j: bool,
) -> Result<()> {
    let human = !j && !output::is_json() && !output::is_jsonl();
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
            if human {
                return print_vm_table(
                    page["vms"].as_array().context("missing VM list")?,
                    include_deleted,
                    next.is_some(),
                );
            }
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
        }
        if next.is_none() {
            if human {
                return print_vm_table(&items, include_deleted, false);
            }
            return output::print(
                &json!({"vms":items,"next_cursor":null,"features":page["features"]}),
                j,
            );
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

fn print_vm_table(items: &[Value], include_deleted: bool, more: bool) -> Result<()> {
    let rows: Vec<[String; 7]> = items
        .iter()
        .filter(|vm| include_deleted || !vm_is_deleted(vm))
        .map(|vm| {
            [
                vm["name"].as_str().unwrap_or("-").to_owned(),
                vm_state(vm),
                if vm["ssh_ready"] == true {
                    "ready".into()
                } else {
                    "-".into()
                },
                vm["flavor_id"].as_str().unwrap_or("-").to_owned(),
                vm["vcpus"].to_string(),
                format_memory(vm["memory_mib"].as_u64()),
                format_disk(vm["disk_gib"].as_u64()),
            ]
        })
        .collect();
    if rows.is_empty() {
        if include_deleted {
            println!("No VMs found.");
        } else {
            println!("No active VMs. Use --include-deleted to show deleted VMs.");
        }
        return Ok(());
    }
    let headers = ["NAME", "STATE", "SSH", "FLAVOR", "CPU", "MEMORY", "DISK"];
    let widths: Vec<usize> = (0..headers.len())
        .map(|column| {
            rows.iter()
                .map(|row| row[column].len())
                .chain(std::iter::once(headers[column].len()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    println!(
        "{}",
        headers
            .iter()
            .enumerate()
            .map(|(column, header)| format_cell(header, widths[column]))
            .collect::<Vec<_>>()
            .join("  ")
    );
    for row in rows {
        println!(
            "{}",
            row.iter()
                .enumerate()
                .map(|(column, cell)| format_cell(cell, widths[column]))
                .collect::<Vec<_>>()
                .join("  ")
        );
    }
    if more {
        println!("\nMore VMs available. Use --all to list them.");
    }
    Ok(())
}

fn format_cell(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn vm_is_deleted(vm: &Value) -> bool {
    vm["desired_state"] == json!("deleted") || vm["observed_state"] == json!("deleted")
}

fn vm_state(vm: &Value) -> String {
    let desired = vm["desired_state"].as_str().unwrap_or("unknown");
    let observed = vm["observed_state"].as_str().unwrap_or("unknown");
    if observed == "unknown" {
        desired.to_owned()
    } else if desired == observed {
        observed.to_owned()
    } else {
        format!("{desired}/{observed}")
    }
}

fn format_memory(memory_mib: Option<u64>) -> String {
    memory_mib
        .map(|mib| {
            if mib % 1024 == 0 {
                format!("{} GiB", mib / 1024)
            } else {
                format!("{mib} MiB")
            }
        })
        .unwrap_or_else(|| "-".into())
}

fn format_disk(disk_gib: Option<u64>) -> String {
    disk_gib
        .map(|gib| format!("{gib} GiB"))
        .unwrap_or_else(|| "-".into())
}

#[cfg(test)]
#[path = "compute_tests.rs"]
mod tests;

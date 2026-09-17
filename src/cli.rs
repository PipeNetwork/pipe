use crate::{
    account,
    auth::ControlClient,
    config::{ConfigStore, Profile},
    crypto, output, payments,
    s3::S3Client,
    sync,
};
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "pipe", version, about = "Pipe platform command-line client")]
pub struct Cli {
    #[arg(
        long,
        global = true,
        env = "PIPE_CLI_CONFIG",
        help = "Path to the profile configuration"
    )]
    pub config: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Named profile (defaults to the active profile)"
    )]
    pub profile: Option<String>,
    #[arg(long, global = true, help = "Print machine-readable JSON")]
    pub json: bool,
    #[arg(long, global = true, value_enum, conflicts_with = "json")]
    pub output: Option<output::Mode>,
    #[arg(long, global = true)]
    pub no_input: bool,
    #[arg(
        long,
        global = true,
        help = "Confirm resource deletion and payment submission without prompting"
    )]
    pub yes: bool,
    #[arg(
        long,
        global = true,
        help = "Explicitly export newly issued credential secrets"
    )]
    pub show_secret: bool,
    #[arg(long, global = true, env = "PIPE_CONTROL_API_URL")]
    pub control_api_url: Option<String>,
    #[arg(
        long,
        global = true,
        conflicts_with = "if_none_match",
        help = "Require this opaque object ETag"
    )]
    pub if_match: Option<String>,
    #[arg(
        long,
        global = true,
        conflicts_with = "if_match",
        help = "Require a different ETag, or '*' to require absence"
    )]
    pub if_none_match: Option<String>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Shortcut for `auth login`.
    Login {
        #[arg(
            long,
            default_value = "account.read org.read billing.read storage.read usage.read compute.read hosting.read kv.read durable.read"
        )]
        scope: String,
        #[arg(long)]
        no_browser: bool,
        #[arg(long)]
        wallet: Option<String>,
        #[arg(long, requires = "wallet")]
        legacy_wallet: bool,
        #[arg(long)]
        device_label: Option<String>,
    },
    /// Shortcut for `auth logout`.
    Logout,
    /// Show the authenticated CLI context.
    Whoami,
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    Account {
        #[command(subcommand)]
        command: Option<crate::customer::Account>,
    },
    Org {
        #[command(subcommand)]
        command: crate::customer::Org,
    },
    Billing {
        #[command(subcommand)]
        command: crate::customer::Billing,
    },
    /// Resolve canonical identity and available infrastructure contexts.
    Context,
    Credentials {
        #[command(subcommand)]
        command: crate::platform::CredentialCommands,
    },
    /// Report explicit supported, enabled and authorized capabilities.
    Doctor {
        /// Write a private redacted diagnostic report; never uploads it.
        #[arg(long)]
        export: Option<PathBuf>,
    },
    Api {
        #[command(subcommand)]
        command: crate::platform::ApiCommands,
    },
    /// Customer compute workflows.
    Compute {
        #[command(subcommand)]
        command: crate::platform::ComputeCommands,
    },
    /// Customer KV management.
    Kv {
        #[command(subcommand)]
        command: crate::platform::KvCommands,
    },
    /// Paid customer Durable Objects management.
    Durable {
        #[command(subcommand)]
        command: crate::platform::DurableCommands,
    },
    Hosting {
        #[command(subcommand)]
        command: crate::platform::HostingCommands,
    },
    Storage {
        #[command(subcommand)]
        command: StorageCommands,
    },
    /// Current customer storage pricing; product pricing is also available in each product command.
    Pricing,
    Credits,
    Usage {
        #[arg(long)]
        from: Option<u64>,
        #[arg(long)]
        to: Option<u64>,
    },
    Payments {
        #[command(subcommand)]
        command: PaymentCommands,
    },
    S3 {
        #[command(subcommand)]
        command: S3Commands,
    },
    Bucket {
        #[command(subcommand)]
        command: BucketCommands,
    },
    Object {
        #[command(subcommand)]
        command: ObjectCommands,
    },
    UploadFile {
        local_file: String,
        destination: String,
        #[arg(long)]
        encrypt: bool,
        #[arg(
            long = "password-file",
            help = "Read encryption password from a private file; otherwise prompt"
        )]
        password: Option<String>,
        #[arg(long, help = "Resume a previously created multipart upload")]
        upload_id: Option<String>,
    },
    DownloadFile {
        remote: String,
        local_file: String,
        #[arg(long)]
        decrypt: bool,
        #[arg(
            long = "password-file",
            help = "Read decryption password from a private file; otherwise prompt"
        )]
        password: Option<String>,
        #[arg(long)]
        range: Option<String>,
    },
    UploadDirectory {
        local_directory: String,
        bucket: String,
        #[arg(default_value = "")]
        prefix: String,
    },
    DownloadDirectory {
        bucket: String,
        prefix: String,
        local_directory: String,
    },
    Sync {
        source: String,
        destination: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum StorageCommands {
    Bucket {
        #[command(subcommand)]
        command: BucketCommands,
    },
    Object {
        #[command(subcommand)]
        command: ObjectCommands,
    },
    S3 {
        #[command(subcommand)]
        command: S3Commands,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuthCommands {
    /// Sign in using the existing Pipe website account.
    Browser {
        #[arg(long, default_value = "Pipe CLI")]
        device_label: String,
        #[arg(
            long,
            default_value = "account.read org.read billing.read storage.read usage.read compute.read hosting.read kv.read durable.read"
        )]
        scope: String,
        #[arg(long)]
        no_browser: bool,
    },
    Login {
        #[arg(
            long,
            default_value = "account.read org.read billing.read storage.read usage.read compute.read hosting.read kv.read durable.read"
        )]
        scope: String,
        #[arg(long)]
        no_browser: bool,
        #[arg(long)]
        wallet: Option<String>,
        /// Use the preserved storage-only wallet authentication endpoints.
        #[arg(long, requires = "wallet")]
        legacy_wallet: bool,
        #[arg(long)]
        device_label: Option<String>,
    },
    Logout,
    /// Show local session status without printing tokens.
    Status,
    Sessions {
        #[arg(long)]
        revoke: Option<Uuid>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProfileCommands {
    Create {
        name: String,
        #[arg(long)]
        control_api_url: Option<String>,
        #[arg(long)]
        s3_endpoint: Option<String>,
        #[arg(long, default_value = "us-east-1")]
        region: String,
        #[arg(long)]
        bucket: Option<String>,
        #[arg(long)]
        prefix: Option<String>,
    },
    Use {
        name: String,
    },
    #[command(visible_alias = "get")]
    Show {
        name: Option<String>,
    },
    #[command(visible_alias = "update")]
    Set {
        name: Option<String>,
        #[arg(long)]
        control_api_url: Option<String>,
        #[arg(long)]
        s3_endpoint: Option<String>,
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        bucket: Option<String>,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long)]
        clear_bucket: bool,
        #[arg(long)]
        clear_prefix: bool,
        #[arg(long)]
        clear_s3_endpoint: bool,
    },
    List,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    Show,
    /// Create a private checksummed profile/configuration backup.
    Backup {
        destination: PathBuf,
    },
    /// Restore configuration while preserving all current secrets and journals.
    Rollback {
        backup: PathBuf,
    },
    Migrate {
        #[arg(long)]
        legacy_path: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum PaymentCommands {
    Config,
    CreateX402 {
        amount: String,
        #[arg(long)]
        idempotency_key: Option<Uuid>,
    },
    SubmitX402 {
        invoice_id: String,
        #[arg(long)]
        payload_file: String,
    },
    Create {
        amount: String,
        #[arg(long)]
        payer: Option<String>,
        #[arg(long)]
        idempotency_key: Option<Uuid>,
    },
    Status {
        invoice_id: String,
    },
    Pay {
        invoice_id: String,
    },
    Submit {
        invoice_id: String,
        #[arg(long)]
        transaction: Option<String>,
        #[arg(long)]
        signature: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum S3Commands {
    /// Show the configured bucket after a signed HEAD request.
    ///
    /// Pipe's customer gateway does not expose global ListBuckets enumeration,
    /// so this is equivalent to `pipe bucket list`.
    #[command(name = "ls", visible_alias = "list")]
    List {
        location: Option<String>,
    },
    /// Copy one object, or a directory with `--recursive`.
    #[command(name = "cp", visible_alias = "copy")]
    Copy {
        source: String,
        destination: String,
        #[arg(long)]
        recursive: bool,
    },
    /// Synchronize a local directory and an S3 prefix.
    Sync {
        source: String,
        destination: String,
    },
    /// Delete one object, or every object under a prefix with `--recursive`.
    #[command(name = "rm", visible_alias = "delete")]
    Remove {
        remote: String,
        #[arg(long)]
        recursive: bool,
    },
    /// Create a bucket.
    #[command(name = "mb", visible_alias = "make-bucket")]
    MakeBucket {
        bucket: String,
    },
    /// Delete an empty bucket.
    #[command(name = "rb", visible_alias = "remove-bucket")]
    RemoveBucket {
        bucket: String,
    },
    /// Inspect a bucket or object.
    #[command(name = "head", visible_alias = "stat")]
    Head {
        remote: String,
    },
    Multipart {
        #[command(subcommand)]
        command: MultipartCommands,
    },
    #[command(visible_alias = "credentials")]
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },
    Endpoint,
}

#[derive(Subcommand, Debug)]
pub enum MultipartCommands {
    List { bucket: String },
    Parts { remote: String, upload_id: String },
    Complete { remote: String, upload_id: String },
    Abort { remote: String, upload_id: String },
}

#[derive(Subcommand, Debug)]
pub enum CredentialCommands {
    Rotate {
        access_key_id: String,
    },
    Use {
        access_key_id: String,
    },
    Import {
        access_key_id: String,
    },
    Create {
        #[arg(long)]
        wallet: Option<String>,
        #[arg(long, default_value = "cli")]
        label: String,
        #[arg(long = "bucket")]
        buckets: Vec<String>,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long = "permission")]
        permissions: Vec<String>,
        #[arg(long)]
        expires_at: Option<u64>,
    },
    List,
    Revoke {
        access_key_id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum BucketCommands {
    Create {
        bucket: String,
    },
    #[command(visible_alias = "ls")]
    List,
    #[command(visible_alias = "stat")]
    Head {
        bucket: String,
    },
    #[command(visible_alias = "rm")]
    Delete {
        bucket: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ObjectCommands {
    Put {
        local_file: String,
        destination: String,
        #[arg(long)]
        encrypt: bool,
        #[arg(
            long = "password-file",
            help = "Read encryption password from a private file; otherwise prompt"
        )]
        password: Option<String>,
        #[arg(long, help = "Resume a previously created multipart upload")]
        upload_id: Option<String>,
    },
    Get {
        remote: String,
        local_file: String,
        #[arg(long)]
        decrypt: bool,
        #[arg(
            long = "password-file",
            help = "Read decryption password from a private file; otherwise prompt"
        )]
        password: Option<String>,
        #[arg(long)]
        range: Option<String>,
    },
    #[command(visible_alias = "stat")]
    Head { remote: String },
    #[command(visible_alias = "rm")]
    Delete { remote: String },
    List {
        bucket: String,
        #[arg(default_value = "")]
        prefix: String,
    },
}

pub async fn run(mut cli: Cli) -> Result<()> {
    output::configure(cli.output, cli.no_input, cli.show_secret);
    cli.json |= matches!(cli.output, Some(output::Mode::Json | output::Mode::Jsonl));
    if destructive(&cli.command) && !cli.yes {
        output::require_input()?;
        eprint!("This command deletes a resource or submits a payment. Type yes to continue: ");
        use std::io::Write;
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        anyhow::ensure!(answer.trim() == "yes", "command cancelled");
    }

    match &cli.command {
        Commands::Profile { command } => return profile_command(&cli, command).await,
        Commands::Config { command } => return config_command(&cli, command),
        _ => {}
    }
    let (mut store, name, profile) = context(&cli)?;
    let mut client = ControlClient::new(
        profile.clone(),
        format!("{}:{}", store.path.display(), name),
    )?;
    client.if_match = cli.if_match;
    client.if_none_match = cli.if_none_match;
    client.progress = !cli.json;
    let _command_lock = client.secrets.command_lock()?;
    match cli.command {
        Commands::Credentials { command } => {
            crate::platform::credentials(&client, command, cli.json).await
        }
        Commands::Context => output::print(&client.get("/v1/cli/context").await?, cli.json),
        Commands::Doctor { export } => {
            crate::doctor::run(&client, export.as_deref(), cli.json).await
        }
        Commands::Api { command } => crate::platform::api(&client, command, cli.json).await,
        Commands::Compute { command } => crate::platform::compute(&client, command, cli.json).await,
        Commands::Kv { command } => crate::platform::kv(&client, command, cli.json).await,
        Commands::Durable { command } => crate::platform::durable(&client, command, cli.json).await,
        Commands::Hosting { command } => crate::platform::hosting(&client, command, cli.json).await,
        Commands::Storage { command } => match command {
            StorageCommands::Bucket { command } => {
                bucket_command(&client, &store, &name, &profile, command, cli.json).await
            }
            StorageCommands::Object { command } => {
                object_command(&client, &store, &name, &profile, command, cli.json).await
            }
            StorageCommands::S3 { command } => {
                s3_command(&client, &mut store, &name, command, cli.json).await
            }
        },
        Commands::Auth { command } => auth_command(&client, command, cli.json).await,
        Commands::Login {
            scope,
            no_browser,
            wallet,
            legacy_wallet,
            device_label,
        } => {
            auth_command(
                &client,
                AuthCommands::Login {
                    scope,
                    no_browser,
                    wallet,
                    legacy_wallet,
                    device_label,
                },
                cli.json,
            )
            .await
        }
        Commands::Logout => auth_command(&client, AuthCommands::Logout, cli.json).await,
        Commands::Whoami => output::print(&client.get("/v1/cli/context").await?, cli.json),
        Commands::Account { command: None } => {
            output::print(&account::account(&client).await?, cli.json)
        }
        Commands::Account {
            command: Some(command),
        } => crate::customer::account(&client, command, cli.json).await,
        Commands::Org { command } => crate::customer::org(&client, command, cli.json).await,
        Commands::Billing { command } => crate::customer::billing(&client, command, cli.json).await,
        Commands::Pricing => {
            crate::platform::api(
                &client,
                crate::platform::ApiCommands::Call {
                    operation: "getStoragePricing".into(),
                    paths: vec![],
                    query: vec![],
                },
                cli.json,
            )
            .await
        }
        Commands::Credits => {
            let value = account::account(&client).await?;
            let payment_config = payments::config(&client).await?;
            let simplified = json!({"owner_wallet":value["owner_wallet"],"identities":value["identities"],"payments":value["payments"],"payment_config":payment_config});
            output::print(&simplified, cli.json)
        }
        Commands::Usage { from, to } => {
            output::print(&account::usage(&client, from, to).await?, cli.json)
        }
        Commands::Payments { command } => payment_command(&client, command, cli.json).await,
        Commands::S3 { command } => s3_command(&client, &mut store, &name, command, cli.json).await,
        Commands::Bucket { command } => {
            bucket_command(&client, &store, &name, &profile, command, cli.json).await
        }
        Commands::Object { command } => {
            object_command(&client, &store, &name, &profile, command, cli.json).await
        }
        Commands::UploadFile {
            local_file,
            destination,
            encrypt,
            password,
            upload_id,
        } => {
            put_file_command(
                &client,
                &store,
                &name,
                &profile,
                &local_file,
                &destination,
                encrypt,
                password.as_deref(),
                upload_id.as_deref(),
                cli.json,
            )
            .await
        }
        Commands::DownloadFile {
            remote,
            local_file,
            decrypt,
            password,
            range,
        } => {
            get_file_command(
                &client,
                &store,
                &name,
                &profile,
                &remote,
                &local_file,
                decrypt,
                password.as_deref(),
                range.as_deref(),
                cli.json,
            )
            .await
        }
        Commands::UploadDirectory {
            local_directory,
            bucket,
            prefix,
        } => {
            let s3 = s3_client(&client, &store, &name, &profile).await?;
            let count =
                sync::upload_directory(&s3, Path::new(&local_directory), &bucket, &prefix).await?;
            output::print(
                &json!({"uploaded":count,"bucket":bucket,"prefix":prefix}),
                cli.json,
            )
        }
        Commands::DownloadDirectory {
            bucket,
            prefix,
            local_directory,
        } => {
            let s3 = s3_client(&client, &store, &name, &profile).await?;
            let count =
                sync::download_directory(&s3, &bucket, &prefix, Path::new(&local_directory))
                    .await?;
            output::print(
                &json!({"downloaded":count,"bucket":bucket,"prefix":prefix}),
                cli.json,
            )
        }
        Commands::Sync {
            source,
            destination,
        } => {
            sync_command(
                &client,
                &store,
                &name,
                &profile,
                &source,
                &destination,
                cli.json,
            )
            .await
        }
        Commands::Profile { .. } | Commands::Config { .. } => unreachable!(),
    }
}

fn context(cli: &Cli) -> Result<(ConfigStore, String, Profile)> {
    let store = ConfigStore::load(cli.config.as_deref())?;
    let (name, mut profile) = store.profile(cli.profile.as_deref())?;
    if let Some(url) = &cli.control_api_url {
        profile.control_api_url = url.clone();
        profile.validate()?;
    }
    Ok((store, name, profile))
}

async fn auth_command(
    client: &ControlClient,
    command: AuthCommands,
    json_output: bool,
) -> Result<()> {
    match command {
        AuthCommands::Browser {
            device_label,
            scope,
            no_browser,
        } => output::print(
            &crate::device::login(client, &device_label, &scope, no_browser).await?,
            json_output,
        ),
        AuthCommands::Login {
            wallet,
            legacy_wallet,
            device_label,
            scope,
            no_browser,
        } => {
            let result = if let Some(wallet) = wallet {
                if legacy_wallet {
                    client.login(Some(&wallet), device_label.as_deref()).await?
                } else {
                    crate::wallet_auth::login(
                        client,
                        &wallet,
                        device_label.as_deref().unwrap_or("Pipe CLI"),
                        &scope,
                    )
                    .await?
                }
            } else {
                crate::device::login(
                    client,
                    device_label.as_deref().unwrap_or("Pipe CLI"),
                    &scope,
                    no_browser,
                )
                .await?
            };
            output::print(&result, json_output)
        }
        AuthCommands::Logout => output::print(&client.logout().await?, json_output),
        AuthCommands::Status => {
            let session = client.session()?;
            let automation = std::env::var_os("PIPE_CLI_TOKEN").is_some();
            let value = if let Some(session) = session {
                json!({
                    "authenticated": true,
                    "credential_kind": if session.access_token.starts_with("pcli_a_") { "platform_session" } else { "website_session" },
                    "owner_wallet": session.owner_wallet,
                    "account_id": session.account_id,
                    "session_id": session.session_id,
                    "scope": session.scope,
                    "expires_in": session.expires_in,
                    "refresh_expires_in": session.refresh_expires_in,
                })
            } else {
                json!({
                    "authenticated": automation,
                    "credential_kind": if automation { "automation" } else { "none" },
                })
            };
            output::print(&value, json_output)
        }
        AuthCommands::Sessions { revoke } => {
            let value = if let Some(id) = revoke {
                client
                    .delete(&format!("{}/sessions/{id}", client.auth_base()?))
                    .await?
            } else {
                client
                    .get(&format!("{}/sessions", client.auth_base()?))
                    .await?
            };
            output::print(&value, json_output)
        }
    }
}

async fn payment_command(
    client: &ControlClient,
    command: PaymentCommands,
    json_output: bool,
) -> Result<()> {
    match command {
        PaymentCommands::Config => output::print(&payments::config(client).await?, json_output),
        PaymentCommands::CreateX402 {
            amount,
            idempotency_key,
        } => output::print(
            &payments::create_x402(client, parse_usdc(&amount)?, idempotency_key).await?,
            json_output,
        ),
        PaymentCommands::SubmitX402 {
            invoice_id,
            payload_file,
        } => output::print(
            &payments::submit_x402(client, &invoice_id, Path::new(&payload_file)).await?,
            json_output,
        ),
        PaymentCommands::Pay { invoice_id } => {
            output::print(&payments::pay(client, &invoice_id).await?, json_output)
        }
        PaymentCommands::Create {
            amount,
            payer,
            idempotency_key,
        } => {
            let atoms = parse_usdc(&amount)?;
            output::print(
                &payments::create(client, atoms, payer.as_deref(), idempotency_key).await?,
                json_output,
            )
        }
        PaymentCommands::Status { invoice_id } => {
            output::print(&payments::status(client, &invoice_id).await?, json_output)
        }
        PaymentCommands::Submit {
            invoice_id,
            transaction,
            signature,
        } => output::print(
            &payments::submit(
                client,
                &invoice_id,
                transaction.as_deref(),
                signature.as_deref(),
            )
            .await?,
            json_output,
        ),
    }
}

async fn s3_command(
    client: &ControlClient,
    store: &mut ConfigStore,
    name: &str,
    command: S3Commands,
    json_output: bool,
) -> Result<()> {
    match command {
        S3Commands::List { location } => {
            let (_, profile) = store.profile(Some(name))?;
            if let Some(location) = location {
                let (bucket, prefix) = remote_prefix(&profile, &location)?;
                object_command(
                    client,
                    store,
                    name,
                    &profile,
                    ObjectCommands::List { bucket, prefix },
                    json_output,
                )
                .await
            } else {
                bucket_command(
                    client,
                    store,
                    name,
                    &profile,
                    BucketCommands::List,
                    json_output,
                )
                .await
            }
        }
        S3Commands::Copy {
            source,
            destination,
            recursive,
        } => {
            let (_, profile) = store.profile(Some(name))?;
            s3_copy_command(
                client,
                store,
                name,
                &profile,
                &source,
                &destination,
                recursive,
                json_output,
            )
            .await
        }
        S3Commands::Sync {
            source,
            destination,
        } => {
            let (_, profile) = store.profile(Some(name))?;
            sync_command(
                client,
                store,
                name,
                &profile,
                &source,
                &destination,
                json_output,
            )
            .await
        }
        S3Commands::Remove { remote, recursive } => {
            let (_, profile) = store.profile(Some(name))?;
            s3_remove_command(
                client,
                store,
                name,
                &profile,
                &remote,
                recursive,
                json_output,
            )
            .await
        }
        S3Commands::MakeBucket { bucket } => {
            let (_, profile) = store.profile(Some(name))?;
            bucket_command(
                client,
                store,
                name,
                &profile,
                BucketCommands::Create { bucket },
                json_output,
            )
            .await
        }
        S3Commands::RemoveBucket { bucket } => {
            let (_, profile) = store.profile(Some(name))?;
            bucket_command(
                client,
                store,
                name,
                &profile,
                BucketCommands::Delete { bucket },
                json_output,
            )
            .await
        }
        S3Commands::Head { remote } => {
            let (_, profile) = store.profile(Some(name))?;
            if remote
                .strip_prefix("s3://")
                .unwrap_or(&remote)
                .contains('/')
            {
                object_command(
                    client,
                    store,
                    name,
                    &profile,
                    ObjectCommands::Head { remote },
                    json_output,
                )
                .await
            } else {
                bucket_command(
                    client,
                    store,
                    name,
                    &profile,
                    BucketCommands::Head { bucket: remote },
                    json_output,
                )
                .await
            }
        }
        S3Commands::Multipart { command } => {
            let (_, profile) = store.profile(Some(name))?;
            let s3 = s3_client(client, store, name, &profile).await?;
            match command {
                MultipartCommands::List { bucket } => {
                    output::print(&s3.list_multipart_uploads(&bucket).await?, json_output)
                }
                MultipartCommands::Parts { remote, upload_id } => {
                    let (bucket, key) = remote_location(&profile, &remote)?;
                    output::print(
                        &s3.list_parts(&bucket, &key, &upload_id).await?,
                        json_output,
                    )
                }
                MultipartCommands::Complete { remote, upload_id } => {
                    let (bucket, key) = remote_location(&profile, &remote)?;
                    let parts = s3.list_parts(&bucket, &key, &upload_id).await?;
                    s3.complete_multipart_upload(&bucket, &key, &upload_id, &parts)
                        .await?;
                    output::print(
                        &json!({"completed":true,"upload_id":upload_id}),
                        json_output,
                    )
                }
                MultipartCommands::Abort { remote, upload_id } => {
                    let (bucket, key) = remote_location(&profile, &remote)?;
                    s3.abort_multipart_upload(&bucket, &key, &upload_id).await?;
                    output::print(&json!({"aborted":true,"upload_id":upload_id}), json_output)
                }
            }
        }
        S3Commands::Endpoint => {
            let mut value = account::endpoint(client).await?;
            if let Some(endpoint) = value.get("endpoint").and_then(Value::as_str) {
                if let Some(profile) = store.file.profiles.get_mut(name) {
                    profile.s3_endpoint = Some(endpoint.to_owned());
                    if let Some(region) = value.get("region").and_then(Value::as_str) {
                        profile.region = region.to_owned();
                    }
                    profile.validate()?;
                    store.save()?;
                    value["configured"] = json!(true);
                }
            }
            output::print(&value, json_output)
        }
        S3Commands::Credential { command } => match command {
            CredentialCommands::Import { access_key_id } => {
                validate_access_key(&access_key_id)?;
                output::require_input()?;
                let secret =
                    zeroize::Zeroizing::new(rpassword::prompt_password("S3 secret access key: ")?);
                if secret.is_empty() {
                    return Err(anyhow!("S3 secret cannot be empty"));
                }
                client.save_s3_secret(&access_key_id, &secret)?;
                client.secrets.set("s3_access_key", &access_key_id)?;
                output::print(
                    &json!({"access_key_id":access_key_id,"imported":true}),
                    json_output,
                )
            }
            CredentialCommands::Use { access_key_id } => {
                validate_access_key(&access_key_id)?;
                client.s3_secret(&access_key_id)?;
                client.secrets.set("s3_access_key", &access_key_id)?;
                output::print(
                    &json!({"access_key_id":access_key_id,"active":true}),
                    json_output,
                )
            }
            CredentialCommands::Rotate { access_key_id } => {
                rotate_credential(client, &access_key_id, json_output).await
            }
            CredentialCommands::List => {
                output::print(&account::credentials(client).await?, json_output)
            }
            CredentialCommands::Revoke { access_key_id } => {
                validate_access_key(&access_key_id)?;
                let value = account::revoke_credential(client, &access_key_id).await?;
                client.secrets.delete(&format!("s3:{access_key_id}"))?;
                if client.secrets.get("s3_access_key")?.as_deref() == Some(&access_key_id) {
                    client.secrets.delete("s3_access_key")?;
                }
                output::print(&value, json_output)
            }
            CredentialCommands::Create {
                wallet,
                label,
                buckets,
                prefix,
                mut permissions,
                expires_at,
            } => {
                let wallet = wallet.unwrap_or(client.current_wallet()?);
                if permissions.is_empty() {
                    permissions = vec!["read".into(), "write".into(), "list".into()];
                }
                let value = account::create_credential(
                    client,
                    &wallet,
                    &label,
                    &buckets,
                    &prefix,
                    &permissions,
                    expires_at,
                )
                .await?;
                store_credential(client, &value)?;
                output::print_credential(&value, json_output)
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn s3_copy_command(
    client: &ControlClient,
    store: &ConfigStore,
    name: &str,
    profile: &Profile,
    source: &str,
    destination: &str,
    recursive: bool,
    json_output: bool,
) -> Result<()> {
    let source_path = Path::new(source);
    let source_is_local = source_path.exists();
    let destination_is_remote = looks_like_remote(destination);
    let source_is_remote = looks_like_remote(source);
    anyhow::ensure!(
        source_is_local != source_is_remote,
        "copy requires one local path and one S3 location; use s3://bucket/key for clarity"
    );

    if source_is_local {
        anyhow::ensure!(
            destination_is_remote,
            "copy destination must be an S3 location; use s3://bucket/key for clarity"
        );
        let destination = remote_location(profile, destination)?;
        if source_path.is_dir() {
            anyhow::ensure!(recursive, "copying a directory requires --recursive");
            let s3 = s3_client(client, store, name, profile).await?;
            let count =
                sync::upload_directory(&s3, source_path, &destination.0, &destination.1).await?;
            output::print(
                &json!({"uploaded":count,"bucket":destination.0,"prefix":destination.1}),
                json_output,
            )
        } else {
            anyhow::ensure!(
                source_path.is_file(),
                "copy source must be a regular file or directory"
            );
            let destination = destination_string(destination.0, destination.1);
            put_file_command(
                client,
                store,
                name,
                profile,
                source,
                &destination,
                false,
                None,
                None,
                json_output,
            )
            .await
        }
    } else {
        anyhow::ensure!(
            !destination_is_remote,
            "copy requires one local path and one S3 location"
        );
        if recursive {
            let (bucket, prefix) = remote_prefix(profile, source)?;
            let s3 = s3_client(client, store, name, profile).await?;
            let count =
                sync::download_directory(&s3, &bucket, &prefix, Path::new(destination)).await?;
            output::print(
                &json!({"downloaded":count,"bucket":bucket,"prefix":prefix}),
                json_output,
            )
        } else {
            let output_path = if Path::new(destination).is_dir() {
                let (_, key) = remote_location(profile, source)?;
                let filename = Path::new(&key)
                    .file_name()
                    .ok_or_else(|| anyhow!("S3 object has no filename"))?;
                Path::new(destination).join(filename)
            } else {
                PathBuf::from(destination)
            };
            get_file_command(
                client,
                store,
                name,
                profile,
                source,
                output_path
                    .to_str()
                    .ok_or_else(|| anyhow!("destination path is not valid UTF-8"))?,
                false,
                None,
                None,
                json_output,
            )
            .await
        }
    }
}

async fn s3_remove_command(
    client: &ControlClient,
    store: &ConfigStore,
    name: &str,
    profile: &Profile,
    remote: &str,
    recursive: bool,
    json_output: bool,
) -> Result<()> {
    let s3 = s3_client(client, store, name, profile).await?;
    if recursive {
        let (bucket, prefix) = remote_prefix(profile, remote)?;
        let objects = s3.list_all_objects(&bucket, Some(&prefix)).await?;
        for object in &objects {
            s3.delete_object(&bucket, &object.key).await?;
        }
        output::print(
            &json!({"bucket":bucket,"prefix":prefix,"deleted":objects.len()}),
            json_output,
        )
    } else {
        let (bucket, key) = remote_location(profile, remote)?;
        s3.delete_object(&bucket, &key).await?;
        output::print(
            &json!({"bucket":bucket,"key":key,"deleted":true}),
            json_output,
        )
    }
}

fn looks_like_remote(value: &str) -> bool {
    let value = value.strip_prefix("s3://").unwrap_or(value);
    let Some((bucket, key)) = value.split_once('/') else {
        return false;
    };
    !key.is_empty() && (3..=63).contains(&bucket.len()) && !Path::new(value).exists()
}

fn destination_string(bucket: String, key: String) -> String {
    format!("s3://{bucket}/{key}")
}

async fn bucket_command(
    client: &ControlClient,
    store: &ConfigStore,
    name: &str,
    profile: &Profile,
    command: BucketCommands,
    json_output: bool,
) -> Result<()> {
    let s3 = s3_client(client, store, name, profile).await?;
    match command {
        BucketCommands::Create { bucket } => {
            s3.create_bucket(&bucket).await?;
            output::print(&json!({"bucket":bucket,"created":true}), json_output)
        }
        BucketCommands::Head { bucket } => {
            s3.head_bucket(&bucket).await?;
            output::print(&json!({"bucket":bucket,"exists":true}), json_output)
        }
        BucketCommands::Delete { bucket } => {
            s3.delete_bucket(&bucket).await?;
            output::print(&json!({"bucket":bucket,"deleted":true}), json_output)
        }
        BucketCommands::List => {
            let bucket=profile.bucket.clone().ok_or_else(||anyhow!("Pipe's gateway does not support ListBuckets; specify a bucket or configure profile.bucket"))?;
            s3.head_bucket(&bucket).await?;
            output::print(&json!({"items":[bucket]}), json_output)
        }
    }
}

async fn object_command(
    client: &ControlClient,
    store: &ConfigStore,
    name: &str,
    profile: &Profile,
    command: ObjectCommands,
    json_output: bool,
) -> Result<()> {
    match command {
        ObjectCommands::Put {
            local_file,
            destination,
            encrypt,
            password,
            upload_id,
        } => {
            put_file_command(
                client,
                store,
                name,
                profile,
                &local_file,
                &destination,
                encrypt,
                password.as_deref(),
                upload_id.as_deref(),
                json_output,
            )
            .await
        }
        ObjectCommands::Get {
            remote,
            local_file,
            decrypt,
            password,
            range,
        } => {
            get_file_command(
                client,
                store,
                name,
                profile,
                &remote,
                &local_file,
                decrypt,
                password.as_deref(),
                range.as_deref(),
                json_output,
            )
            .await
        }
        ObjectCommands::Head { remote } => {
            let (bucket, key) = remote_location(profile, &remote)?;
            let s3 = s3_client(client, store, name, profile).await?;
            output::print(&s3.head_object(&bucket, &key).await?, json_output)
        }
        ObjectCommands::Delete { remote } => {
            let (bucket, key) = remote_location(profile, &remote)?;
            let s3 = s3_client(client, store, name, profile).await?;
            s3.delete_object(&bucket, &key).await?;
            output::print(
                &json!({"bucket":bucket,"key":key,"deleted":true}),
                json_output,
            )
        }
        ObjectCommands::List { bucket, prefix } => {
            let s3 = s3_client(client, store, name, profile).await?;
            let mut token = None;
            let mut seen = std::collections::HashSet::new();
            loop {
                let (items, next) = s3
                    .list_objects(&bucket, Some(&prefix), token.as_deref())
                    .await?;
                output::print(&json!({"items":items,"next":next}), json_output)?;
                match next {
                    Some(next) if seen.insert(next.clone()) => token = Some(next),
                    Some(_) => return Err(anyhow!("S3 returned a repeated continuation token")),
                    None => break,
                }
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn put_file_command(
    client: &ControlClient,
    store: &ConfigStore,
    name: &str,
    profile: &Profile,
    local: &str,
    destination: &str,
    encrypt: bool,
    password: Option<&str>,
    upload_id: Option<&str>,
    json_output: bool,
) -> Result<()> {
    let (bucket, key) = remote_location(profile, destination)?;
    let s3 = s3_client(client, store, name, profile).await?;
    let mut path = PathBuf::from(local);
    let mut temporary = None;
    if encrypt {
        // Keep the exact randomized ciphertext across interruption and resume.
        let source = std::fs::canonicalize(local)?;
        let identity = crate::sigv4::sha256_hex(
            serde_json::to_string(&(source, &bucket, &key, &profile.s3_endpoint))?.as_bytes(),
        );
        let directory = client.secrets.state_directory().join("encrypted-uploads");
        std::fs::create_dir_all(&directory)?;
        let spool = directory.join(format!("{identity}.enc"));
        let manifest = directory.join(format!("{identity}.json"));
        let digest = hash_local(Path::new(local))?;
        if upload_id.is_some() {
            let saved: Value =
                serde_json::from_slice(&std::fs::read(&manifest).map_err(|_| {
                    anyhow!(
                        "encrypted resume requires the original ciphertext spool in this profile"
                    )
                })?)?;
            if saved["source_hash"] != digest || !spool.is_file() {
                return Err(anyhow!(
                    "local file changed or encrypted resume spool is missing"
                ));
            }
        } else {
            let password = password_value(password, "Encryption password: ")?;
            crypto::encrypt_file(Path::new(local), &spool, &password)?;
            crate::keyring::atomic_private_write(
                &manifest,
                &serde_json::to_vec(&json!({"source_hash":digest}))?,
            )?;
        }
        path = spool.clone();
        temporary = Some((spool, manifest));
    }
    let upload_result = s3
        .put_file_resumable(&bucket, &key, &path, None, upload_id)
        .await;
    if upload_result.is_ok() {
        if let Some((spool, manifest)) = temporary {
            std::fs::remove_file(spool)?;
            std::fs::remove_file(manifest)?;
        }
    }
    upload_result?;
    output::print(
        &json!({"bucket":bucket,"key":key,"uploaded":true}),
        json_output,
    )
}

#[allow(clippy::too_many_arguments)]
async fn get_file_command(
    client: &ControlClient,
    store: &ConfigStore,
    name: &str,
    profile: &Profile,
    remote: &str,
    local: &str,
    decrypt: bool,
    password: Option<&str>,
    range: Option<&str>,
    json_output: bool,
) -> Result<()> {
    let (bucket, key) = remote_location(profile, remote)?;
    let s3 = s3_client(client, store, name, profile).await?;
    let parsed_range = parse_range(range)?;
    if decrypt && parsed_range.is_some() {
        return Err(anyhow!(
            "local encryption requires a complete object; omit --range when using --decrypt"
        ));
    }
    let target = PathBuf::from(local);
    let mut temporary = None;
    let output_path = if decrypt {
        let temp = tempfile::NamedTempFile::new()?.into_temp_path();
        let path = temp.to_path_buf();
        temporary = Some(temp);
        path
    } else {
        target.clone()
    };
    let bytes = match s3
        .get_to_file(&bucket, &key, &output_path, parsed_range)
        .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            if let Some(path) = temporary.as_ref() {
                let _ = std::fs::remove_file(path);
            }
            return Err(error);
        }
    };
    if decrypt {
        let password = password_value(password, "Decryption password: ")?;
        let decrypt_result = crypto::decrypt_file(temporary.as_ref().unwrap(), &target, &password);
        let _ = std::fs::remove_file(temporary.unwrap());
        decrypt_result?;
    }
    output::print(
        &json!({"bucket":bucket,"key":key,"path":local,"bytes":bytes,"downloaded":true}),
        json_output,
    )
}

fn password_value(file: Option<&str>, prompt: &str) -> Result<zeroize::Zeroizing<String>> {
    let value = match file {
        Some(file) => std::fs::read_to_string(file)?
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
        None => {
            output::require_input()?;
            rpassword::prompt_password(prompt)?
        }
    };
    if value.is_empty() {
        return Err(anyhow!("password cannot be empty"));
    }
    Ok(zeroize::Zeroizing::new(value))
}

fn hash_local(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hash = blake3::Hasher::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash.finalize().to_hex().to_string())
}

fn validate_access_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(anyhow!("invalid S3 access key ID"));
    }
    Ok(())
}

fn store_credential(client: &ControlClient, value: &Value) -> Result<()> {
    let access = value["access_key_id"]
        .as_str()
        .ok_or_else(|| anyhow!("credential response omitted access key ID"))?;
    validate_access_key(access)?;
    let secret = value["secret_access_key"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("credential response omitted secret"))?;
    client.save_s3_secret(access, secret)?;
    client.secrets.set("s3_access_key", access)
}

async fn rotate_credential(client: &ControlClient, access: &str, json_output: bool) -> Result<()> {
    validate_access_key(access)?;
    let credentials = account::credentials(client).await?;
    let prior = credentials["items"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["access_key_id"] == access && item["revoked_at"].is_null())
        })
        .ok_or_else(|| anyhow!("active S3 credential was not found"))?;
    let wallet = prior["wallet"]
        .as_str()
        .ok_or_else(|| anyhow!("credential wallet missing"))?;
    let buckets: Vec<String> = serde_json::from_value(prior["buckets"].clone())?;
    let permissions: Vec<String> = serde_json::from_value(prior["permissions"].clone())?;
    let mut new = account::create_credential(
        client,
        wallet,
        prior["label"].as_str().unwrap_or("cli"),
        &buckets,
        prior["key_prefix"].as_str().unwrap_or(""),
        &permissions,
        None,
    )
    .await?;
    store_credential(client, &new)?;
    match account::revoke_credential(client, access).await {
        Ok(_) => {
            client.secrets.delete(&format!("s3:{access}"))?;
            new["previous_revoked"] = json!(true);
        }
        Err(_) => {
            new["previous_revoked"] = json!(false);
            eprintln!("new credential is stored and active; revocation of {access} failed; retry 'pipe s3 credential revoke {access}'");
            output::print_credential(&new, json_output)?;
            return Err(anyhow!(
                "credential rotation requires revocation of the previous key"
            ));
        }
    }
    output::print_credential(&new, json_output)
}

async fn sync_command(
    client: &ControlClient,
    store: &ConfigStore,
    name: &str,
    profile: &Profile,
    source: &str,
    destination: &str,
    json_output: bool,
) -> Result<()> {
    if Path::new(source).is_dir() {
        let (bucket, prefix) = remote_prefix(profile, destination)?;
        let s3 = s3_client(client, store, name, profile).await?;
        let count = sync::sync_upload(
            &s3,
            Path::new(source),
            &bucket,
            &prefix,
            client.secrets.state_directory(),
        )
        .await?;
        output::print(&json!({"uploaded":count}), json_output)
    } else {
        if !source.starts_with("s3://") {
            return Err(anyhow!(
                "sync source must be an existing local directory or s3://bucket/prefix"
            ));
        }
        let (bucket, prefix) = remote_prefix(profile, source)?;
        let s3 = s3_client(client, store, name, profile).await?;
        let count = sync::sync_download(
            &s3,
            &bucket,
            &prefix,
            Path::new(destination),
            client.secrets.state_directory(),
        )
        .await?;
        output::print(&json!({"downloaded":count}), json_output)
    }
}

async fn s3_client(
    client: &ControlClient,
    _store: &ConfigStore,
    _name: &str,
    profile: &Profile,
) -> Result<S3Client> {
    let access = client.secrets.get("s3_access_key")?.ok_or_else(|| {
        anyhow!("no active S3 credential; create one with 'pipe s3 credential create'")
    })?;
    let secret = client.s3_secret(&access)?;
    S3Client::from_parts(profile, &access, secret)?
        .with_conditions(client.if_match.clone(), client.if_none_match.clone())
        .map(|s3| {
            s3.with_progress(client.progress)
                .with_state_directory(client.secrets.state_directory().join("uploads"))
        })
}

fn remote_location(profile: &Profile, value: &str) -> Result<(String, String)> {
    let value = value.strip_prefix("s3://").unwrap_or(value);
    let (bucket, key) = if let Some((bucket, key)) = value.split_once('/') {
        (bucket.to_owned(), key.to_owned())
    } else {
        (
            profile.bucket.clone().ok_or_else(|| {
                anyhow!("destination must be bucket/key or profile.bucket must be set")
            })?,
            sync::join_key(profile.prefix.as_deref().unwrap_or(""), value),
        )
    };
    if bucket.len() < 3 || bucket.len() > 63 || key.is_empty() {
        return Err(anyhow!("object location must be bucket/key"));
    }
    Ok((bucket, key))
}

fn remote_prefix(profile: &Profile, value: &str) -> Result<(String, String)> {
    if let Some(value) = value.strip_prefix("s3://") {
        let (bucket, prefix) = value.split_once('/').unwrap_or((value, ""));
        if bucket.len() < 3 || bucket.len() > 63 {
            return Err(anyhow!("remote location requires a bucket"));
        }
        return Ok((bucket.to_owned(), prefix.to_owned()));
    }
    remote_location(profile, value)
}
fn parse_range(value: Option<&str>) -> Result<Option<(u64, u64)>> {
    let Some(value) = value else { return Ok(None) };
    let (a, b) = value
        .split_once('-')
        .ok_or_else(|| anyhow!("range must be START-END"))?;
    let start: u64 = a.parse()?;
    let end: u64 = b.parse()?;
    if end
        .checked_sub(start)
        .and_then(|v| v.checked_add(1))
        .is_none_or(|len| len > crate::s3::MAX_RANGE_BYTES)
    {
        return Err(anyhow!("range must be at most 32 MiB"));
    }
    Ok(Some((start, end)))
}
fn parse_usdc(value: &str) -> Result<u64> {
    let value = value.trim().trim_start_matches('$');
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 6
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(anyhow!(
            "amount must be a non-negative USDC value with at most 6 decimals"
        ));
    }
    let whole: u64 = whole.parse()?;
    let fraction = format!("{fraction:0<6}").parse::<u64>().unwrap_or(0);
    whole
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(fraction))
        .ok_or_else(|| anyhow!("amount is too large"))
}

async fn profile_command(cli: &Cli, command: &ProfileCommands) -> Result<()> {
    let mut store = ConfigStore::load(cli.config.as_deref())?;
    match command {
        ProfileCommands::Create {
            name,
            control_api_url,
            s3_endpoint,
            region,
            bucket,
            prefix,
        } => {
            if store.file.profiles.contains_key(name) {
                return Err(anyhow!("profile '{name}' already exists"));
            }
            let mut profile = Profile::new(
                control_api_url
                    .clone()
                    .unwrap_or_else(|| crate::config::default_api_url().into()),
            );
            profile.s3_endpoint = s3_endpoint.clone();
            profile.region = region.clone();
            profile.bucket = bucket.clone();
            profile.prefix = prefix.clone();
            profile.validate()?;
            store.file.profiles.insert(name.clone(), profile);
            store.save()?;
            output::print(&json!({"profile":name,"created":true}), cli.json)
        }
        ProfileCommands::Use { name } => {
            if !store.file.profiles.contains_key(name) {
                return Err(anyhow!("profile '{name}' does not exist"));
            }
            store.file.active_profile = Some(name.clone());
            store.save()?;
            output::print(&json!({"profile":name,"active":true}), cli.json)
        }
        ProfileCommands::Show { name } => {
            let selected = store.active_name(name.as_deref());
            let profile = store
                .file
                .profiles
                .get(&selected)
                .ok_or_else(|| anyhow!("profile '{selected}' does not exist"))?;
            profile.validate()?;
            output::print(
                &json!({"active":store.file.active_profile.as_deref() == Some(selected.as_str()),"profile":selected,"settings":profile}),
                cli.json,
            )
        }
        ProfileCommands::Set {
            name,
            control_api_url,
            s3_endpoint,
            region,
            bucket,
            prefix,
            clear_bucket,
            clear_prefix,
            clear_s3_endpoint,
        } => {
            anyhow::ensure!(
                control_api_url.is_some()
                    || s3_endpoint.is_some()
                    || region.is_some()
                    || bucket.is_some()
                    || prefix.is_some()
                    || *clear_bucket
                    || *clear_prefix
                    || *clear_s3_endpoint,
                "profile set requires at least one setting"
            );
            let selected = store.active_name(name.as_deref());
            let profile = store
                .file
                .profiles
                .get(&selected)
                .cloned()
                .ok_or_else(|| anyhow!("profile '{selected}' does not exist"))?;
            let mut updated = profile;
            if let Some(value) = control_api_url {
                updated.control_api_url = value.clone();
            }
            if let Some(value) = s3_endpoint {
                updated.s3_endpoint = Some(value.clone());
            }
            if let Some(value) = region {
                updated.region = value.clone();
            }
            if let Some(value) = bucket {
                updated.bucket = Some(value.clone());
            }
            if let Some(value) = prefix {
                updated.prefix = Some(value.clone());
            }
            if *clear_bucket {
                updated.bucket = None;
            }
            if *clear_prefix {
                updated.prefix = None;
            }
            if *clear_s3_endpoint {
                updated.s3_endpoint = None;
            }
            updated.validate()?;
            store.file.profiles.insert(selected.clone(), updated);
            store.save()?;
            output::print(&json!({"profile":selected,"updated":true}), cli.json)
        }
        ProfileCommands::List => {
            let items = store.file.profiles.keys().collect::<Vec<_>>();
            output::print(
                &json!({"active":store.file.active_profile,"profiles":items}),
                cli.json,
            )
        }
    }
}
fn config_command(cli: &Cli, command: &ConfigCommands) -> Result<()> {
    let mut store = ConfigStore::load(cli.config.as_deref())?;
    match command {
        ConfigCommands::Show => output::print(&store.file, cli.json),
        ConfigCommands::Backup { destination } => {
            store.backup(destination)?;
            output::print(
                &json!({"backup":destination,"journals":"preserved","secrets":"preserved"}),
                cli.json,
            )
        }
        ConfigCommands::Rollback { backup } => {
            if !cli.yes {
                return Err(anyhow!("configuration rollback requires --yes"));
            }
            let previous = store.rollback(backup)?;
            output::print(
                &json!({"restored":true,"previous_configuration":previous,"journals":"preserved","secrets":"preserved"}),
                cli.json,
            )
        }
        ConfigCommands::Migrate { legacy_path } => {
            let path = legacy_path.clone().map(PathBuf::from).unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".pipe-cli.json")
            });
            let backup = store.migrate_legacy(&path)?;
            output::print(&json!({"migrated":true,"backup":backup}), cli.json)
        }
    }
}

fn destructive(command: &Commands) -> bool {
    if let Commands::Account {
        command: Some(command),
    } = command
    {
        return crate::customer::account_confirmation(command);
    }
    if let Commands::Billing { command } = command {
        return crate::customer::billing_confirmation(command);
    }
    if let Commands::Org { command } = command {
        return crate::customer::org_confirmation(command);
    }
    if let Commands::Hosting { command } = command {
        return crate::hosting::needs_confirmation(command);
    }
    if let Commands::Durable { command } = command {
        return crate::durable::needs_confirmation(command);
    }
    if let Commands::Kv { command } = command {
        return crate::kv::needs_confirmation(command);
    }
    if let Commands::Compute { command } = command {
        return crate::compute::needs_confirmation(command);
    }
    matches!(
        command,
        Commands::Bucket {
            command: BucketCommands::Delete { .. },
        } | Commands::Object {
            command: ObjectCommands::Delete { .. },
        } | Commands::Storage {
            command: StorageCommands::Bucket {
                command: BucketCommands::Delete { .. },
            },
        } | Commands::Storage {
            command: StorageCommands::Object {
                command: ObjectCommands::Delete { .. },
            },
        } | Commands::S3 {
            command: S3Commands::Remove { .. } | S3Commands::RemoveBucket { .. },
        } | Commands::Storage {
            command: StorageCommands::S3 {
                command: S3Commands::Remove { .. } | S3Commands::RemoveBucket { .. },
            },
        } | Commands::Payments {
            command: PaymentCommands::Pay { .. }
                | PaymentCommands::Submit { .. }
                | PaymentCommands::SubmitX402 { .. },
        } | Commands::Credentials {
            command: crate::platform::CredentialCommands::Revoke { .. },
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn current_command_surface_parses() {
        for args in [
            &["pipe", "auth", "login"][..],
            &["pipe", "login"][..],
            &["pipe", "logout"][..],
            &["pipe", "whoami"][..],
            &["pipe", "auth", "status"][..],
            &["pipe", "profile", "create", "personal"][..],
            &["pipe", "profile", "show"][..],
            &["pipe", "profile", "set", "--bucket", "bucket"][..],
            &["pipe", "s3", "credential", "list"][..],
            &["pipe", "s3", "credentials", "list"][..],
            &["pipe", "s3", "ls"][..],
            &["pipe", "s3", "ls", "s3://bucket/prefix"][..],
            &["pipe", "s3", "list"][..],
            &["pipe", "s3", "cp", "file", "s3://bucket/key"][..],
            &["pipe", "s3", "sync", "./local", "s3://bucket/prefix"][..],
            &["pipe", "s3", "rm", "s3://bucket/key"][..],
            &["pipe", "s3", "mb", "bucket"][..],
            &["pipe", "s3", "rb", "bucket"][..],
            &["pipe", "s3", "stat", "s3://bucket/key"][..],
            &["pipe", "bucket", "ls"][..],
            &["pipe", "bucket", "rm", "bucket"][..],
            &["pipe", "object", "rm", "bucket/key"][..],
            &["pipe", "object", "put", "file", "bucket/key"][..],
            &["pipe", "upload-file", "file", "bucket/key"][..],
        ] {
            Cli::try_parse_from(args).expect("current command should parse");
        }
    }

    #[test]
    fn legacy_commands_are_rejected() {
        for args in [
            &["pipe", "new-user", "name"][..],
            &["pipe", "sync-deposits"][..],
            &["pipe", "check-token"][..],
            &["pipe", "create-public-link", "key"][..],
        ] {
            assert!(
                Cli::try_parse_from(args).is_err(),
                "legacy command unexpectedly accepted: {args:?}"
            );
        }
    }

    #[test]
    fn active_profile_is_used_without_explicit_override() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("config.json");
        let mut store = ConfigStore::load(file.to_str()).unwrap();
        store
            .file
            .profiles
            .insert("work".into(), Profile::new("https://example.test"));
        store.file.active_profile = Some("work".into());
        store.save().unwrap();
        let cli =
            Cli::try_parse_from(["pipe", "--config", file.to_str().unwrap(), "account"]).unwrap();
        assert_eq!(context(&cli).unwrap().1, "work");
    }

    #[test]
    fn range_arithmetic_cannot_overflow() {
        assert!(parse_range(Some("0-18446744073709551615")).is_err());
        assert!(parse_range(Some("4-3")).is_err());
        assert_eq!(
            parse_range(Some("0-33554431")).unwrap(),
            Some((0, 33554431))
        );
    }

    #[test]
    fn remote_keys_preserve_trailing_slashes_and_s3_scheme() {
        let mut profile = Profile::new("https://example.test");
        profile.bucket = Some("default".into());
        profile.prefix = Some("root".into());
        assert_eq!(
            remote_location(&profile, "s3://bucket/a/").unwrap(),
            ("bucket".into(), "a/".into())
        );
        assert_eq!(
            remote_location(&profile, "one").unwrap(),
            ("default".into(), "root/one".into())
        );
    }
}

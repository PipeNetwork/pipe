use crate::{
    auth::ControlClient,
    compute_journal::ContextBinding,
    error::ApiError,
    kv_state::{Credential, Intent, State},
    output, platform,
};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Subcommand};
use pipe_transports::kv::{self as transport, Command, Reply};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
#[derive(Subcommand, Debug)]
pub enum Commands {
    Pricing,
    #[command(alias = "instance")]
    Instances {
        #[command(subcommand)]
        command: Option<Instances>,
    },
    #[command(alias = "credential")]
    Credentials {
        #[command(subcommand)]
        command: Option<Credentials>,
    },
    Connection {
        credential: Uuid,
    },
    Get {
        key: String,
        #[arg(long)]
        destination: Option<PathBuf>,
        #[command(flatten)]
        connection: Connection,
    },
    Set {
        key: String,
        #[arg(
            long,
            required_unless_present = "value_file",
            conflicts_with = "value_file"
        )]
        value: Option<String>,
        #[arg(long)]
        value_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "xx")]
        nx: bool,
        #[arg(long)]
        xx: bool,
        #[arg(long, conflicts_with = "px")]
        ex: Option<u64>,
        #[arg(long)]
        px: Option<u64>,
        #[command(flatten)]
        connection: Connection,
    },
    Mget {
        #[arg(required=true,num_args=1..=128)]
        keys: Vec<String>,
        #[command(flatten)]
        connection: Connection,
    },
    Delete {
        #[arg(required=true,num_args=1..=128)]
        keys: Vec<String>,
        #[command(flatten)]
        connection: Connection,
    },
    Exists {
        #[arg(required=true,num_args=1..=128)]
        keys: Vec<String>,
        #[command(flatten)]
        connection: Connection,
    },
    Scan {
        #[arg(long, default_value_t = 0)]
        cursor: u64,
        #[arg(long)]
        pattern: Option<String>,
        #[arg(long,default_value_t=10,value_parser=clap::value_parser!(u32).range(1..=256))]
        count: u32,
        #[arg(long)]
        all: bool,
        #[arg(long,default_value_t=1000,value_parser=clap::value_parser!(u32).range(1..=1000))]
        max_pages: u32,
        #[command(flatten)]
        connection: Connection,
    },
    Incr {
        key: String,
        #[arg(long, default_value_t = 1, allow_hyphen_values = true)]
        by: i64,
        #[command(flatten)]
        connection: Connection,
    },
    Decr {
        key: String,
        #[arg(long, default_value_t = 1, allow_hyphen_values = true)]
        by: i64,
        #[command(flatten)]
        connection: Connection,
    },
    Ttl {
        key: String,
        #[arg(long)]
        milliseconds: bool,
        #[command(flatten)]
        connection: Connection,
    },
    Expire {
        key: String,
        #[arg(allow_hyphen_values = true)]
        duration: i64,
        #[arg(long)]
        milliseconds: bool,
        #[command(flatten)]
        connection: Connection,
    },
    Persist {
        key: String,
        #[command(flatten)]
        connection: Connection,
    },
    Requests,
    /// Retry only a management intent with its original resource ID and secret.
    Resume {
        request_id: Uuid,
    },
    /// Record that you inspected an uncertain data mutation; never replays it.
    Acknowledge {
        request_id: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum Instances {
    List,
    Get {
        id: Uuid,
    },
    Create {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    Delete {
        id: Uuid,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
}
#[derive(Subcommand, Debug)]
pub enum Credentials {
    List,
    Create {
        instance: Uuid,
        #[arg(long, default_value = "")]
        label: String,
        #[arg(long,value_parser=clap::value_parser!(u8).range(1..=3))]
        permissions: u8,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    Revoke {
        id: Uuid,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    /// Save an existing product credential in the selected secure store.
    Import {
        id: Uuid,
        #[arg(long)]
        secret_file: PathBuf,
        #[arg(long)]
        endpoint: String,
    },
    /// Reveal the stored credential only with the global --show-secret option.
    Export {
        id: Uuid,
    },
}
#[derive(Args, Debug, Clone)]
pub struct Connection {
    #[arg(long, env = "PIPE_KV_CREDENTIAL")]
    credential: Uuid,
    /// Additional trusted CA certificates; TLS name verification remains required.
    #[arg(long, env = "PIPE_KV_CA_CERT")]
    ca_cert: Option<PathBuf>,
    #[arg(long,default_value_t=15,value_parser=clap::value_parser!(u64).range(1..=120))]
    timeout: u64,
    /// Decode key and MATCH arguments from base64, preserving arbitrary bytes.
    #[arg(long)]
    base64_keys: bool,
}
pub fn needs_confirmation(cmd: &Commands) -> bool {
    matches!(
        cmd,
        Commands::Resume { .. }
            | Commands::Acknowledge { .. }
            | Commands::Delete { .. }
            | Commands::Instances {
                command: Some(Instances::Create { .. } | Instances::Delete { .. })
            }
            | Commands::Credentials {
                command: Some(Credentials::Create { .. } | Credentials::Revoke { .. })
            }
    )
}
#[derive(Debug, thiserror::Error)]
#[error("KV outcome unknown for request {id}; inspect pipe kv requests. Management requests can use pipe kv resume; data mutations must be inspected before acknowledgement and are never replayed")]
pub struct Unknown {
    pub id: Uuid,
}
async fn read(c: &ControlClient, id: &str, path: &str) -> Result<Value> {
    let v = c.get(path).await?;
    platform::validate_response(id, "200", &v)?;
    Ok(v)
}
async fn binding(c: &ControlClient) -> Result<ContextBinding> {
    let v = read(c, "platformCliContext", "/v1/cli/context").await?;
    Ok(ContextBinding {
        endpoint: c.url(""),
        owner_wallet: v["principal"]["owner_wallet"]
            .as_str()
            .context("missing owner")?
            .into(),
        account_id: v["principal"]["account_id"].as_str().map(str::to_owned),
    })
}
fn bounded_file(path: &Path, max: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut data = Vec::new();
    if path == Path::new("-") {
        std::io::stdin()
            .take(max as u64 + 1)
            .read_to_end(&mut data)?;
    } else {
        std::fs::File::open(path)?
            .take(max as u64 + 1)
            .read_to_end(&mut data)?;
    }
    ensure!(data.len() <= max, "input exceeds {max} bytes");
    Ok(data)
}
fn key(s: String, connection: &Connection) -> Result<Vec<u8>> {
    if connection.base64_keys {
        Ok(STANDARD.decode(s)?)
    } else {
        Ok(s.into_bytes())
    }
}
fn binary(v: &Option<Vec<u8>>) -> Value {
    v.as_ref()
        .map(|b| json!({"base64":STANDARD.encode(b),"bytes":b.len()}))
        .unwrap_or(Value::Null)
}
fn present(reply: &Reply) -> Value {
    match reply {
        Reply::Bulk(v) => binary(v),
        Reply::Integer(v) => json!({"integer":v.to_string()}),
        Reply::Simple(v) => json!({"status":String::from_utf8_lossy(v)}),
        Reply::Array(v) => Value::Array(v.iter().map(present).collect()),
    }
}
async fn data(
    c: &ControlClient,
    connection: &Connection,
    args: Vec<Vec<u8>>,
) -> Result<(Reply, Option<Uuid>)> {
    let command = Command::new(args)?;
    let mut state = State::load(c)?;
    let credential = state
        .credentials
        .get(&connection.credential)
        .context("KV credential is not saved in this profile; create or import it")?
        .clone();
    let endpoint = transport::Endpoint::parse(&credential.endpoint)?;
    let tls = transport::tls_config(connection.ca_cert.as_deref())?;
    let id = command.mutation.then(Uuid::new_v4);
    if let Some(id) = id {
        state.prepare(
            c,
            None,
            Intent::Data {
                endpoint: credential.endpoint.clone(),
                credential: credential.id,
                command: command.name().into(),
                sha256: crate::sigv4::sha256_hex(&command.encoded()),
            },
            id,
        )?;
        eprintln!("KV mutation {id} saved before forwarding");
    }
    let result = transport::execute(
        &endpoint,
        tls,
        &credential.id.to_string(),
        &credential.secret,
        &command,
        Duration::from_secs(connection.timeout),
    )
    .await;
    if let Some(id) = id {
        match &result {
            Ok(_) => state
                .finish(c, id, "accepted", None)
                .map_err(|_| Unknown { id })?,
            Err(e)
                if matches!(
                    e.downcast_ref::<transport::Error>(),
                    Some(transport::Error::Unknown) | None
                ) =>
            {
                return Err(Unknown { id }.into())
            }
            Err(_) => state.finish(c, id, "rejected", None)?,
        }
    }
    Ok((result?, id))
}
async fn manage(c: &ControlClient, intent: Option<Intent>, id: Uuid, j: bool) -> Result<()> {
    let context = binding(c).await?;
    let mut state = State::load(c)?;
    if let Some(intent) = intent {
        state.prepare(c, Some(context.clone()), intent, id)?;
    }
    let entry = state
        .requests
        .get(&id)
        .context("no saved KV request with this ID")?
        .clone();
    ensure!(
        entry.context.as_ref() == Some(&context),
        "KV request belongs to another account or endpoint"
    );
    ensure!(
        entry.state != "rejected",
        "KV request was rejected; correct the cause and use a new request ID"
    );
    if let Some(v) = entry.response {
        return output::print(&json!({"request_id":id,"response":v}), j);
    }
    let (operation, path, body, method) = match &entry.intent {
        Intent::CreateInstance { wallet, id } => (
            "createKvInstance",
            "/v1/customer/kv/instances".into(),
            serde_json::to_value(pipe_api::kv::CreateInstance {
                wallet: wallet.clone(),
                id: *id,
            })?,
            reqwest::Method::POST,
        ),
        Intent::DeleteInstance { id } => (
            "deleteKvInstance",
            format!("/v1/customer/kv/instances/{id}"),
            json!({}),
            reqwest::Method::DELETE,
        ),
        Intent::CreateCredential {
            instance,
            id,
            label,
            permissions,
        } => {
            let secret = state
                .credentials
                .get(id)
                .context("credential material is missing; preserve recovery state")?
                .secret
                .clone();
            (
                "createKvCredential",
                "/v1/customer/kv/credentials".into(),
                serde_json::to_value(pipe_api::kv::CreateCredential {
                    instance: *instance,
                    credential_id: *id,
                    label: label.clone(),
                    permissions: *permissions,
                    secret,
                })?,
                reqwest::Method::POST,
            )
        }
        Intent::RevokeCredential { id } => (
            "revokeKvCredential",
            format!("/v1/customer/kv/credentials/{id}"),
            json!({}),
            reqwest::Method::DELETE,
        ),
        Intent::Data { .. } => anyhow::bail!(
            "data mutations cannot be resumed; inspect their outcome before acknowledgement"
        ),
    };
    if method == reqwest::Method::POST {
        let (_, _, op) = platform::operation(operation)?;
        platform::validate(
            &op["requestBody"]["content"]["application/json"]["schema"],
            &body,
        )?;
    }
    eprintln!("KV management request {id} saved; recover with: pipe kv resume {id} --yes");
    let result = c
        .send_idempotent(method, &path, body, id, reqwest::StatusCode::OK)
        .await;
    let mut v = match result {
        Ok(v) => v,
        Err(e) => {
            if e.downcast_ref::<ApiError>()
                .is_some_and(|e| matches!(e.status.as_u16(), 400 | 401 | 403 | 404 | 409 | 422))
            {
                state.finish(c, id, "rejected", None)?;
                return Err(e);
            }
            return Err(Unknown { id }.into());
        }
    };
    let verify = || -> Result<()> {
        platform::validate_response(operation, "200", &v)?;
        match &entry.intent {
            Intent::CreateInstance { wallet, id } => {
                let r: pipe_api::kv::InstanceReceipt = serde_json::from_value(v.clone())?;
                ensure!(
                    r.id == *id && r.wallet == *wallet,
                    "KV instance receipt mismatch"
                );
            }
            Intent::CreateCredential {
                instance,
                id,
                permissions,
                ..
            } => {
                let r: pipe_api::kv::CredentialReceipt = serde_json::from_value(v.clone())?;
                ensure!(
                    r.credential_id == *id
                        && r.instance == *instance
                        && r.permissions == *permissions
                        && r.secret == state.credentials[id].secret,
                    "KV credential receipt mismatch"
                );
            }
            Intent::DeleteInstance { id } => ensure!(
                v["id"] == id.to_string() && v["deleted"] == true,
                "KV deletion receipt mismatch"
            ),
            Intent::RevokeCredential { id } => ensure!(
                v["credential_id"] == id.to_string() && v["revoked"] == true,
                "KV revocation receipt mismatch"
            ),
            _ => unreachable!(),
        }
        Ok(())
    };
    verify().map_err(|_| Unknown { id })?;
    if let Some(object) = v.as_object_mut() {
        object.remove("secret");
    }
    state
        .finish(c, id, "accepted", Some(v.clone()))
        .map_err(|_| Unknown { id })?;
    output::print(&json!({"request_id":id,"response":v}), j)
}
pub async fn run(c: &ControlClient, cmd: Commands, j: bool) -> Result<()> {
    let (connection, args, destination) = match cmd {
        Commands::Pricing => {
            return output::print(&read(c, "getKvPricing", "/v1/kv/pricing").await?, j)
        }
        Commands::Instances {
            command: None | Some(Instances::List),
        } => {
            return output::print(
                &read(c, "listKvInstances", "/v1/customer/kv/instances").await?,
                j,
            )
        }
        Commands::Instances {
            command: Some(Instances::Get { id }),
        } => {
            let v = read(c, "listKvInstances", "/v1/customer/kv/instances").await?;
            return output::print(
                v["instances"]
                    .as_array()
                    .context("missing instances")?
                    .iter()
                    .find(|v| v["id"] == id.to_string())
                    .context("owned KV instance not found")?,
                j,
            );
        }
        Commands::Instances {
            command: Some(Instances::Create { wallet, request_id }),
        } => {
            let id = request_id.unwrap_or_else(Uuid::new_v4);
            return manage(
                c,
                Some(Intent::CreateInstance {
                    wallet: canonical_wallet(&wallet)?,
                    id,
                }),
                id,
                j,
            )
            .await;
        }
        Commands::Instances {
            command: Some(Instances::Delete { id, request_id }),
        } => {
            return manage(
                c,
                Some(Intent::DeleteInstance { id }),
                request_id.unwrap_or_else(Uuid::new_v4),
                j,
            )
            .await
        }
        Commands::Credentials {
            command: None | Some(Credentials::List),
        } => {
            return output::print(
                &read(c, "listKvCredentials", "/v1/customer/kv/credentials").await?,
                j,
            )
        }
        Commands::Credentials {
            command:
                Some(Credentials::Create {
                    instance,
                    label,
                    permissions,
                    request_id,
                }),
        } => {
            ensure!(label.len() <= 128, "credential label exceeds 128 bytes");
            let id = request_id.unwrap_or_else(Uuid::new_v4);
            let mut s = State::load(c)?;
            if let Some(old) = s.credentials.get(&id) {
                ensure!(
                    old.instance == Some(instance) && old.permissions == Some(permissions),
                    "credential ID is already bound to another instance or permissions"
                );
            } else {
                let price: pipe_api::kv::Pricing =
                    serde_json::from_value(read(c, "getKvPricing", "/v1/kv/pricing").await?)?;
                let endpoint = price.endpoint.context("KV endpoint is not available")?;
                transport::Endpoint::parse(&endpoint)?;
                s.credentials.insert(
                    id,
                    Credential {
                        id,
                        secret: hex::encode(rand::random::<[u8; 32]>()),
                        endpoint,
                        instance: Some(instance),
                        permissions: Some(permissions),
                    },
                );
                s.save(c)?;
            }
            return manage(
                c,
                Some(Intent::CreateCredential {
                    instance,
                    id,
                    label,
                    permissions,
                }),
                id,
                j,
            )
            .await;
        }
        Commands::Credentials {
            command: Some(Credentials::Revoke { id, request_id }),
        } => {
            return manage(
                c,
                Some(Intent::RevokeCredential { id }),
                request_id.unwrap_or_else(Uuid::new_v4),
                j,
            )
            .await
        }
        Commands::Credentials {
            command:
                Some(Credentials::Import {
                    id,
                    secret_file,
                    endpoint,
                }),
        } => {
            transport::Endpoint::parse(&endpoint)?;
            let secret = String::from_utf8(bounded_file(&secret_file, 128)?)?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            ensure!(
                secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit()),
                "KV secret must be 32-byte hexadecimal"
            );
            let mut s = State::load(c)?;
            if let Some(old) = s.credentials.get(&id) {
                ensure!(
                    old.secret == secret && old.endpoint == endpoint,
                    "credential already bound to different material or endpoint"
                );
            } else {
                s.credentials.insert(
                    id,
                    Credential {
                        id,
                        secret,
                        endpoint,
                        instance: None,
                        permissions: None,
                    },
                );
                s.save(c)?;
            }
            return output::print(&json!({"credential_id":id,"saved":true}), j);
        }
        Commands::Credentials {
            command: Some(Credentials::Export { id }),
        } => {
            let s = State::load(c)?;
            let v = s.credentials.get(&id).context("credential not saved")?;
            return output::print_automation(
                &json!({"credential_id":id,"secret":v.secret,"endpoint":v.endpoint}),
                j,
            );
        }
        Commands::Connection { credential } => {
            let s = State::load(c)?;
            let v = s
                .credentials
                .get(&credential)
                .context("credential not saved")?;
            return output::print(
                &json!({"credential_id":credential,"endpoint":v.endpoint,"instance":v.instance,"protocol":"TLS/RESP2","permissions":v.permissions}),
                j,
            );
        }
        Commands::Requests => return output::print(&State::load(c)?.requests, j),
        Commands::Resume { request_id } => return manage(c, None, request_id, j).await,
        Commands::Acknowledge { request_id } => {
            let mut s = State::load(c)?;
            ensure!(
                matches!(
                    s.requests
                        .get(&request_id)
                        .context("unknown request ID")?
                        .intent,
                    Intent::Data { .. }
                ),
                "only data outcomes can be acknowledged"
            );
            s.finish(c, request_id, "acknowledged_unknown", None)?;
            return output::print(
                &json!({"request_id":request_id,"state":"acknowledged_unknown","replayed":false}),
                j,
            );
        }
        Commands::Get {
            key: k,
            destination,
            connection,
        } => {
            if let Some(p) = &destination {
                ensure!(!p.exists(), "download destination already exists");
            }
            let args = vec![b"GET".to_vec(), key(k, &connection)?];
            (connection, args, destination)
        }
        Commands::Set {
            key: k,
            value,
            value_file,
            nx,
            xx,
            ex,
            px,
            connection,
        } => {
            let v = if let Some(p) = value_file {
                bounded_file(&p, transport::MAX_VALUE)?
            } else {
                value.context("missing value")?.into_bytes()
            };
            let mut a = vec![b"SET".to_vec(), key(k, &connection)?, v];
            if nx {
                a.push(b"NX".to_vec());
            }
            if xx {
                a.push(b"XX".to_vec());
            }
            if let Some(n) = ex {
                a.extend([b"EX".to_vec(), n.to_string().into_bytes()]);
            }
            if let Some(n) = px {
                a.extend([b"PX".to_vec(), n.to_string().into_bytes()]);
            }
            (connection, a, None)
        }
        Commands::Mget { keys, connection } => multi("MGET", keys, connection)?,
        Commands::Delete { keys, connection } => multi("DEL", keys, connection)?,
        Commands::Exists { keys, connection } => multi("EXISTS", keys, connection)?,
        Commands::Incr {
            key: k,
            by,
            connection,
        } => number("INCRBY", k, by, connection)?,
        Commands::Decr {
            key: k,
            by,
            connection,
        } => number("DECRBY", k, by, connection)?,
        Commands::Expire {
            key: k,
            duration,
            milliseconds,
            connection,
        } => number(
            if milliseconds { "PEXPIRE" } else { "EXPIRE" },
            k,
            duration,
            connection,
        )?,
        Commands::Ttl {
            key: k,
            milliseconds,
            connection,
        } => {
            let a = vec![
                if milliseconds {
                    b"PTTL".to_vec()
                } else {
                    b"TTL".to_vec()
                },
                key(k, &connection)?,
            ];
            (connection, a, None)
        }
        Commands::Persist { key: k, connection } => {
            let a = vec![b"PERSIST".to_vec(), key(k, &connection)?];
            (connection, a, None)
        }
        Commands::Scan {
            cursor,
            pattern,
            count,
            all,
            max_pages,
            connection,
        } => return scan(c, connection, cursor, pattern, count, all, max_pages, j).await,
    };
    let (reply, id) = data(c, &connection, args).await?;
    if let Some(path) = destination {
        use std::io::Write;
        let Reply::Bulk(Some(bytes)) = reply else {
            anyhow::bail!("key does not exist; no file written")
        };
        let mut file = tempfile::NamedTempFile::new_in(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(&path)?;
        return output::print(&json!({"destination":path,"bytes":bytes.len()}), j);
    }
    output::print(&json!({"request_id":id,"reply":present(&reply)}), j)
}
fn multi(
    name: &str,
    keys: Vec<String>,
    connection: Connection,
) -> Result<(Connection, Vec<Vec<u8>>, Option<PathBuf>)> {
    let mut a = vec![name.as_bytes().to_vec()];
    for k in keys {
        a.push(key(k, &connection)?);
    }
    Ok((connection, a, None))
}
fn number(
    name: &str,
    k: String,
    n: i64,
    connection: Connection,
) -> Result<(Connection, Vec<Vec<u8>>, Option<PathBuf>)> {
    let a = vec![
        name.as_bytes().to_vec(),
        key(k, &connection)?,
        n.to_string().into_bytes(),
    ];
    Ok((connection, a, None))
}
#[allow(clippy::too_many_arguments)]
async fn scan(
    c: &ControlClient,
    connection: Connection,
    mut cursor: u64,
    pattern: Option<String>,
    count: u32,
    all: bool,
    max_pages: u32,
    j: bool,
) -> Result<()> {
    let mut pages = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut bytes = 0;
    for _ in 0..max_pages {
        ensure!(
            seen.insert(cursor),
            "KV SCAN repeated a cursor; resume from the last emitted page"
        );
        let mut a = vec![
            b"SCAN".to_vec(),
            cursor.to_string().into_bytes(),
            b"COUNT".to_vec(),
            count.to_string().into_bytes(),
        ];
        if let Some(p) = &pattern {
            a.extend([b"MATCH".to_vec(), key(p.clone(), &connection)?]);
        }
        let (Reply::Array(reply), _) = data(c, &connection, a).await? else {
            anyhow::bail!("invalid SCAN reply")
        };
        let Reply::Bulk(Some(next)) = &reply[0] else {
            anyhow::bail!("invalid SCAN cursor")
        };
        cursor = std::str::from_utf8(next)?.parse()?;
        let page =
            json!({"cursor":cursor.to_string(),"keys":present(&reply[1]),"complete":cursor==0});
        if output::is_jsonl() {
            output::print(&page, j)?;
        } else {
            bytes += serde_json::to_vec(&page)?.len();
            ensure!(
                bytes <= 16 * 1024 * 1024,
                "SCAN output exceeds 16 MiB; use JSONL"
            );
            pages.push(page);
        }
        if !all || cursor == 0 {
            break;
        }
    }
    if !output::is_jsonl() {
        output::print(
            &json!({"pages":pages,"cursor":cursor.to_string(),"complete":cursor==0}),
            j,
        )?;
    }
    Ok(())
}

fn canonical_wallet(value: &str) -> Result<String> {
    let bytes = if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(value)?
    } else {
        bs58::decode(value).into_vec()?
    };
    ensure!(bytes.len() == 32, "wallet must be a 32-byte public key");
    Ok(hex::encode(bytes))
}

//! Managed storage workflows share customer authentication and encrypted,
//! account-bound recovery. No private BFF or arbitrary destination URLs.
use crate::{auth::ControlClient, compute_journal::ContextBinding, output, platform, secure_state};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    path::PathBuf,
};
use uuid::Uuid;
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Durable managed buckets, distinct from historical shared S3 namespaces.
    Buckets {
        #[command(subcommand)]
        command: Buckets,
    },
    /// Search committed publications from PipeBox, S3 and native clients.
    Search(Search),
    Cors {
        bucket: Uuid,
        #[command(subcommand)]
        command: Config,
    },
    /// Application S3 keys scoped to a personal or team bucket.
    Keys {
        bucket: Uuid,
        #[command(subcommand)]
        command: Keys,
    },
    Webhooks {
        bucket: Uuid,
        #[command(subcommand)]
        command: Webhooks,
    },
    Lifecycle {
        bucket: Uuid,
        #[command(subcommand)]
        command: Lifecycle,
    },
    Audit {
        bucket: Uuid,
        #[arg(long)]
        before: Option<u64>,
    },
    /// Inspect durable storage requests without printing saved secrets.
    Requests,
    /// Retry the exact original request in its original account context.
    Resume { request_id: Uuid },
}
#[derive(Args, Debug)]
pub struct Page {
    #[arg(long,default_value_t=50,value_parser=clap::value_parser!(u32).range(1..=100))]
    limit: u32,
    #[arg(long)]
    after: Option<Uuid>,
    #[arg(long)]
    all: bool,
}
#[derive(Subcommand, Debug)]
pub enum Buckets {
    List {
        #[command(flatten)]
        page: Page,
    },
    Get {
        id: Uuid,
    },
    Create {
        label: String,
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        organization: Option<String>,
    },
}
#[derive(Args, Debug)]
pub struct Search {
    #[arg(default_value = "")]
    query: String,
    #[arg(long)]
    bucket: Option<Uuid>,
    #[arg(long)]
    extension: Option<String>,
    #[arg(long)]
    min_bytes: Option<u128>,
    #[arg(long)]
    max_bytes: Option<u128>,
    #[arg(long)]
    modified_after: Option<i64>,
    #[arg(long)]
    modified_before: Option<i64>,
    #[command(flatten)]
    page: Page,
}
#[derive(Subcommand, Debug)]
pub enum Config {
    Get,
    /// JSON object containing the observed revision and rules.
    Set {
        #[arg(long)]
        file: PathBuf,
    },
}
#[derive(Subcommand, Debug)]
pub enum Keys {
    List,
    Create {
        label: String,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, default_value="read,list",value_delimiter=',',value_parser=["read","write","list"])]
        permissions: Vec<String>,
        #[arg(long, default_value_t=604800,value_parser=clap::value_parser!(u32).range(60..=31536000))]
        expires_in: u32,
    },
    Revoke {
        id: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum Webhooks {
    List,
    Create {
        url: String,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long,required=true,value_parser=["object.uploaded","object.deleted"])]
        event: Vec<String>,
    },
    Revoke {
        id: Uuid,
    },
    Deliveries {
        #[arg(long)]
        before: Option<Uuid>,
    },
    Retry {
        delivery: Uuid,
    },
}
#[derive(Subcommand, Debug)]
pub enum Lifecycle {
    Get,
    Preview {
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long,value_parser=clap::value_parser!(u32).range(1..=36500))]
        days: u32,
    },
    /// Review a preview, then explicitly enable permanent expiration.
    Enable {
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long,value_parser=clap::value_parser!(u32).range(1..=36500))]
        days: u32,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        preview_token: String,
    },
    Disable,
}
pub fn needs_confirmation(c: &Commands) -> bool {
    matches!(
        c,
        Commands::Lifecycle {
            command: Lifecycle::Enable { .. },
            ..
        } | Commands::Resume { .. }
    )
}
const SPEC: secure_state::Spec = secure_state::Spec {
    file: "storage-workspace-v1.enc",
    key: "storage-workspace-v1",
    magic: b"PIPESTW1",
    limit: 16 * 1024 * 1024,
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    activate_s3: bool,
    binding: ContextBinding,
    operation: String,
    parameters: BTreeMap<String, String>,
    body: Option<Value>,
    state: String,
    response: Option<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    requests: BTreeMap<Uuid, Intent>,
}
impl Journal {
    fn load(c: &ControlClient) -> Result<Self> {
        let Some(bytes) = secure_state::read(c, &SPEC)? else {
            return Ok(Self {
                version: 1,
                requests: BTreeMap::new(),
            });
        };
        let s: Self = serde_json::from_slice(&bytes)
            .context("invalid storage journal; original preserved")?;
        ensure!(
            s.version == 1,
            "unsupported storage journal; original preserved"
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
}
async fn binding(c: &ControlClient) -> Result<ContextBinding> {
    let ctx = c.get("/v1/cli/context").await?;
    platform::validate_response("platformCliContext", "200", &ctx)?;
    Ok(ContextBinding {
        endpoint: c.url(""),
        owner_wallet: ctx["principal"]["owner_wallet"]
            .as_str()
            .context("missing canonical owner")?
            .into(),
        account_id: ctx["principal"]["account_id"].as_str().map(str::to_owned),
    })
}
fn target(op: &str, parameters: &BTreeMap<String, String>) -> Result<(String, String)> {
    ensure!(
        matches!(
            op,
            "storageBucketsList"
                | "storageBucketsCreate"
                | "storageBucketGet"
                | "storageBucketAudit"
                | "storageBucketCredentialsList"
                | "storageBucketCredentialCreate"
                | "storageBucketCredentialRevoke"
                | "storageObjectsSearch"
                | "storageCorsGet"
                | "storageCorsUpdate"
                | "storageWebhooksList"
                | "storageWebhookCreate"
                | "storageWebhookRevoke"
                | "storageWebhookDeliveries"
                | "storageWebhookRetry"
                | "storageLifecycleGet"
                | "storageLifecyclePreview"
                | "storageLifecycleUpdate"
        ),
        "unknown managed storage operation"
    );
    let (template, method, _) = platform::operation(op)?;
    let mut path = template.to_owned();
    for (key, value) in parameters {
        ensure!(
            ["id", "hook", "delivery", "key"].contains(&key.as_str()),
            "invalid resource parameter"
        );
        let uuid = Uuid::parse_str(value)?;
        let placeholder = format!("{{{key}}}");
        ensure!(path.contains(&placeholder), "unexpected resource parameter");
        path = path.replace(&placeholder, &uuid.to_string());
    }
    ensure!(!path.contains('{'), "missing storage resource parameter");
    Ok((path, method.to_ascii_uppercase()))
}
async fn call(
    c: &ControlClient,
    op: &str,
    p: &BTreeMap<String, String>,
    body: Option<Value>,
) -> Result<Value> {
    let (path, method) = target(op, p)?;
    let (_, _, schema) = platform::operation(op)?;
    if let Some(v) = &body {
        let schema = &schema["requestBody"]["content"]["application/json"]["schema"];
        if !schema.is_null() {
            platform::validate(schema, v)?;
        }
    }
    let value = match method.as_str() {
        "GET" => c.get(&path).await?,
        "POST" => c.post(&path, body.unwrap_or(json!({}))).await?,
        "DELETE" => c.delete(&path).await?,
        _ => anyhow::bail!("unsupported storage method"),
    };
    platform::validate_response(op, "200", &value)?;
    Ok(value)
}
async fn submit(
    c: &ControlClient,
    operation: &str,
    parameters: BTreeMap<String, String>,
    body: Option<Value>,
    id: Uuid,
) -> Result<Value> {
    submit_with_activation(c, operation, parameters, body, id, false).await
}
async fn submit_with_activation(
    c: &ControlClient,
    operation: &str,
    parameters: BTreeMap<String, String>,
    body: Option<Value>,
    id: Uuid,
    activate_s3: bool,
) -> Result<Value> {
    let b = binding(c).await?;
    let mut j = Journal::load(c)?;
    for (id, e) in &j.requests {
        ensure!(
            e.binding != b || e.state != "unknown",
            "unresolved storage request {id}; use pipe storage resume {id}"
        );
    }
    ensure!(
        j.requests.len() < 4096,
        "storage journal full; preserve recovery records"
    );
    ensure!(!j.requests.contains_key(&id), "request already exists");
    target(operation, &parameters)?;
    if let Some(body) = &body {
        let (_, _, op) = platform::operation(operation)?;
        let schema = &op["requestBody"]["content"]["application/json"]["schema"];
        if !schema.is_null() {
            platform::validate(schema, body)?;
        }
    }
    j.requests.insert(
        id,
        Intent {
            attempts: 0,
            activate_s3,
            binding: b,
            operation: operation.into(),
            parameters,
            body,
            state: "unknown".into(),
            response: None,
        },
    );
    j.save(c)?;
    eprintln!("Storage request {id}");
    execute(c, &mut j, id).await
}
async fn execute(c: &ControlClient, j: &mut Journal, id: Uuid) -> Result<Value> {
    let e = j.requests.get(&id).context("storage request not found")?;
    ensure!(
        e.binding == binding(c).await?,
        "storage request belongs to another account or endpoint"
    );
    if let Some(response) = &e.response {
        if e.activate_s3 {
            activate(c, response)?;
        }
        return Ok(response.clone());
    }
    ensure!(e.state == "unknown", "storage request was rejected");
    let attempts = e.attempts;
    let activate_s3 = e.activate_s3;
    let operation = e.operation.clone();
    let parameters = e.parameters.clone();
    let body = e.body.clone();
    j.requests.get_mut(&id).unwrap().attempts += 1;
    j.save(c)?;
    let result = call(c, &operation, &parameters, body).await;
    match result {
        Ok(value) => {
            let e = j.requests.get_mut(&id).unwrap();
            e.state = "complete".into();
            e.response = Some(value.clone());
            j.save(c)?;
            if activate_s3 {
                activate(c, &value)?;
            }
            Ok(value)
        }
        Err(error) => {
            // The server checks lifecycle revision/replay before preview expiry.
            // This specific rejection proves the original revision is unchanged;
            // a lost successful update instead returns its original result.
            let expired_unapplied_preview = operation == "storageLifecycleUpdate"
                && error
                    .downcast_ref::<crate::error::ApiError>()
                    .is_some_and(|e| e.status.as_u16() == 400 && e.code == "preview_required");
            if expired_unapplied_preview
                || (attempts == 0
                    && error
                        .downcast_ref::<crate::error::ApiError>()
                        .is_some_and(|e| {
                            matches!(e.status.as_u16(), 400 | 401 | 403 | 404 | 409 | 422)
                        }))
            {
                j.requests.get_mut(&id).unwrap().state = "rejected".into();
                j.save(c)?;
                return Err(error);
            }
            Err(Unknown { request_id: id }.into())
        }
    }
}
fn params(bucket: Uuid) -> BTreeMap<String, String> {
    BTreeMap::from([("id".into(), bucket.to_string())])
}
fn activate(c: &ControlClient, value: &Value) -> Result<()> {
    let expires = value["expires_at"]
        .as_u64()
        .context("credential expiry missing")?;
    ensure!(
        expires
            > std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        "saved storage credential has expired; create a new connection"
    );
    let access = value["access_key_id"]
        .as_str()
        .context("credential ID missing")?;
    let secret = value["secret_access_key"]
        .as_str()
        .filter(|v| !v.is_empty())
        .context("credential secret missing")?;
    c.save_active_s3_credential(access, secret)
}
pub(crate) async fn setup_key(
    c: &ControlClient,
    bucket: Uuid,
    label: &str,
    prefix: &str,
    write: bool,
    expires_in: u64,
) -> Result<Value> {
    let id = Uuid::new_v4();
    let permissions = if write {
        vec!["read", "write", "list"]
    } else {
        vec!["read", "list"]
    };
    submit_with_activation(c,"storageBucketCredentialCreate",params(bucket),Some(json!({"request_id":id,"label":label,"prefix":prefix,"permissions":permissions,"expires_in":expires_in})),id,true).await
}
async fn pages(
    c: &ControlClient,
    op: &str,
    mut query: Vec<(String, String)>,
    page: Page,
) -> Result<Value> {
    let (path, _) = target(op, &BTreeMap::new())?;
    let mut after = page.after.map(|v| v.to_string());
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    query.push(("limit".into(), page.limit.to_string()));
    for _ in 0..1000 {
        let mut q = query.clone();
        if let Some(a) = &after {
            q.push(("after".into(), a.clone()));
        }
        let mut url = reqwest::Url::parse("https://query.invalid")?;
        url.query_pairs_mut().extend_pairs(q);
        let encoded = url.query().unwrap_or("");
        let mut value = c.get(&format!("{path}?{encoded}")).await?;
        platform::validate_response(op, "200", &value)?;
        if !page.all {
            return Ok(value);
        }
        let rows = value["items"].as_array().context("missing page items")?;
        if output::is_jsonl() {
            output::print(&value, true)?;
        } else {
            items.extend(rows.iter().cloned());
            ensure!(
                items.len() <= 100000,
                "storage results exceed bounded pagination"
            );
        }
        after = value["next_cursor"].as_str().map(str::to_owned);
        if after.is_none() {
            if output::is_jsonl() {
                return Ok(Value::Null);
            }
            value["items"] = json!(items);
            return Ok(value);
        }
        ensure!(
            seen.insert(after.clone().unwrap()),
            "storage cursor repeated"
        );
    }
    anyhow::bail!("storage pagination reached the 1000-page bound")
}
pub async fn run(
    c: &ControlClient,
    command: Commands,
    json_output: bool,
    store: &mut crate::config::ConfigStore,
    profile_name: &str,
) -> Result<()> {
    let request_id = Uuid::new_v4();
    let mut mutation = None;
    let value = match command {
        Commands::Keys {
            bucket,
            command: Keys::List,
        } => call(c, "storageBucketCredentialsList", &params(bucket), None).await?,
        Commands::Keys {
            bucket,
            command:
                Keys::Create {
                    label,
                    prefix,
                    permissions,
                    expires_in,
                },
        } => {
            mutation = Some((
                "storageBucketCredentialCreate",
                params(bucket),
                Some(
                    json!({"request_id":request_id,"label":label,"prefix":prefix,"permissions":permissions,"expires_in":expires_in}),
                ),
            ));
            Value::Null
        }
        Commands::Keys {
            bucket,
            command: Keys::Revoke { id },
        } => {
            let mut p = params(bucket);
            p.insert("key".into(), id.to_string());
            mutation = Some(("storageBucketCredentialRevoke", p, None));
            Value::Null
        }
        Commands::Buckets {
            command: Buckets::List { page },
        } => pages(c, "storageBucketsList", vec![], page).await?,
        Commands::Buckets {
            command: Buckets::Get { id },
        } => call(c, "storageBucketGet", &params(id), None).await?,
        Commands::Buckets {
            command:
                Buckets::Create {
                    label,
                    wallet,
                    organization,
                },
        } => {
            mutation = Some((
                "storageBucketsCreate",
                BTreeMap::new(),
                Some(
                    json!({"request_id":request_id,"label":label,"wallet":wallet,"organization_id":organization}),
                ),
            ));
            Value::Null
        }
        Commands::Search(input) => {
            let mut query = vec![("q".into(), input.query)];
            for (k, v) in [
                ("bucket", input.bucket.map(|v| v.to_string())),
                ("extension", input.extension),
                ("min_bytes", input.min_bytes.map(|v| v.to_string())),
                ("max_bytes", input.max_bytes.map(|v| v.to_string())),
                (
                    "modified_after",
                    input.modified_after.map(|v| v.to_string()),
                ),
                (
                    "modified_before",
                    input.modified_before.map(|v| v.to_string()),
                ),
            ] {
                if let Some(v) = v {
                    query.push((k.into(), v));
                }
            }
            pages(c, "storageObjectsSearch", query, input.page).await?
        }
        Commands::Cors {
            bucket,
            command: Config::Get,
        } => call(c, "storageCorsGet", &params(bucket), None).await?,
        Commands::Cors {
            bucket,
            command: Config::Set { file },
        } => {
            let mut bytes = Vec::new();
            std::fs::File::open(file)?
                .take(65537)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 65536, "CORS document exceeds 64 KiB");
            mutation = Some((
                "storageCorsUpdate",
                params(bucket),
                Some(serde_json::from_slice(&bytes)?),
            ));
            Value::Null
        }
        Commands::Webhooks { bucket, command } => match command {
            Webhooks::List => call(c, "storageWebhooksList", &params(bucket), None).await?,
            Webhooks::Create { url, prefix, event } => {
                mutation = Some((
                    "storageWebhookCreate",
                    params(bucket),
                    Some(json!({"request_id":request_id,"url":url,"prefix":prefix,"events":event})),
                ));
                Value::Null
            }
            Webhooks::Revoke { id } => {
                let mut p = params(bucket);
                p.insert("hook".into(), id.to_string());
                mutation = Some(("storageWebhookRevoke", p, None));
                Value::Null
            }
            Webhooks::Retry { delivery } => {
                let mut p = params(bucket);
                p.insert("delivery".into(), delivery.to_string());
                mutation = Some(("storageWebhookRetry", p, None));
                Value::Null
            }
            Webhooks::Deliveries { before } => {
                let (path, _) = target("storageWebhookDeliveries", &params(bucket))?;
                let path = before.map(|v| format!("{path}?before={v}")).unwrap_or(path);
                let v = c.get(&path).await?;
                platform::validate_response("storageWebhookDeliveries", "200", &v)?;
                v
            }
        },
        Commands::Lifecycle { bucket, command } => match command {
            Lifecycle::Get => call(c, "storageLifecycleGet", &params(bucket), None).await?,
            Lifecycle::Preview { prefix, days } => {
                let current = call(c, "storageLifecycleGet", &params(bucket), None).await?;
                let mut preview=call(c,"storageLifecyclePreview",&params(bucket),Some(json!({"revision":current["revision"],"prefix":prefix,"days":days,"enabled":true,"preview_token":null}))).await?;
                preview["revision"] = current["revision"].clone();
                preview
            }
            Lifecycle::Enable {
                prefix,
                days,
                revision,
                preview_token,
            } => {
                mutation = Some((
                    "storageLifecycleUpdate",
                    params(bucket),
                    Some(
                        json!({"revision":revision,"prefix":prefix,"days":days,"enabled":true,"preview_token":preview_token}),
                    ),
                ));
                Value::Null
            }
            Lifecycle::Disable => {
                let current = call(c, "storageLifecycleGet", &params(bucket), None).await?;
                mutation = Some((
                    "storageLifecycleUpdate",
                    params(bucket),
                    Some(
                        json!({"revision":current["revision"],"prefix":current["prefix"],"days":current["days"],"enabled":false,"preview_token":null}),
                    ),
                ));
                Value::Null
            }
        },
        Commands::Audit { bucket, before } => {
            let (path, _) = target("storageBucketAudit", &params(bucket))?;
            let path = before.map(|v| format!("{path}?before={v}")).unwrap_or(path);
            let value = c.get(&path).await?;
            platform::validate_response("storageBucketAudit", "200", &value)?;
            value
        }
        Commands::Requests => {
            json!({"requests":Journal::load(c)?.requests.iter().map(|(id,e)|json!({"request_id":id,"context":e.binding,"operation":e.operation,"state":e.state})).collect::<Vec<_>>()})
        }
        Commands::Resume { request_id } => {
            let mut journal = Journal::load(c)?;
            let value = execute(c, &mut journal, request_id).await?;
            if journal.requests[&request_id].activate_s3 {
                crate::cli::save_s3_profile_defaults(
                    store,
                    profile_name,
                    value["bucket"].as_str().context("bucket missing")?,
                    value["prefix"].as_str(),
                )?;
            }
            value
        }
    };
    let value = if let Some((op, p, body)) = mutation {
        submit(c, op, p, body, request_id).await?
    } else {
        value
    };
    if value.is_null() && output::is_jsonl() {
        return Ok(());
    }
    if value.get("secret_access_key").is_some() {
        output::print_credential(&value, json_output)
    } else {
        output::print_automation(&value, json_output)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("outcome unknown for storage request {request_id}; use pipe storage resume {request_id} --yes; do not create a replacement")]
pub struct Unknown {
    pub request_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    use wiremock::{
        matchers::{body_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };
    #[tokio::test]
    async fn storage_unknown_result_preserves_exact_request_and_secret_across_restart() {
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
        let changed = Arc::new(AtomicBool::new(false));
        let switch = changed.clone();
        Mock::given(path("/v1/cli/context")).respond_with(move|_:&wiremock::Request|ResponseTemplate::new(200).set_body_json(json!({"principal":{"owner_wallet":if switch.load(Ordering::SeqCst){"other"}else{"owner"},"account_id":null,"credential_id":Uuid::nil(),"credential_kind":"session","account_access":true,"organizations":[],"resources":[],"scopes":["storage.write"]},"contexts":[],"storage":{"endpoint":"https://api.pipedev.network","region":"us-east-1"}}))).mount(&server).await;
        let bucket = Uuid::new_v4();
        let id = Uuid::new_v4();
        let secret = "private-webhook-signing-secret";
        let body = json!({"request_id":id,"url":"https://receiver.example.test/events","prefix":"logs/","events":["object.uploaded"]});
        let n = Arc::new(AtomicUsize::new(0));
        let calls = n.clone();
        Mock::given(method("POST")).and(path(format!("/v1/customer/storage/buckets/{bucket}/webhooks"))).and(body_json(body.clone())).respond_with(move|_:&wiremock::Request|if calls.fetch_add(1,Ordering::SeqCst)==0{ResponseTemplate::new(502)}else{ResponseTemplate::new(200).set_body_json(json!({"id":id,"secret":secret,"url":"https://receiver.example.test/events","prefix":"logs/","events":["object.uploaded"]}))}).expect(2).mount(&server).await;
        let error = submit(
            &c,
            "storageWebhookCreate",
            params(bucket),
            Some(body.clone()),
            id,
        )
        .await
        .unwrap_err();
        assert_eq!(crate::error::classification(&error), ("unknown_outcome", 8));
        assert!(submit(
            &c,
            "storageWebhookCreate",
            params(bucket),
            Some(body),
            Uuid::new_v4()
        )
        .await
        .is_err());
        drop(c);
        let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
        changed.store(true, Ordering::SeqCst);
        assert!(execute(&c, &mut Journal::load(&c).unwrap(), id)
            .await
            .is_err());
        assert_eq!(n.load(Ordering::SeqCst), 1);
        changed.store(false, Ordering::SeqCst);
        let result = execute(&c, &mut Journal::load(&c).unwrap(), id)
            .await
            .unwrap();
        assert_eq!(result["secret"], secret);
        let bytes = std::fs::read(c.secrets.state_directory().join(SPEC.file)).unwrap();
        assert!(!bytes.windows(secret.len()).any(|b| b == secret.as_bytes()));
        assert_eq!(
            execute(&c, &mut Journal::load(&c).unwrap(), id)
                .await
                .unwrap(),
            result
        );
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }
    #[tokio::test]
    async fn expired_unapplied_lifecycle_preview_releases_unknown_request() {
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
        Mock::given(path("/v1/cli/context")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"principal":{"owner_wallet":"owner","account_id":null,"credential_id":Uuid::nil(),"credential_kind":"session","account_access":true,"organizations":[],"resources":[],"scopes":["storage.write"]},"contexts":[],"storage":{"endpoint":"https://api.pipedev.network","region":"us-east-1"}}))).mount(&server).await;
        let bucket = Uuid::new_v4();
        let id = Uuid::new_v4();
        let body = json!({"revision":0,"prefix":"logs/","days":30,"enabled":true,"preview_token":"expired"});
        let n = Arc::new(AtomicUsize::new(0));
        let calls = n.clone();
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/customer/storage/buckets/{bucket}/lifecycle"
            )))
            .and(body_json(body.clone()))
            .respond_with(move |_: &wiremock::Request| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(502)
                } else {
                    ResponseTemplate::new(400).set_body_json(json!({"code":"preview_required"}))
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        assert!(
            submit(&c, "storageLifecycleUpdate", params(bucket), Some(body), id)
                .await
                .unwrap_err()
                .is::<Unknown>()
        );
        let error = execute(&c, &mut Journal::load(&c).unwrap(), id)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<crate::error::ApiError>().unwrap().code,
            "preview_required"
        );
        assert_eq!(Journal::load(&c).unwrap().requests[&id].state, "rejected");
    }
    #[test]
    fn routes_are_fixed_and_lifecycle_enable_requires_confirmation() {
        assert!(target("createTopup", &BTreeMap::new()).is_err());
        assert!(target(
            "storageBucketGet",
            &BTreeMap::from([("id".into(), "../operator".into())])
        )
        .is_err());
        assert!(target("storageBrowserSessionGet", &params(Uuid::new_v4())).is_err());
        use clap::Parser;
        let parsed = crate::cli::Cli::try_parse_from([
            "pipe",
            "storage",
            "lifecycle",
            &Uuid::nil().to_string(),
            "enable",
            "--days",
            "30",
            "--revision",
            "0",
            "--preview-token",
            "token",
        ])
        .unwrap();
        let crate::cli::Commands::Storage {
            command: crate::cli::StorageCommands::Workspace(c),
        } = parsed.command
        else {
            panic!("wrong parser")
        };
        assert!(needs_confirmation(&c));
    }
}

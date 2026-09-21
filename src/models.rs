//! Customer model registry: the same private workspace as the Models dashboard.
use crate::{auth::ControlClient, error::ApiError, output};
use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::{Args, Subcommand};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;
use walkdir::WalkDir;

const PART_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = PART_BYTES * 10_000;
const MAX_FILES: usize = 2048;
const MAX_CARD_BYTES: usize = 128 * 1024;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List models in the signed-in personal or team workspace.
    List {
        #[arg(long)]
        q: Option<String>,
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 30)]
        limit: u32,
    },
    /// Inspect one workspace model, including unpublished revisions.
    Get {
        model: Uuid,
        #[arg(long)]
        revision: Option<String>,
    },
    /// Upload a model directory into the workspace. It appears under Your models immediately.
    Upload(Box<Upload>),
    /// Queue verification for a sealed revision.
    Verify { model: Uuid, revision: Uuid },
    /// Point a tag at a verified revision. `latest` becomes the workspace's published revision.
    Publish {
        model: Uuid,
        revision: Uuid,
        #[arg(long, default_value = "latest")]
        tag: String,
    },
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct ModelFile {
    path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct Hardware {
    memory_gib: Option<u32>,
    quantization: Option<String>,
    context_length: Option<u32>,
    concurrency: Option<u32>,
    runtime: Option<String>,
    notes: String,
}

#[derive(Serialize, Deserialize)]
struct Journal {
    model_request_id: Uuid,
    revision_request_id: Uuid,
    fingerprint: String,
    create_fingerprint: String,
}

pub async fn run(client: &ControlClient, command: Commands, json_output: bool) -> Result<()> {
    client.require_login()?;
    match command {
        Commands::List { q, after, limit } => {
            ensure!((1..=100).contains(&limit), "limit must be 1–100");
            output::print(
                &page(client, q.as_deref(), after, limit).await?,
                json_output,
            )
        }
        Commands::Get { model, revision } => {
            let mut path = format!("/v1/customer/models/{model}");
            if let Some(revision) = revision {
                ensure!(
                    revision.len() <= 80
                        && revision
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
                    "revision must be a UUID or tag"
                );
                path.push_str(&format!("?revision={revision}"));
            }
            output::print(&client.get(&path).await?, json_output)
        }
        Commands::Upload(request) => {
            client.authorize_model_writes(false).await?;
            output::print(&upload(client, *request).await?, json_output)
        }
        Commands::Verify { model, revision } => {
            client.authorize_model_writes(false).await?;
            output::print(&verify(client, model, revision).await?, json_output)
        }
        Commands::Publish {
            model,
            revision,
            tag,
        } => {
            client.authorize_model_writes(false).await?;
            output::print(&publish(client, model, revision, &tag).await?, json_output)
        }
    }
}

#[derive(Args, Debug)]
pub struct Upload {
    /// Model directory, or one `.gguf` file. An MLX directory contains config.json, tokenizer files, and safetensors or .npz/.npy weights.
    path: PathBuf,
    /// Label a safetensors directory as MLX. Inferred for .npz/.npy weights and for MLX quantization in config.json.
    #[arg(long)]
    mlx: bool,
    #[arg(long)]
    namespace: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    license: String,
    /// Linked infrastructure billing identity from `pipe account identities`.
    /// Required only when this namespace and name do not already exist.
    #[arg(long)]
    wallet: Option<String>,
    #[arg(long)]
    organization: Option<String>,
    #[arg(long, default_value = "")]
    description: String,
    #[arg(long, default_value = "text-generation")]
    task: String,
    #[arg(long, default_value = "")]
    architecture: String,
    #[arg(long)]
    parameters_billions: Option<f64>,
    #[arg(long, default_value = "")]
    quantization: String,
    #[arg(long)]
    runtime: Option<String>,
    #[arg(long)]
    memory_gib: Option<u32>,
    #[arg(long)]
    context_length: Option<u32>,
    #[arg(long)]
    concurrency: Option<u32>,
    #[arg(long, default_value = "")]
    notes: String,
    /// Read the model card from this file (maximum 128 KiB).
    #[arg(long)]
    card: Option<PathBuf>,
    /// Add a revision to this model instead of looking it up by namespace and name.
    #[arg(long)]
    model_id: Option<Uuid>,
    /// Stable create id. Reuse it to retry the same new model after a lost response.
    #[arg(long)]
    request_id: Option<Uuid>,
    /// Stable revision id. Reuse it to resume the same file set.
    #[arg(long)]
    revision_id: Option<Uuid>,
    #[arg(long)]
    base_model: Option<Uuid>,
    #[arg(long, requires = "base_model")]
    base_revision: Option<Uuid>,
    #[arg(long, requires = "base_revision")]
    base_manifest: Option<String>,
    /// Poll until the worker reports the revision verified or failed.
    #[arg(long)]
    wait: bool,
    /// Publish the revision after verification. This waits for verification.
    #[arg(long)]
    publish: bool,
    #[arg(long, default_value = "latest")]
    tag: String,
    /// Seconds to wait when `--wait` or `--publish` is set.
    #[arg(long, default_value_t = 600)]
    timeout: u64,
}

async fn upload(client: &ControlClient, request: Upload) -> Result<Value> {
    validate_slug(&request.namespace, "namespace")?;
    validate_slug(&request.name, "name")?;
    ensure!(
        !["pipe", "pipenetwork", "admin", "api", "models"].contains(&request.namespace.as_str()),
        "this namespace is reserved"
    );
    ensure!(
        !request.license.is_empty() && request.license.len() <= 256,
        "a license of at most 256 characters is required"
    );
    ensure!(request.description.len() <= 4096, "description is too long");
    validate_tag(&request.tag)?;
    let hardware = hardware(&request)?;
    let card = match &request.card {
        Some(path) => {
            let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
            ensure!(bytes.len() <= MAX_CARD_BYTES, "model card exceeds 128 KiB");
            String::from_utf8(bytes).context("model card must be UTF-8")?
        }
        None => String::new(),
    };
    let base = match (
        request.base_model,
        request.base_revision,
        request.base_manifest.as_deref(),
    ) {
        (Some(model_id), Some(revision_id), Some(manifest)) => {
            ensure!(
                manifest.len() == 64 && manifest.bytes().all(|b| b.is_ascii_hexdigit()),
                "base manifest must be a SHA-256 hex digest"
            );
            Some(
                json!({"model_id": model_id, "revision_id": revision_id, "manifest_sha256": manifest.to_ascii_lowercase()}),
            )
        }
        (None, None, None) => None,
        _ => bail!("an adapter base needs --base-model, --base-revision, and --base-manifest"),
    };

    let (paths, skipped_hidden) = collect(&request.path)?;
    let mlx = request.mlx || mlx_package(&paths);
    let mut files = Vec::with_capacity(paths.len());
    for (path, local, size) in &paths {
        if client.progress {
            eprintln!("Hashing {path}");
        }
        let sha256 = sha256_file(local)?;
        files.push(ModelFile {
            path: path.clone(),
            size_bytes: *size,
            sha256,
        });
    }
    check_package(&files, base.is_some(), mlx)?;
    let formats = formats_of(&files, mlx);
    let runtimes = match &request.runtime {
        Some(runtime) => vec![runtime.clone()],
        None if mlx => vec!["mlx".into()],
        None => Vec::new(),
    };
    let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&files)?));
    let create_fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&json!({
        "namespace": request.namespace,
        "name": request.name,
        "license": request.license,
        "wallet": request.wallet,
        "organization": request.organization,
        "description": request.description,
        "task": request.task,
        "architecture": request.architecture,
        "parameters_billions": request.parameters_billions,
        "formats": formats,
        "quantization": request.quantization,
        "runtimes": runtimes,
    }))?));

    let first = page(
        client,
        Some(&format!("{}/{}", request.namespace, request.name)),
        None,
        100,
    )
    .await?;
    if first["available"] == false {
        bail!("Models are not enabled on this control plane");
    }
    let mut model_id = request
        .model_id
        .or(find_in(&first, &request.namespace, &request.name));
    if model_id.is_none() && !first["next_cursor"].is_null() {
        model_id = find_model(
            client,
            &request.namespace,
            &request.name,
            first["next_cursor"].clone(),
        )
        .await?;
    }
    let journal_key = journal_key(
        &request.namespace,
        &request.name,
        &fs::canonicalize(&request.path).unwrap_or_else(|_| request.path.clone()),
    );
    let mut journal = load_journal(client, &journal_key)?;
    let mut creating = model_id.is_none();
    if creating {
        let wallet = request
            .wallet
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "pass --wallet with a linked infrastructure billing identity (`pipe account identities`) to create {namespace}/{name}",
                    namespace = request.namespace,
                    name = request.name
                )
            })?;
        let request_id = if let Some(id) = request.request_id {
            id
        } else if journal
            .as_ref()
            .is_some_and(|item| item.create_fingerprint == create_fingerprint)
        {
            journal.as_ref().unwrap().model_request_id
        } else {
            Uuid::new_v4()
        };
        let revision_request_id = revision_id_for(&request, &journal, &fingerprint);
        journal = Some(Journal {
            model_request_id: request_id,
            revision_request_id,
            fingerprint: fingerprint.clone(),
            create_fingerprint: create_fingerprint.clone(),
        });
        save_journal(client, &journal_key, journal.as_ref().unwrap())?;
        match client
            .post(
                "/v1/customer/models",
                json!({
                    "request_id": request_id,
                    "namespace": request.namespace,
                    "name": request.name,
                    "wallet": wallet,
                    "organization_id": request.organization,
                    "description": request.description,
                    "license": request.license,
                    "task": request.task,
                    "architecture": request.architecture,
                    "parameters_billions": request.parameters_billions,
                    "formats": formats,
                    "quantization": request.quantization,
                    "runtimes": runtimes,
                }),
            )
            .await
        {
            Ok(created) => {
                model_id = created["id"]
                    .as_str()
                    .and_then(|value| Uuid::parse_str(value).ok());
            }
            Err(error) if api_code(&error) == Some("model_exists") => {
                creating = false;
                model_id = find_existing(client, &request.namespace, &request.name).await?;
                if model_id.is_none() {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    let model_id =
        model_id.ok_or_else(|| anyhow!("the model id was missing from the registry response"))?;
    let revision_request_id = revision_id_for(&request, &journal, &fingerprint);
    let stored = Journal {
        model_request_id: journal
            .as_ref()
            .map(|item| item.model_request_id)
            .unwrap_or(model_id),
        revision_request_id,
        fingerprint,
        create_fingerprint,
    };
    save_journal(client, &journal_key, &stored)?;

    let created = client
        .post(
            &format!("/v1/customer/models/{model_id}/revisions"),
            json!({
                "request_id": revision_request_id,
                "files": files,
                "card": card,
                "hardware": hardware,
                "base": base,
            }),
        )
        .await?;
    let revision = created["revision_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or(revision_request_id);
    let transfer = transfer_client()?;
    for (file, local) in files.iter().zip(paths.iter().map(|(_, path, _)| path)) {
        send_file(client, &transfer, model_id, revision, file, local).await?;
    }
    let verified = verify(client, model_id, revision).await?;
    let mut state = verified["state"].as_str().unwrap_or("verifying").to_owned();
    if request.wait || request.publish {
        state = wait_until_verified(
            client,
            model_id,
            revision,
            Duration::from_secs(request.timeout),
        )
        .await?;
    }
    let mut result = json!({
        "id": model_id,
        "namespace": request.namespace,
        "name": request.name,
        "revision_id": revision,
        "state": state,
        "files": files.len(),
        "bytes": files.iter().map(|file| file.size_bytes).sum::<u64>(),
        "skipped_hidden": skipped_hidden,
        "created": creating,
        "dashboard_path": format!("/dashboard/models/{model_id}"),
    });
    if request.publish {
        let published = publish(client, model_id, revision, &request.tag).await?;
        result["state"] = published["state"].clone();
        result["tag"] = json!(request.tag);
        result["manifest_sha256"] = published["manifest_sha256"].clone();
    }
    Ok(result)
}

fn revision_id_for(request: &Upload, journal: &Option<Journal>, fingerprint: &str) -> Uuid {
    if let Some(id) = request.revision_id {
        return id;
    }
    if let Some(journal) = journal {
        if journal.fingerprint == fingerprint {
            return journal.revision_request_id;
        }
    }
    Uuid::new_v4()
}

async fn verify(client: &ControlClient, model: Uuid, revision: Uuid) -> Result<Value> {
    client
        .post(
            &format!("/v1/customer/models/{model}/revisions/{revision}/verify"),
            json!({}),
        )
        .await
}

async fn publish(client: &ControlClient, model: Uuid, revision: Uuid, tag: &str) -> Result<Value> {
    validate_tag(tag)?;
    client
        .post(
            &format!("/v1/customer/models/{model}/revisions/{revision}/publish"),
            json!({"tag": tag}),
        )
        .await
}

async fn wait_until_verified(
    client: &ControlClient,
    model: Uuid,
    revision: Uuid,
    timeout: Duration,
) -> Result<String> {
    let started = Instant::now();
    loop {
        let detail = client
            .get(&format!("/v1/customer/models/{model}?revision={revision}"))
            .await?;
        let state = detail["revision"]["state"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned();
        match state.as_str() {
            "verified" | "published" => return Ok(state),
            "failed" => {
                let error = detail["revision"]["error"]
                    .as_str()
                    .unwrap_or("verification failed");
                bail!("{error}");
            }
            _ if started.elapsed() > timeout => {
                bail!(
                    "revision is still {state} after {} seconds",
                    timeout.as_secs()
                )
            }
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
}

async fn send_file(
    client: &ControlClient,
    transfer: &reqwest::Client,
    model: Uuid,
    revision: Uuid,
    file: &ModelFile,
    local: &Path,
) -> Result<()> {
    let root = format!("/v1/customer/models/{model}/revisions/{revision}");
    let mut opened = None;
    for _ in 0..5 {
        match client
            .post(&format!("{root}/upload"), json!({"path": file.path}))
            .await
        {
            Ok(value) => {
                opened = Some(value);
                break;
            }
            Err(error) if api_code(&error) == Some("upload_initializing") => {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(error) => return Err(error),
        }
    }
    let opened = opened.ok_or_else(|| {
        anyhow!(
            "upload initialization is still in progress for {}",
            file.path
        )
    })?;
    if opened["complete"] == true {
        return Ok(());
    }
    let part_bytes = opened["part_bytes"].as_u64().unwrap_or(0);
    ensure!(
        part_bytes == PART_BYTES,
        "storage returned an unsupported model part size"
    );
    let mut done = opened["parts"].as_array().cloned().unwrap_or_default();
    let mut number = 1u32;
    let mut offset = 0u64;
    while offset < file.size_bytes {
        let length = (file.size_bytes - offset).min(PART_BYTES);
        if !done
            .iter()
            .any(|part| part["part_number"].as_u64() == Some(u64::from(number)))
        {
            if client.progress {
                eprintln!("Uploading {} · {} / {}", file.path, offset, file.size_bytes);
            }
            let ticket = client
                .post(
                    &format!("{root}/part"),
                    json!({"path": file.path, "part_number": number}),
                )
                .await?;
            let ticket_length = ticket["length"].as_u64().unwrap_or(0);
            ensure!(
                ticket_length == length,
                "upload authorization did not match {}",
                file.path
            );
            let url = ticket["url"].as_str().context("part URL missing")?;
            check_transfer_url(url)?;
            let bytes = read_range(local, offset, length as usize)?;
            let response = transfer
                .put(url)
                .body(bytes)
                .send()
                .await
                .map_err(|error| error.without_url())
                .with_context(|| format!("upload {}", file.path))?;
            ensure!(
                response.status().is_success(),
                "storage rejected part {number} of {}",
                file.path
            );
            let etag = response
                .headers()
                .get("etag")
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .ok_or_else(|| anyhow!("storage did not confirm part {number} of {}", file.path))?
                .to_owned();
            done.push(json!({"part_number": number, "etag": etag}));
        }
        offset += length;
        number += 1;
    }
    done.sort_by_key(|part| part["part_number"].as_u64().unwrap_or(0));
    client
        .post(
            &format!("{root}/complete"),
            json!({"path": file.path, "parts": done}),
        )
        .await?;
    Ok(())
}

async fn page(
    client: &ControlClient,
    q: Option<&str>,
    after: Option<Uuid>,
    limit: u32,
) -> Result<Value> {
    let mut path = format!("/v1/customer/models?limit={limit}");
    if let Some(q) = q.filter(|value| !value.is_empty()) {
        ensure!(q.len() <= 256, "search text is too long");
        path.push_str(&format!("&q={}", urlencoding(q)));
    }
    if let Some(after) = after {
        path.push_str(&format!("&after={after}"));
    }
    client.get(&path).await
}

async fn find_existing(
    client: &ControlClient,
    namespace: &str,
    name: &str,
) -> Result<Option<Uuid>> {
    let mut cursor = None;
    for _ in 0..100 {
        let body = page(client, Some(&format!("{namespace}/{name}")), cursor, 100).await?;
        if let Some(id) = find_in(&body, namespace, name) {
            return Ok(Some(id));
        }
        match body["next_cursor"]
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
        {
            Some(id) => cursor = Some(id),
            None => return Ok(None),
        }
    }
    Ok(None)
}

async fn find_model(
    client: &ControlClient,
    namespace: &str,
    name: &str,
    mut cursor: Value,
) -> Result<Option<Uuid>> {
    for _ in 0..100 {
        let Some(after) = cursor
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            return Ok(None);
        };
        let body = page(
            client,
            Some(&format!("{namespace}/{name}")),
            Some(after),
            100,
        )
        .await?;
        if let Some(id) = find_in(&body, namespace, name) {
            return Ok(Some(id));
        }
        if body["next_cursor"].is_null() {
            return Ok(None);
        }
        cursor = body["next_cursor"].clone();
    }
    Ok(None)
}

fn find_in(page: &Value, namespace: &str, name: &str) -> Option<Uuid> {
    page["items"].as_array()?.iter().find_map(|item| {
        (item["namespace"] == namespace && item["name"] == name)
            .then(|| {
                item["id"]
                    .as_str()
                    .and_then(|value| Uuid::parse_str(value).ok())
            })
            .flatten()
    })
}

type CollectedFile = (String, PathBuf, u64);

fn collect(path: &Path) -> Result<(Vec<CollectedFile>, u64)> {
    if path.is_file() {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("model file name must be UTF-8"))?;
        ensure!(
            name.ends_with(".gguf") && valid_path(name),
            "a single file upload must be one .gguf file; upload an MLX model as its directory"
        );
        let size = path.metadata()?.len();
        ensure!(
            size > 0 && size <= MAX_FILE_BYTES,
            "GGUF file is empty or too large"
        );
        return Ok((vec![(name.to_owned(), path.to_owned(), size)], 0));
    }
    ensure!(
        path.is_dir(),
        "upload a model directory, an MLX directory, or a .gguf file"
    );
    let root = fs::canonicalize(path)?;
    let mut files = Vec::new();
    let mut skipped_hidden = 0u64;
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry.with_context(|| format!("read {}", path.display()))?;
        if entry.path() == root {
            continue;
        }
        let relative = entry.path().strip_prefix(&root).unwrap();
        let mut parts = Vec::new();
        let mut hidden = false;
        for component in relative.components() {
            let Component::Normal(text) = component else {
                bail!("refusing special path {}", relative.display());
            };
            let text = text
                .to_str()
                .ok_or_else(|| anyhow!("model paths must be UTF-8: {}", relative.display()))?;
            if text.starts_with('.') {
                hidden = true;
                break;
            }
            parts.push(text);
        }
        if hidden {
            if entry.file_type().is_file() {
                skipped_hidden += 1;
            }
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!("refusing symlink {}", relative.display());
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let stored = parts.join("/");
        ensure!(
            valid_path(&stored),
            "invalid model file path {stored}: use letters, digits, '.', '_', '-', '+', and spaces"
        );
        let size = entry.metadata()?.len();
        ensure!(
            size <= MAX_FILE_BYTES,
            "{stored} exceeds the 10000-part upload limit"
        );
        files.push((stored, entry.path().to_owned(), size));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    ensure!(!files.is_empty(), "the directory has no model files");
    ensure!(
        files.len() <= MAX_FILES,
        "a revision accepts at most 2048 files"
    );
    Ok((files, skipped_hidden))
}

fn check_package(files: &[ModelFile], adapter: bool, mlx: bool) -> Result<()> {
    let has = |name: &str| {
        files
            .iter()
            .any(|file| file.path == name && file.size_bytes > 0)
    };
    let weights = |suffix: &str| {
        files
            .iter()
            .any(|file| file.path.ends_with(suffix) && file.size_bytes > 0)
    };
    let tensor = weights(".safetensors") || weights(".bin") || weights(".npz") || weights(".npy");
    if adapter {
        ensure!(
            has("adapter_config.json") && weights(".safetensors"),
            "an adapter needs adapter_config.json, safetensors weights, and a pinned base revision"
        );
    } else if mlx || !weights(".gguf") {
        ensure!(
            tensor,
            "include GGUF, safetensors, PyTorch, or MLX weight files"
        );
        ensure!(
            has("config.json")
                && (has("tokenizer.json")
                    || has("tokenizer.model")
                    || (has("vocab.json") && has("merges.txt"))),
            "a runnable package needs config.json and its tokenizer files in this directory"
        );
    }
    Ok(())
}

fn mlx_package(files: &[CollectedFile]) -> bool {
    let weights = |suffix: &str| {
        files
            .iter()
            .any(|(path, _, size)| path.ends_with(suffix) && *size > 0)
    };
    if weights(".npz") || weights(".npy") {
        return true;
    }
    let Some((_, config, _)) = files
        .iter()
        .find(|(path, _, size)| path == "config.json" && *size > 0 && *size <= 2 * 1024 * 1024)
    else {
        return false;
    };
    let Ok(text) = fs::read_to_string(config) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    value
        .get("quantization")
        .and_then(Value::as_object)
        .is_some_and(|quantization| {
            quantization.contains_key("bits")
                || quantization.contains_key("group_size")
                || quantization.contains_key("mode")
        })
}

fn formats_of(files: &[ModelFile], mlx: bool) -> Vec<String> {
    let mut formats = Vec::new();
    if mlx {
        formats.push("mlx".into());
    }
    for file in files {
        if let Some(extension) = file.path.rsplit_once('.').map(|(_, extension)| extension) {
            if matches!(extension, "gguf" | "safetensors")
                && !formats.contains(&extension.to_owned())
            {
                formats.push(extension.to_owned());
            }
        }
    }
    formats
}

fn hardware(request: &Upload) -> Result<Hardware> {
    if request.memory_gib.is_some()
        || request.context_length.is_some()
        || request.concurrency.is_some()
    {
        ensure!(
            request.memory_gib.is_some()
                && request.context_length.is_some()
                && request.concurrency.is_some()
                && request.runtime.is_some()
                && !request.quantization.is_empty(),
            "memory guidance needs --memory-gib, --quantization, --context-length, --concurrency, and --runtime"
        );
    }
    ensure!(request.notes.len() <= 4096, "hardware notes are too long");
    if let Some(memory) = request.memory_gib {
        ensure!(
            (1..=65536).contains(&memory),
            "GPU memory estimate is out of range"
        );
    }
    Ok(Hardware {
        memory_gib: request.memory_gib,
        quantization: (!request.quantization.is_empty()).then(|| request.quantization.clone()),
        context_length: request.context_length,
        concurrency: request.concurrency,
        runtime: request.runtime.clone(),
        notes: if request.memory_gib.is_some() && request.notes.is_empty() {
            "Publisher estimate; actual memory depends on the selected runtime and workload.".into()
        } else {
            request.notes.clone()
        },
    })
}

fn validate_slug(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'),
        "{label} must be 1–64 characters: a lowercase letter or digit, then lowercase letters, digits, '_' or '-'"
    );
    Ok(())
}

fn validate_tag(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "use a tag of at most 64 letters, digits, dots, underscores, or hyphens"
    );
    Ok(())
}

fn valid_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.starts_with('.')
                && !part.ends_with('.')
                && !part.ends_with(' ')
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-+ ".contains(&byte))
        })
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn read_range(path: &Path, offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; length];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn transfer_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(180))
        .build()?)
}

fn check_transfer_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).context("invalid part URL")?;
    ensure!(url.username().is_empty() && url.password().is_none() && url.fragment().is_none());
    let host = url.host_str().context("part URL has no host")?;
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "model part uploads require HTTPS"
    );
    Ok(())
}

fn api_code(error: &anyhow::Error) -> Option<&str> {
    error
        .downcast_ref::<ApiError>()
        .map(|error| error.code.as_str())
}

fn journal_key(namespace: &str, name: &str, path: &Path) -> String {
    hex::encode(Sha256::digest(
        format!("{namespace}\0{name}\0{}", path.display()).into_bytes(),
    ))
}

fn journal_path(client: &ControlClient, key: &str) -> PathBuf {
    client
        .secrets
        .state_directory()
        .join("model-uploads")
        .join(format!("{key}.json"))
}

fn load_journal(client: &ControlClient, key: &str) -> Result<Option<Journal>> {
    let path = journal_path(client, key);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(Some(serde_json::from_slice(&bytes).context(
        "model upload journal is unreadable; remove it to start a new revision",
    )?))
}

fn save_journal(client: &ControlClient, key: &str, journal: &Journal) -> Result<()> {
    let path = journal_path(client, key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec(journal)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn urlencoding(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~/".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn login(client: &ControlClient) {
        client
            .secrets
            .set(
                "session",
                &json!({
                    "access_token": "legacy-test-token",
                    "refresh_token": "refresh",
                    "owner_wallet": "owner",
                    "session_id": Uuid::nil()
                })
                .to_string(),
            )
            .unwrap();
    }

    fn sample(directory: &Path) {
        fs::write(directory.join("model.gguf"), b"weights").unwrap();
        fs::write(directory.join(".hidden"), b"skip").unwrap();
    }

    #[test]
    fn mlx_weights_are_labeled_and_plain_safetensors_are_not() {
        let mlx = tempfile::tempdir().unwrap();
        fs::write(mlx.path().join("weights.npz"), b"weights").unwrap();
        fs::write(
            mlx.path().join("config.json"),
            br#"{"quantization":{"bits":4,"group_size":64}}"#,
        )
        .unwrap();
        fs::write(mlx.path().join("tokenizer.json"), b"{}").unwrap();
        let (paths, _) = collect(mlx.path()).unwrap();
        assert!(mlx_package(&paths));
        let files = paths
            .iter()
            .map(|(path, _, size)| ModelFile {
                path: path.clone(),
                size_bytes: *size,
                sha256: "ab".repeat(32),
            })
            .collect::<Vec<_>>();
        check_package(&files, false, true).unwrap();
        assert!(formats_of(&files, true).contains(&"mlx".to_string()));

        let plain = tempfile::tempdir().unwrap();
        fs::write(plain.path().join("model.safetensors"), b"weights").unwrap();
        fs::write(
            plain.path().join("config.json"),
            br#"{"model_type":"llama"}"#,
        )
        .unwrap();
        fs::write(plain.path().join("tokenizer.json"), b"{}").unwrap();
        let (paths, _) = collect(plain.path()).unwrap();
        assert!(!mlx_package(&paths));
        let files = paths
            .iter()
            .map(|(path, _, size)| ModelFile {
                path: path.clone(),
                size_bytes: *size,
                sha256: "ab".repeat(32),
            })
            .collect::<Vec<_>>();
        check_package(&files, false, false).unwrap();
        assert!(!formats_of(&files, false).contains(&"mlx".to_string()));
    }

    #[test]
    fn safetensors_without_tokenizer_are_rejected_before_upload() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("model.safetensors"), b"weights").unwrap();
        let error = collect(root.path()).and_then(|(files, _)| {
            let files = files
                .into_iter()
                .map(|(path, _, size)| ModelFile {
                    path,
                    size_bytes: size,
                    sha256: "ab".repeat(32),
                })
                .collect::<Vec<_>>();
            check_package(&files, false, false)
        });
        assert!(error.unwrap_err().to_string().contains("tokenizer"));
    }

    #[tokio::test]
    async fn upload_creates_a_private_workspace_model_and_resumes_sealed_parts() {
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let model_dir = tempfile::tempdir().unwrap();
        sample(model_dir.path());
        let client = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
        login(&client);
        let model = Uuid::new_v4();
        let hits = Arc::new(AtomicUsize::new(0));
        let listed = hits.clone();
        Mock::given(method("GET"))
            .and(path("/v1/customer/models"))
            .respond_with(move |_: &wiremock::Request| {
                let seen = listed.fetch_add(1, Ordering::SeqCst);
                let mut body = json!({"available": true, "items": [], "next_cursor": null});
                if seen > 0 {
                    body["items"] = json!([{"id": model, "namespace": "acme", "name": "coder"}]);
                }
                ResponseTemplate::new(200).set_body_json(body)
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/customer/models"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": model, "namespace": "acme", "name": "coder"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let revision = Uuid::nil();
        Mock::given(method("POST"))
            .and(path(format!("/v1/customer/models/{model}/revisions")))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = request.body_json().unwrap();
                assert_eq!(body["files"][0]["path"], "model.gguf");
                assert_eq!(body["files"][0]["size_bytes"], 7);
                ResponseTemplate::new(200).set_body_json(json!({"revision_id": body["request_id"]}))
            })
            .expect(2)
            .mount(&server)
            .await;
        let uploads = Arc::new(AtomicUsize::new(0));
        let upload_hits = uploads.clone();
        Mock::given(method("POST"))
            .and(path(format!("/v1/customer/models/{model}/revisions/{revision}/upload")))
            .respond_with(move |_: &wiremock::Request| {
                let seen = upload_hits.fetch_add(1, Ordering::SeqCst);
                let body = if seen == 0 {
                    json!({"complete": false, "part_bytes": PART_BYTES, "size_bytes": 7, "parts": []})
                } else {
                    json!({"complete": true, "size_bytes": 7})
                };
                ResponseTemplate::new(200).set_body_json(body)
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/customer/models/{model}/revisions/{revision}/part"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"url": format!("{}/part", server.uri()), "length": 7, "expires_at": 1}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/part"))
            .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"part-1\""))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/customer/models/{model}/revisions/{revision}/complete"
            )))
            .respond_with(|request: &wiremock::Request| {
                let body: Value = request.body_json().unwrap();
                assert_eq!(body["parts"][0]["etag"], "\"part-1\"");
                ResponseTemplate::new(200).set_body_json(json!({"state": "sealed"}))
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/customer/models/{model}/revisions/{revision}/verify"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"state": "verifying"})))
            .expect(2)
            .mount(&server)
            .await;

        let request = |revision_id| Upload {
            path: model_dir.path().to_owned(),
            namespace: "acme".into(),
            name: "coder".into(),
            license: "apache-2.0".into(),
            wallet: Some("wallet".into()),
            organization: None,
            description: String::new(),
            task: "text-generation".into(),
            architecture: String::new(),
            parameters_billions: None,
            quantization: String::new(),
            runtime: None,
            memory_gib: None,
            context_length: None,
            concurrency: None,
            mlx: false,
            notes: String::new(),
            card: None,
            model_id: None,
            request_id: None,
            revision_id,
            base_model: None,
            base_revision: None,
            base_manifest: None,
            wait: false,
            publish: false,
            tag: "latest".into(),
            timeout: 5,
        };
        let created = upload(&client, request(Some(revision))).await.unwrap();
        assert_eq!(created["id"], json!(model));
        assert_eq!(created["state"], "verifying");
        assert_eq!(created["created"], true);
        assert_eq!(created["skipped_hidden"], 1);
        assert_eq!(
            created["dashboard_path"],
            json!(format!("/dashboard/models/{model}"))
        );
        let again = upload(&client, request(Some(revision))).await.unwrap();
        assert_eq!(again["created"], false);
        assert_eq!(again["revision_id"], json!(revision));
        assert!(hits.load(Ordering::SeqCst) >= 2);
    }
}

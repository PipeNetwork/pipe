// src/lib.rs

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Body, Client};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Write as IoWrite}; // For writeln!
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Semaphore;
use tokio_util::io::ReaderStream;
use walkdir::WalkDir;

pub const MAX_RETRIES: u32 = 3;
pub const INITIAL_RETRY_DELAY_MS: u64 = 1000;
pub const MAX_RETRY_DELAY_MS: u64 = 10000;

#[derive(Serialize, Debug)]
pub struct VersionCheckRequest {
    pub current_version: String,
}

#[derive(Deserialize, Debug)]
pub struct VersionCheckResponse {
    pub is_latest: bool,
    pub download_link: String,
    #[serde(default)]
    pub latest_version: Option<String>,
    #[serde(default)]
    pub release_notes: Option<String>,
    #[serde(default)]
    pub minimum_required: Option<String>,
}

#[derive(Parser, Debug)]
#[command(name = "pipe", version, about = "Interact with Pipe Network")]
pub struct Cli {
    #[arg(
        long,
        default_value = "https://api.pipenetwork.com",
        global = true,
        help = "Base URL for the Pipe Network client API"
    )]
    pub api: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new user
    NewUser {
        username: String,
    },

    RotateAppKey {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        old_app_key: Option<String>,
    },

    UploadFile {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_path: String,
        file_name: String,
        #[arg(long)]
        epochs: Option<u64>,
    },

    /// Download a single file
    DownloadFile {
        user_id: Option<String>,
        user_app_key: Option<String>,
        file_name: String,
        output_path: String,
    },

    /// Delete a file
    DeleteFile {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_name: String,
    },

    /// Check SOL balance
    CheckSol {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
    },

    /// Check custom token balance
    CheckToken {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
    },

    /// Swap SOL for PIPE tokens
    SwapSolForPipe {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        amount_sol: f64,
    },

    /// Swap PIPE tokens for DC
    SwapPipeForDc {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        pipe_amount: f64,
    },

    /// Withdraw SOL to an external Solana address
    WithdrawSol {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        to_pubkey: String,
        amount_sol: f64,
    },

    /// Withdraw custom tokens to an external address
    WithdrawCustomToken {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        to_pubkey: String,
        amount: u64,
    },

    CreatePublicLink {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_name: String,
    },

    PublicDownload {
        hash: String,
        output_path: String,
    },

    UploadDirectory {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        directory_path: String,
    },

    PriorityUploadDirectory {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        directory_path: String,
        #[arg(long)]
        skip_uploaded: bool,
        #[arg(long, default_value_t = 100)]
        concurrency: usize,
    },

    GetPriorityFee,

    PriorityUpload {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_path: String,
        file_name: String,
        #[arg(long)]
        epochs: Option<u64>,
    },

    PriorityDownload {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_name: String,
        output_path: String,
    },

    ListUploads,

    ExtendStorage {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_name: String,
        additional_months: u64,
    },
}

#[derive(Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateUserResponse {
    pub user_id: String,
    pub user_app_key: String,
    pub solana_pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct RotateAppKeyRequest {
    pub user_id: String,
    pub user_app_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RotateAppKeyResponse {
    pub user_id: String,
    pub new_user_app_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct DownloadRequest {
    pub user_id: String,
    pub user_app_key: String,
    pub file_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeleteFileRequest {
    pub user_id: String,
    pub user_app_key: String,
    pub file_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteFileResponse {
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct CheckWalletRequest {
    pub user_id: String,
    pub user_app_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CheckWalletResponse {
    pub user_id: String,
    pub public_key: String,
    pub balance_lamports: u64,
    pub balance_sol: f64,
}

#[derive(Serialize, Deserialize)]
pub struct CheckCustomTokenRequest {
    pub user_id: String,
    pub user_app_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CheckCustomTokenResponse {
    pub user_id: String,
    pub public_key: String,
    pub token_mint: String,
    pub amount: String,
    pub ui_amount: f64,
}

#[derive(Serialize, Deserialize)]
pub struct SwapSolForPipeRequest {
    pub user_id: String,
    pub user_app_key: String,
    pub amount_sol: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SwapSolForPipeResponse {
    pub user_id: String,
    pub sol_spent: f64,
    pub tokens_minted: u64,
}

#[derive(Serialize, Deserialize)]
pub struct SwapPipeForDcRequest {
    pub user_id: String,
    pub user_app_key: String,
    pub amount_pipe: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SwapPipeForDcResponse {
    pub user_id: String,
    pub pipe_spent: f64,
    pub dc_minted: f64,
}

#[derive(Serialize, Deserialize)]
pub struct WithdrawSolRequest {
    pub user_id: String,
    pub user_app_key: String,
    pub to_pubkey: String,
    pub amount_sol: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WithdrawSolResponse {
    pub user_id: String,
    pub to_pubkey: String,
    pub amount_sol: f64,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct WithdrawTokenRequest {
    pub user_id: String,
    pub user_app_key: String,
    pub to_pubkey: String,
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WithdrawTokenResponse {
    pub user_id: String,
    pub to_pubkey: String,
    pub amount: u64,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PriorityFeeResponse {
    pub priority_fee_per_gb: f64,
}

#[derive(Serialize, Deserialize)]
pub struct CreatePublicLinkRequest {
    pub user_id: String,
    pub user_app_key: String,
    pub file_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreatePublicLinkResponse {
    pub link_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct ExtendStorageRequest {
    pub user_id: String,
    pub user_app_key: String,
    pub file_name: String,
    pub additional_months: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExtendStorageResponse {
    pub message: String,
    pub new_expires_at: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SavedCredentials {
    pub user_id: String,
    pub user_app_key: String,
}

pub fn get_credentials_file_path() -> PathBuf {
    if let Some(home_dir) = dirs::home_dir() {
        home_dir.join(".pipe-cli.json")
    } else {
        PathBuf::from(".pipe-cli.json")
    }
}

pub fn load_credentials_from_file() -> Result<Option<SavedCredentials>> {
    let path = get_credentials_file_path();
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&path)?;
    let creds: SavedCredentials = serde_json::from_str(&data)?;
    Ok(Some(creds))
}

pub fn save_credentials_to_file(user_id: &str, user_app_key: &str) -> Result<()> {
    let creds = SavedCredentials {
        user_id: user_id.to_owned(),
        user_app_key: user_app_key.to_owned(),
    };
    let path = get_credentials_file_path();
    let data = serde_json::to_string_pretty(&creds)?;
    fs::write(&path, data)?;
    Ok(())
}

pub fn get_final_user_id_and_app_key(
    user_id_opt: Option<String>,
    user_app_key_opt: Option<String>,
) -> Result<(String, String)> {
    match (user_id_opt, user_app_key_opt) {
        (Some(u), Some(k)) => Ok((u, k)),
        (maybe_user_id, maybe_app_key) => {
            let creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!(
                    "No saved credentials found. Please run 'new-user' first \
                     or provide --user-id/--user_app_key."
                )
            })?;

            let final_user_id = maybe_user_id.unwrap_or(creds.user_id);
            let final_app_key = maybe_app_key.unwrap_or(creds.user_app_key);
            Ok((final_user_id, final_app_key))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UploadLogEntry {
    pub local_path: String,
    pub remote_path: String,
    pub status: String,
    pub message: String,
}

pub fn get_upload_log_path() -> PathBuf {
    if let Some(home_dir) = dirs::home_dir() {
        home_dir.join(".pipe-cli-uploads.json")
    } else {
        PathBuf::from(".pipe-cli-uploads.json")
    }
}

pub fn append_to_upload_log(local_path: &str, remote_path: &str, status: &str, message: &str) -> Result<()> {
    let log_path = get_upload_log_path();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let entry = UploadLogEntry {
        local_path: local_path.to_string(),
        remote_path: remote_path.to_string(),
        status: status.to_string(),
        message: message.to_string(),
    };

    let json_line = serde_json::to_string(&entry)?;
    writeln!(file, "{}", json_line)?;
    Ok(())
}

async fn check_version(client: &Client, base_url: &str) -> Result<()> {
    const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

    let url = format!("{}/checkVersion", base_url);
    let req_body = serde_json::json!({
        "current_version": CURRENT_VERSION,
    });

    println!("Checking version (current: {})", CURRENT_VERSION);

    let resp = client
        .post(&url)
        .json(&req_body)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to send version check request: {}", e))?;

    let response: VersionCheckResponse = resp
        .json()
        .await
        .map_err(|e| anyhow!("Failed to parse version check response: {}", e))?;

    if !response.is_latest {
        println!("📦 A new version is available!");
        if let Some(version) = &response.latest_version {
            println!("Latest version: {}", version);
        }
        println!("Download the latest version here: {}", response.download_link);

        if let Some(notes) = response.release_notes {
            println!("\nRelease notes:\n{}", notes);
        }
    } else {
        println!("✅ You are using the latest version ({})", CURRENT_VERSION);
    }

    Ok(())
}

async fn improved_download_file(
    client: &Client,
    base_url: &str,
    user_id: &str,
    user_app_key: &str,
    file_name: &str,
    output_path: &str,
) -> Result<()> {
    let url = format!(
        "{}/download?user_id={}&user_app_key={}&file_name={}",
        base_url, user_id, user_app_key, file_name
    );

    let progress = ProgressBar::new(0);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .expect("Progress bar template is valid")
            .progress_chars("#>-"),
    );

    let mut retry_count = 0;
    let mut delay = INITIAL_RETRY_DELAY_MS;

    loop {
        match download_with_progress(client, &url, output_path, &progress).await {
            Ok(_) => {
                progress.finish_with_message("Download completed successfully");
                return Ok(());
            }
            Err(e) => {
                if retry_count >= MAX_RETRIES {
                    progress.finish_with_message("Download failed");
                    return Err(anyhow!(
                        "Download failed after {} retries: {}",
                        MAX_RETRIES,
                        e
                    ));
                }

                eprintln!("Download attempt {} failed: {}", retry_count + 1, e);
                retry_count += 1;
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                delay = std::cmp::min(delay * 2, MAX_RETRY_DELAY_MS);
                progress.set_message(format!("Retrying... Attempt {}/{}", retry_count + 1, MAX_RETRIES));
            }
        }
    }
}

async fn download_with_progress(
    client: &Client,
    url: &str,
    output_path: &str,
    progress: &ProgressBar,
) -> Result<()> {
    let resp = client.get(url).send().await?;
    let status = resp.status();

    if !status.is_success() {
        let error_text = resp.text().await?;
        return Err(anyhow!(
            "Download failed with status {}: {}",
            status,
            error_text
        ));
    }

    let total_size = resp.content_length().unwrap_or(0);
    progress.set_length(total_size);

    let file = tokio::fs::File::create(output_path).await?;
    let mut writer = BufWriter::new(file);
    let mut stream = resp.bytes_stream();
    let mut downloaded: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        writer.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        progress.set_position(downloaded);
    }

    writer.flush().await?;
    Ok(())
}

async fn upload_file(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
) -> Result<String> {
    let f = TokioFile::open(file_path).await
        .map_err(|e| anyhow!("Failed to open local file: {}", e))?;
    let meta = f.metadata().await?;
    let file_size = meta.len();

    let stream_reader = ReaderStream::with_capacity(f, 64 * 1024);
    let body = Body::wrap_stream(stream_reader);

    let resp = client
        .post(full_url)
        .header("Content-Length", file_size)
        .body(body)
        .send()
        .await?;

    let status = resp.status();
    let text_body = resp.text().await?;
    if status.is_success() {
        println!("Upload success => server says: {}", text_body);
        Ok(file_name_in_bucket.to_string())
    } else {
        Err(anyhow!(
            "Upload of '{}' failed. Status={}, Body={}",
            file_path.display(),
            status,
            text_body
        ))
    }
}

async fn upload_file_priority(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
) -> Result<String> {
    let f = TokioFile::open(file_path).await?;
    let meta = f.metadata().await?;
    let file_size = meta.len();

    let progress = ProgressBar::new(file_size);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use futures_util::Stream;
    use tokio_util::io::ReaderStream as InnerReaderStream;

    struct ProgressStream<S> {
        inner: S,
        progress: ProgressBar,
        bytes_uploaded: u64,
    }

    impl<S> Stream for ProgressStream<S>
    where
        S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
    {
        type Item = Result<Bytes, std::io::Error>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    self.bytes_uploaded += chunk.len() as u64;
                    self.progress.set_position(self.bytes_uploaded);
                    Poll::Ready(Some(Ok(chunk)))
                }
                other => other,
            }
        }
    }

    let wrapped_stream = ProgressStream {
        inner: InnerReaderStream::with_capacity(f, 64 * 1024),
        progress: progress.clone(),
        bytes_uploaded: 0,
    };

    let body = Body::wrap_stream(wrapped_stream);

    progress.set_message("Uploading (priority)...");
    let resp = client
        .post(full_url)
        .header("Content-Length", file_size)
        .body(body)
        .send()
        .await?;

    let status = resp.status();
    let text_body = resp.text().await?;
    if status.is_success() {
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&text_body) {
            if let Some(st) = json_val.get("status") {
                if st == "uploading" {
                    // Means the server accepted the file for a background upload
                    progress.finish_with_message("Background upload started by server");
                    println!("Server response: {}", text_body);
                    return Ok(file_name_in_bucket.to_string());
                }
            }
        }
        progress.finish_with_message("Priority upload finished successfully");
        println!("Server says: {}", text_body);
        Ok(file_name_in_bucket.to_string())
    } else {
        progress.finish_and_clear();
        Err(anyhow!(
            "Priority upload of '{}' failed. Status={}, Body={}",
            file_path.display(),
            status,
            text_body
        ))
    }
}

/// Priority-download a file as a base64 string, then decode it.
async fn priority_download_single_file(
    client: &Client,
    base_url: &str,
    user_id: &str,
    user_app_key: &str,
    file_name_in_bucket: &str,
) -> Result<Vec<u8>> {
    let url = format!(
        "{}/priorityDownload?user_id={}&user_app_key={}&file_name={}",
        base_url, user_id, user_app_key, file_name_in_bucket
    );

    let resp = client.get(&url).send().await?;
    let status = resp.status();
    let text_body = resp.text().await?;
    if status.is_success() {
        let decoded = general_purpose::STANDARD
            .decode(&text_body)
            .map_err(|e| anyhow!("Base64 decode error: {}", e))?;
        Ok(decoded)
    } else {
        Err(anyhow!(
            "Priority download of '{}' failed. Status={}, Body={}",
            file_name_in_bucket,
            status,
            text_body
        ))
    }
}

pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new();
    let base_url = cli.api.trim_end_matches('/');

    // Only check version for certain commands
    let should_check_version = matches!(
        cli.command,
        Commands::NewUser { .. }
            | Commands::RotateAppKey { .. }
            | Commands::UploadFile { .. }
            | Commands::DownloadFile { .. }
            | Commands::DeleteFile { .. }
            | Commands::CheckSol { .. }
            | Commands::CheckToken { .. }
            | Commands::SwapSolForPipe { .. }
            | Commands::SwapPipeForDc { .. }
            | Commands::WithdrawSol { .. }
            | Commands::WithdrawCustomToken { .. }
            | Commands::CreatePublicLink { .. }
            | Commands::PublicDownload { .. }
            | Commands::UploadDirectory { .. }
            | Commands::PriorityUploadDirectory { .. }
            | Commands::GetPriorityFee
            | Commands::PriorityUpload { .. }
            | Commands::PriorityDownload { .. }
            | Commands::ListUploads
            | Commands::ExtendStorage { .. }
    );

    if should_check_version {
        println!("Starting version check...");
        if let Err(e) = check_version(&client, base_url).await {
            eprintln!("Version check failed: {}", e);
        } else {
            println!("Version check completed successfully.");
        }
    }

    match cli.command {
        Commands::NewUser { username } => {
            let req_body = CreateUserRequest { username };
            let resp = client
                .post(format!("{}/users", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<CreateUserResponse>(&text_body)?;
                println!(
                    "User created!\nUser ID: {}\nApp Key: {}\nSolana Pubkey: {}",
                    json.user_id, json.user_app_key, json.solana_pubkey
                );

                save_credentials_to_file(&json.user_id, &json.user_app_key)?;
            } else {
                return Err(anyhow!(
                    "Failed to create user. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::RotateAppKey {
            user_id,
            old_app_key,
        } => {
            let (user_id_final, old_app_key_final) =
                get_final_user_id_and_app_key(user_id, old_app_key)?;

            let req_body = RotateAppKeyRequest {
                user_id: user_id_final.clone(),
                user_app_key: old_app_key_final.clone(),
            };

            let resp = client
                .post(format!("{}/rotateAppKey", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;
            if status.is_success() {
                let json = serde_json::from_str::<RotateAppKeyResponse>(&text_body)?;
                println!(
                    "App key rotated!\nUser ID: {}\nNEW APP KEY: {}",
                    json.user_id, json.new_user_app_key
                );

                save_credentials_to_file(&json.user_id, &json.new_user_app_key)?;
            } else {
                return Err(anyhow!(
                    "Rotate app key failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::UploadFile {
            user_id,
            user_app_key,
            file_path,
            file_name,
            epochs,
        } => {
            let (user_id_final, user_app_key_final) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            let local_path = Path::new(&file_path);
            if !local_path.exists() {
                return Err(anyhow!("Local file not found: {}", file_path));
            }

            let epochs_final = epochs.unwrap_or(1); // default 1 month
            let url_with_epochs = format!(
                "{}/upload?user_id={}&user_app_key={}&file_name={}&epochs={}",
                base_url, user_id_final, user_app_key_final, file_name, epochs_final
            );

            match upload_file(&client, local_path, &url_with_epochs, &file_name).await {
                Ok(uploaded_filename) => {
                    println!("File uploaded successfully: {}", uploaded_filename);
                    append_to_upload_log(
                        &file_path,
                        &uploaded_filename,
                        "SUCCESS",
                        &format!("Non-priority upload ({} epochs)", epochs_final)
                    )?;
                }
                Err(e) => {
                    eprintln!("Upload failed for {} => {}", file_path, e);
                    append_to_upload_log(
                        &file_path,
                        &file_name,
                        "FAIL",
                        &format!("Non-priority upload error: {}", e)
                    )?;
                    return Err(e);
                }
            }
        }

        Commands::DownloadFile {
            user_id,
            user_app_key,
            file_name,
            output_path,
        } => {
            let (user_id_final, user_app_key_final) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            improved_download_file(
                &client,
                base_url,
                &user_id_final,
                &user_app_key_final,
                &file_name,
                &output_path,
            )
            .await?;
        }

        Commands::DeleteFile {
            user_id,
            user_app_key,
            file_name,
        } => {
            let (user_id_final, user_app_key_final) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            let req_body = DeleteFileRequest {
                user_id: user_id_final,
                user_app_key: user_app_key_final,
                file_name: file_name.clone(),
            };

            let resp = client
                .post(format!("{}/deleteFile", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<DeleteFileResponse>(&text_body)?;
                println!("Delete success: {}", json.message);
            } else {
                return Err(anyhow!(
                    "Delete file failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::CheckSol {
            user_id,
            user_app_key,
        } => {
            let (uid, key) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            let req_body = CheckWalletRequest {
                user_id: uid,
                user_app_key: key,
            };

            let resp = client
                .post(format!("{}/checkWallet", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<CheckWalletResponse>(&text_body)?;
                println!(
                    "SOL Balance for user: {}\nPubkey: {}\nLamports: {}\nSOL: {}",
                    json.user_id, json.public_key, json.balance_lamports, json.balance_sol
                );
            } else {
                return Err(anyhow!(
                    "Check SOL balance failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::CheckToken {
            user_id,
            user_app_key,
        } => {
            let (uid, key) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            let req_body = CheckCustomTokenRequest {
                user_id: uid,
                user_app_key: key,
            };

            let resp = client
                .post(format!("{}/checkCustomToken", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<CheckCustomTokenResponse>(&text_body)?;
                println!(
                    "Token Balance for user: {}\nPubkey: {}\nMint: {}\nAmount: {}\nUI: {}",
                    json.user_id, json.public_key, json.token_mint, json.amount, json.ui_amount
                );
            } else {
                return Err(anyhow!(
                    "Check Token balance failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::SwapSolForPipe {
            user_id,
            user_app_key,
            amount_sol,
        } => {
            let (uid, key) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            let req_body = SwapSolForPipeRequest {
                user_id: uid,
                user_app_key: key,
                amount_sol,
            };
            let resp = client
                .post(format!("{}/exchangeSolForTokens", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<SwapSolForPipeResponse>(&text_body)?;
                println!(
                    "Swap SOL -> PIPE complete!\nUser: {}\nSOL spent: {}\nPIPE minted: {}",
                    json.user_id, json.sol_spent, json.tokens_minted
                );
            } else {
                return Err(anyhow!(
                    "SwapSolForPipe failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::SwapPipeForDc {
            user_id,
            user_app_key,
            pipe_amount,
        } => {
            let (uid, key) = get_final_user_id_and_app_key(user_id, user_app_key)?;

            let req_body = SwapPipeForDcRequest {
                user_id: uid,
                user_app_key: key,
                amount_pipe: pipe_amount,
            };

            let resp = client
                .post(format!("{}/exchangePipeForDc", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;
            if status.is_success() {
                let data: SwapPipeForDcResponse = serde_json::from_str(&text_body)?;
                println!(
                    "Swap PIPE -> DC successful!\nUser: {}\nPIPE burned: {}\nDC minted: {}",
                    data.user_id, data.pipe_spent, data.dc_minted
                );
            } else {
                return Err(anyhow!(
                    "SwapPipeForDc failed. status={}, body={}",
                    status,
                    text_body
                ));
            }
        }

        Commands::WithdrawSol {
            user_id,
            user_app_key,
            to_pubkey,
            amount_sol,
        } => {
            let (uid, key) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            let req_body = WithdrawSolRequest {
                user_id: uid,
                user_app_key: key,
                to_pubkey,
                amount_sol,
            };

            let resp = client
                .post(format!("{}/withdrawSol", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<WithdrawSolResponse>(&text_body)?;
                println!(
                    "SOL Withdrawal complete!\nUser: {}\nTo: {}\nAmount SOL: {}\nSignature: {}",
                    json.user_id, json.to_pubkey, json.amount_sol, json.signature
                );
            } else {
                return Err(anyhow!(
                    "Withdraw SOL failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::WithdrawCustomToken {
            user_id,
            user_app_key,
            to_pubkey,
            amount,
        } => {
            let (uid, key) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            let req_body = WithdrawTokenRequest {
                user_id: uid,
                user_app_key: key,
                to_pubkey,
                amount,
            };

            let resp = client
                .post(format!("{}/withdrawToken", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<WithdrawTokenResponse>(&text_body)?;
                println!(
                    "Token Withdrawal complete!\nUser: {}\nTo: {}\nAmount: {}\nSignature: {}",
                    json.user_id, json.to_pubkey, json.amount, json.signature
                );
            } else {
                return Err(anyhow!(
                    "Withdraw custom token failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::CreatePublicLink {
            user_id,
            user_app_key,
            file_name,
        } => {
            let (uid, key) = get_final_user_id_and_app_key(user_id, user_app_key)?;

            let req_body = CreatePublicLinkRequest {
                user_id: uid,
                user_app_key: key,
                file_name,
            };

            let resp = client
                .post(format!("{}/createPublicLink", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;
            if status.is_success() {
                let json: CreatePublicLinkResponse = serde_json::from_str(&text_body)?;
                println!(
                    "Public link created! Link hash: {}/publicDownload?hash={}",
                    base_url, json.link_hash
                );
                println!(
                    "Use `publicDownload?hash={}` to download the file without auth.",
                    json.link_hash
                );
            } else {
                return Err(anyhow!(
                    "Create public link failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::PublicDownload { hash, output_path } => {
            let url = format!("{}/publicDownload?hash={}", base_url, hash);
            let resp = client.get(&url).send().await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let decoded = general_purpose::STANDARD
                    .decode(&text_body)
                    .map_err(|e| anyhow!("Base64 decode error: {}", e))?;

                fs::write(&output_path, &decoded)?;
                println!("Public file downloaded to {}", output_path);
            } else {
                return Err(anyhow!(
                    "Public download failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::UploadDirectory {
            user_id,
            user_app_key,
            directory_path,
        } => {
            let (uid, key) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            let dir = Path::new(&directory_path);
            if !dir.is_dir() {
                return Err(anyhow!("Provided path is not a directory: {}", directory_path));
            }

            let file_entries: Vec<_> = WalkDir::new(dir)
                .into_iter()
                .filter_map(|entry| {
                    match entry {
                        Ok(e) if e.path().is_file() => Some(e.path().to_owned()),
                        _ => None,
                    }
                })
                .collect();

            let concurrency_limit = 100;
            let sem = Arc::new(Semaphore::new(concurrency_limit));
            let mut handles = Vec::new();

            for path in file_entries {
                let sem_clone = Arc::clone(&sem);
                let client_clone = client.clone();
                let base_url_clone = base_url.to_string();
                let user_id_clone = uid.clone();
                let user_app_key_clone = key.clone();

                let rel_path = match path.strip_prefix(dir) {
                    Ok(r) => r.to_string_lossy().to_string(),
                    Err(_) => path
                        .file_name()
                        .map(|os| os.to_string_lossy().to_string())
                        .unwrap_or_else(|| "untitled".to_string()),
                };

                let handle = tokio::spawn(async move {
                    let _permit = sem_clone.acquire_owned().await.unwrap();
                    let url_no_epochs = format!(
                        "{}/upload?user_id={}&user_app_key={}&file_name={}",
                        base_url_clone, user_id_clone, user_app_key_clone, rel_path
                    );

                    match upload_file(&client_clone, &path, &url_no_epochs, &rel_path).await {
                        Ok(uploaded_file) => {
                            println!("Uploaded: {}", uploaded_file);
                            let _ = append_to_upload_log(
                                &path.display().to_string(),
                                &uploaded_file,
                                "SUCCESS",
                                "Directory upload success"
                            );
                        }
                        Err(e) => {
                            eprintln!("Failed to upload {}: {}", path.display(), e);
                            let _ = append_to_upload_log(
                                &path.display().to_string(),
                                &rel_path,
                                "FAIL",
                                &format!("Directory upload error: {}", e)
                            );
                        }
                    }
                });

                handles.push(handle);
            }

            for h in handles {
                let _ = h.await;
            }

            println!(
                "Directory upload complete. Check the log file for details:\n  {}",
                get_upload_log_path().display()
            );
        }

        Commands::PriorityUploadDirectory {
            user_id,
            user_app_key,
            directory_path,
            skip_uploaded,
            concurrency,
        } => {
            let (uid, key) = get_final_user_id_and_app_key(user_id, user_app_key)?;

            let dir = Path::new(&directory_path);
            if !dir.is_dir() {
                return Err(anyhow!("Provided path is not a directory: {}", directory_path));
            }

            // Get current priority fee from server
            let url = format!("{}/getPriorityFee", base_url);
            let resp = client.get(&url).send().await?;
            let fee_resp: PriorityFeeResponse = resp.json().await?;
            println!("Current priority fee: {} tokens/GB", fee_resp.priority_fee_per_gb);
            println!("Starting priority upload of directory...");

            // Read upload log if skip_uploaded == true
            let mut previously_uploaded: HashSet<String> = HashSet::new();
            if skip_uploaded {
                let log_path = get_upload_log_path();
                if log_path.exists() {
                    let contents = fs::read_to_string(&log_path)?;
                    for line in contents.lines() {
                        if let Ok(entry) = serde_json::from_str::<UploadLogEntry>(line) {
                            if entry.status.contains("SUCCESS") || entry.status.contains("BACKGROUND") {
                                previously_uploaded.insert(entry.local_path);
                            }
                        }
                    }
                }
                println!("Found {} previously uploaded files in log", previously_uploaded.len());
            }

            let file_entries: Vec<_> = WalkDir::new(dir)
                .into_iter()
                .filter_map(|entry| {
                    match entry {
                        Ok(e) if e.path().is_file() => Some(e.path().to_owned()),
                        _ => None,
                    }
                })
                .collect();

            println!("Found {} files to upload", file_entries.len());

            let total_files = file_entries.len() as u64;
            let progress = Arc::new(ProgressBar::new(total_files));
            progress.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] \
                         {pos}/{len} ({eta}) - {msg}"
                    )
                    .unwrap()
                    .progress_chars("#>-"),
            );
            progress.set_message("Uploading files...");

            let sem = Arc::new(Semaphore::new(concurrency));
            let mut handles = Vec::new();

            for path in file_entries {
                if skip_uploaded && previously_uploaded.contains(&path.display().to_string()) {
                    println!("Skipping previously uploaded file: {}", path.display());
                    progress.inc(1);
                    continue;
                }

                let sem_clone = Arc::clone(&sem);
                let client_clone = client.clone();
                let base_url_clone = base_url.to_string();
                let user_id_clone = uid.clone();
                let user_app_key_clone = key.clone();
                let progress_clone = Arc::clone(&progress);

                let rel_path = match path.strip_prefix(dir) {
                    Ok(r) => r.to_string_lossy().to_string(),
                    Err(_) => path
                        .file_name()
                        .map(|os| os.to_string_lossy().to_string())
                        .unwrap_or_else(|| "untitled".to_string()),
                };

                let handle = tokio::spawn(async move {
                    let _permit = sem_clone.acquire_owned().await.unwrap();
                    let url_no_epochs = format!(
                        "{}/priorityUpload?user_id={}&user_app_key={}&file_name={}",
                        base_url_clone, user_id_clone, user_app_key_clone, rel_path
                    );

                    match upload_file_priority(&client_clone, &path, &url_no_epochs, &rel_path).await {
                        Ok(uploaded_file) => {
                            println!("Priority Uploaded: {}", uploaded_file);
                            let _ = append_to_upload_log(
                                &path.display().to_string(),
                                &uploaded_file,
                                "PRIORITY SUCCESS",
                                "Priority directory upload success"
                            );
                        }
                        Err(e) => {
                            eprintln!("Failed priority upload {}: {}", path.display(), e);
                            let _ = append_to_upload_log(
                                &path.display().to_string(),
                                &rel_path,
                                "PRIORITY FAIL",
                                &format!("Priority directory upload error: {}", e)
                            );
                        }
                    }
                    progress_clone.inc(1);
                });

                handles.push(handle);
            }

            for h in handles {
                let _ = h.await;
            }

            progress.finish_with_message("Priority directory upload complete!");
            println!(
                "Check the log file for details:\n  {}",
                get_upload_log_path().display()
            );
        }

        Commands::GetPriorityFee => {
            let url = format!("{}/getPriorityFee", base_url);
            let resp = client.get(&url).send().await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let parsed = serde_json::from_str::<PriorityFeeResponse>(&text_body)?;
                // For demonstration, a placeholder for normal fees:
                let normal_fee_per_gb = 1.0;
                println!("Normal (non-priority) fee per GB: {}", normal_fee_per_gb);
                println!(
                    "Estimated priority fee per GB if you start now: {} tokens/GB",
                    parsed.priority_fee_per_gb
                );
            } else {
                return Err(anyhow!(
                    "Failed to get priority fee. Status={}, Body={}",
                    status,
                    text_body
                ));
            }
        }

        Commands::PriorityUpload {
            user_id,
            user_app_key,
            file_path,
            file_name,
            epochs,
        } => {
            let (uid, key) = get_final_user_id_and_app_key(user_id, user_app_key)?;

            let local_path = Path::new(&file_path);
            if !local_path.exists() {
                return Err(anyhow!("Local file not found: {}", file_path));
            }

            let epochs_final = epochs.unwrap_or(1);
            let url_with_epochs = format!(
                "{}/priorityUpload?user_id={}&user_app_key={}&file_name={}&epochs={}",
                base_url, uid, key, file_name, epochs_final
            );

            match upload_file_priority(&client, local_path, &url_with_epochs, &file_name).await {
                Ok(uploaded_filename) => {
                    println!("Priority file uploaded (or backgrounded): {}", uploaded_filename);
                    append_to_upload_log(
                        &file_path,
                        &uploaded_filename,
                        "PRIORITY SUCCESS",
                        &format!("Priority upload ({} epochs)", epochs_final)
                    )?;
                }
                Err(e) => {
                    eprintln!("Priority upload failed for {} => {}", file_path, e);
                    append_to_upload_log(
                        &file_path,
                        &file_name,
                        "PRIORITY FAIL",
                        &format!("Priority single upload error: {}", e)
                    )?;
                    return Err(e);
                }
            }
        }

        Commands::PriorityDownload {
            user_id,
            user_app_key,
            file_name,
            output_path,
        } => {
            let (uid, key) = get_final_user_id_and_app_key(user_id, user_app_key)?;

            match priority_download_single_file(&client, base_url, &uid, &key, &file_name).await {
                Ok(file_data) => {
                    fs::write(&output_path, &file_data)?;
                    println!("Priority file downloaded to {}", output_path);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Commands::ListUploads => {
            let log_path = get_upload_log_path();
            if !log_path.exists() {
                println!("No upload log found at {}", log_path.display());
            } else {
                let contents = fs::read_to_string(&log_path)?;
                for (i, line) in contents.lines().enumerate() {
                    if let Ok(entry) = serde_json::from_str::<UploadLogEntry>(line) {
                        println!(
                            "{}: local='{}', remote='{}', status='{}', msg='{}'",
                            i + 1,
                            entry.local_path,
                            entry.remote_path,
                            entry.status,
                            entry.message
                        );
                    } else {
                        println!("{}: (unparseable JSON) => {}", i + 1, line);
                    }
                }
            }
        }

        Commands::ExtendStorage {
            user_id,
            user_app_key,
            file_name,
            additional_months,
        } => {
            let (uid, key) = get_final_user_id_and_app_key(user_id, user_app_key)?;

            let req_body = ExtendStorageRequest {
                user_id: uid,
                user_app_key: key,
                file_name,
                additional_months,
            };

            let url = format!("{}/extendStorage", base_url);
            let resp = client
                .post(url)
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let parsed = serde_json::from_str::<ExtendStorageResponse>(&text_body)?;
                println!(
                    "ExtendStorage success: {}\nNew expiration date: {}",
                    parsed.message, parsed.new_expires_at
                );
            } else {
                return Err(anyhow!(
                    "ExtendStorage failed. status={}, body={}",
                    status,
                    text_body
                ));
            }
        }
    }

    Ok(())
}
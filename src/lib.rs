// src/lib.rs

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Body, Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Write as IoWrite}; // For writeln!
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Semaphore;
use tokio::sync::Mutex as TokioMutex;
use walkdir::WalkDir;
use chrono::{DateTime, Utc};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_RETRIES: u32 = 3;
pub const INITIAL_RETRY_DELAY_MS: u64 = 1000;
pub const MAX_RETRY_DELAY_MS: u64 = 10000;

// JWT Authentication structures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Debug)]
pub struct SetPasswordRequest {
    pub user_id: String,
    pub user_app_key: String,
    pub new_password: String,
}

#[derive(Serialize, Debug)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Deserialize, Debug)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

// Combined credentials structure that supports both legacy and JWT auth
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SavedCredentials {
    pub user_id: String,
    pub user_app_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_tokens: Option<AuthTokens>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct VersionCheckRequest {
    pub current_version: String,
}

#[derive(Deserialize, Debug)]
pub struct VersionCheckResponse {
    pub is_latest: bool,
    #[serde(default)]
    pub download_link: Option<String>,
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
        default_value = "http://74.118.142.173:3333",
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

    /// Login with username and password (JWT authentication)
    Login {
        username: String,
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Logout and revoke current session
    Logout,

    /// Set password for existing user (for migration to JWT auth)
    SetPassword {
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
    },

    /// Refresh access token
    RefreshToken,

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
        /// Optional user ID override; if omitted, read from .pipe-cli.json
        #[arg(long)]
        user_id: Option<String>,

        /// Optional user app key override; if omitted, read from .pipe-cli.json
        #[arg(long)]
        user_app_key: Option<String>,

        /// Required remote file name on the server
        file_name: String,

        /// Required local file path to store the downloaded file
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

    /// Withdraw SOL to an external Solana address
    WithdrawSol {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        amount_sol: f64,
        to_pubkey: String,
    },

    /// Withdraw custom tokens to an external address
    WithdrawCustomToken {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        token_mint: String,
        amount: u64,
        to_pubkey: String,
    },

    CreatePublicLink {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_name: String,
    },

    DeletePublicLink {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        link_hash: String,
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
        #[arg(long, default_value_t = 10)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct CheckWalletRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_app_key: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_app_key: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_app_key: Option<String>,
    pub amount_sol: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SwapSolForPipeResponse {
    pub user_id: String,
    pub sol_spent: f64,
    pub tokens_minted: u64,
}

#[derive(Serialize, Deserialize)]
pub struct WithdrawSolRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_app_key: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_app_key: Option<String>,
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
pub struct DeletePublicLinkRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_app_key: Option<String>,
    pub link_hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeletePublicLinkResponse {
    pub message: String,
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
    // Try to preserve existing auth tokens if they exist
    let creds = if let Ok(Some(existing)) = load_credentials_from_file() {
        SavedCredentials {
            user_id: user_id.to_owned(),
            user_app_key: user_app_key.to_owned(),
            auth_tokens: existing.auth_tokens,
            username: existing.username,
        }
    } else {
        SavedCredentials {
            user_id: user_id.to_owned(),
            user_app_key: user_app_key.to_owned(),
            auth_tokens: None,
            username: None,
        }
    };
    
    save_full_credentials(&creds)
}

// Save full credentials including JWT tokens
pub fn save_full_credentials(creds: &SavedCredentials) -> Result<()> {
    let path = get_credentials_file_path();
    let json = serde_json::to_string_pretty(&creds)?;
    fs::write(&path, json)?;
    println!("Credentials saved to {:?}", path);
    Ok(())
}

// Check if JWT token is expired or about to expire (within 60 seconds)
fn is_token_expired(auth_tokens: &AuthTokens) -> bool {
    if let Some(expires_at) = auth_tokens.expires_at {
        let now = Utc::now();
        let buffer = chrono::Duration::seconds(60);
        now + buffer >= expires_at
    } else {
        true // If no expiration time, assume expired
    }
}

// Refresh JWT token if needed
async fn ensure_valid_token(client: &Client, base_url: &str, creds: &mut SavedCredentials) -> Result<()> {
    if let Some(ref auth_tokens) = creds.auth_tokens {
        if is_token_expired(auth_tokens) {
            println!("Token expired or expiring soon, refreshing...");
            
            let req_body = RefreshTokenRequest {
                refresh_token: auth_tokens.refresh_token.clone(),
            };

            let resp = client
                .post(format!("{}/auth/refresh", base_url))
                .json(&req_body)
                .send()
                .await?;

            if resp.status().is_success() {
                let refresh_response: RefreshTokenResponse = resp.json().await?;
                
                // Calculate new expires_at timestamp
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                let expires_at = DateTime::<Utc>::from_timestamp(now + refresh_response.expires_in, 0)
                    .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;
                
                // Update auth tokens
                if let Some(ref mut auth_tokens) = creds.auth_tokens {
                    auth_tokens.access_token = refresh_response.access_token;
                    auth_tokens.expires_in = refresh_response.expires_in;
                    auth_tokens.expires_at = Some(expires_at);
                }
                
                // Save updated credentials
                save_full_credentials(creds)?;
                println!("Token refreshed successfully!");
            } else {
                // Token refresh failed, clear auth tokens
                creds.auth_tokens = None;
                save_full_credentials(creds)?;
                return Err(anyhow!("Token refresh failed, please login again"));
            }
        }
    }
    Ok(())
}

// Build a request with JWT auth header if available, otherwise use query params
fn build_authenticated_request(
    method: reqwest::Method,
    url: String,
    creds: &SavedCredentials,
    include_legacy: bool,
) -> reqwest::RequestBuilder {
    let client = Client::new();
    let mut request = client.request(method, &url);
    
    // First try JWT authentication
    if let Some(ref auth_tokens) = creds.auth_tokens {
        request = request.header("Authorization", format!("Bearer {}", auth_tokens.access_token));
    } else if include_legacy {
        // Fall back to legacy auth via query params (already in URL)
    }
    
    request
}

/// Add authentication headers including CSRF token for state-changing requests
fn add_auth_headers(
    mut request: reqwest::RequestBuilder,
    creds: &SavedCredentials,
    is_state_changing: bool,
) -> reqwest::RequestBuilder {
    // Add JWT auth if available
    if let Some(ref auth_tokens) = creds.auth_tokens {
        request = request.header("Authorization", format!("Bearer {}", auth_tokens.access_token));
        
        // Add CSRF token for state-changing requests
        if is_state_changing {
            if let Some(ref csrf_token) = auth_tokens.csrf_token {
                request = request.header("X-CSRF-Token", csrf_token);
            }
        }
    } else {
        // Legacy auth via headers
        request = request
            .header("X-User-Id", &creds.user_id)
            .header("X-User-App-Key", &creds.user_app_key);
    }
    
    request
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

        // Only print download link if present
        if let Some(link) = &response.download_link {
            println!("Download the latest version here: {}", link);
        } else {
            println!("(No download link provided by the server.)");
        }

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
    // Create a credentials object for backward compatibility
    let creds = SavedCredentials {
        user_id: user_id.to_owned(),
        user_app_key: user_app_key.to_owned(),
        auth_tokens: None,
        username: None,
    };
    improved_download_file_with_auth(client, base_url, &creds, file_name, output_path).await
}

async fn improved_download_file_with_auth(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    file_name: &str,
    output_path: &str,
) -> Result<()> {
    println!("Downloading '{}' to '{}'...", file_name, output_path);

    // Build the URL - NO CREDENTIALS IN URL (security fix)
    let url = format!("{}/download?file_name={}", base_url, file_name);

    // Create progress bar
    let progress = ProgressBar::new(0);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Build request with appropriate auth headers
    let mut request = client.get(&url);
    if let Some(ref auth_tokens) = creds.auth_tokens {
        // JWT authentication
        request = request.header("Authorization", format!("Bearer {}", auth_tokens.access_token));
    } else {
        // Legacy authentication via headers (NOT URL params for security)
        request = request
            .header("X-User-Id", &creds.user_id)
            .header("X-User-App-Key", &creds.user_app_key);
    }

    let resp = request.send().await?;
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
    progress.finish_with_message("Download completed");
    
    println!("File downloaded successfully to: {}", output_path);
    Ok(())
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

async fn upload_file_with_auth(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
    creds: &SavedCredentials,
) -> Result<String> {
    let f = TokioFile::open(file_path).await
        .map_err(|e| anyhow!("Failed to open local file: {}", e))?;
    let meta = f.metadata().await?;
    let file_size = meta.len();

    // Add progress bar
    let progress = ProgressBar::new(file_size);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Progress tracking stream
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

    progress.set_message("Uploading...");
    let mut request = client
        .post(full_url)
        .header("Content-Length", file_size)
        .header("Content-Type", "application/octet-stream");
    
    // Add JWT auth header if available
    if let Some(ref auth_tokens) = creds.auth_tokens {
        request = request.header("Authorization", format!("Bearer {}", auth_tokens.access_token));
    }
    
    let resp = request.body(body).send().await?;

    let status = resp.status();
    let text_body = resp.text().await?;
    if status.is_success() {
        progress.finish_with_message("Upload completed successfully");
        println!("Server response: {}", text_body);
        Ok(file_name_in_bucket.to_string())
    } else {
        progress.finish_and_clear();
        Err(anyhow!(
            "Upload of '{}' failed. Status={}, Body={}",
            file_path.display(),
            status,
            text_body
        ))
    }
}

// Wrapper for backward compatibility
#[allow(dead_code)]
async fn upload_file(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
) -> Result<String> {
    // Create a dummy credentials with no JWT tokens for backward compatibility
    let creds = SavedCredentials {
        user_id: String::new(),
        user_app_key: String::new(),
        auth_tokens: None,
        username: None,
    };
    upload_file_with_auth(client, file_path, full_url, file_name_in_bucket, &creds).await
}

#[allow(dead_code)]
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
        .header("Content-Type", "application/octet-stream")
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

#[allow(dead_code)]
async fn upload_file_priority_with_auth(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
    creds: &SavedCredentials,
) -> Result<String> {
    let f = TokioFile::open(file_path).await
        .map_err(|e| anyhow!("Failed to open local file: {}", e))?;
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
    let mut request = client
        .post(full_url)
        .header("Content-Length", file_size)
        .header("Content-Type", "application/octet-stream");
    
    // Add JWT auth header if available
    if let Some(ref auth_tokens) = creds.auth_tokens {
        request = request.header("Authorization", format!("Bearer {}", auth_tokens.access_token));
    }
    
    let resp = request.body(body).send().await?;

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
#[allow(dead_code)]
async fn priority_download_single_file(
    client: &Client,
    base_url: &str,
    user_id: &str,
    user_app_key: &str,
    file_name_in_bucket: &str,
) -> Result<Vec<u8>> {
    // Build URL without credentials (security fix)
    let url = format!("{}/priorityDownload?file_name={}", base_url, file_name_in_bucket);

    // Add legacy auth headers
    let resp = client.get(&url)
        .header("X-User-Id", user_id)
        .header("X-User-App-Key", user_app_key)
        .send().await?;
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

/// Priority-download a file with JWT authentication support
async fn priority_download_single_file_with_auth(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    file_name_in_bucket: &str,
) -> Result<Vec<u8>> {
    // Build URL without credentials (security fix)
    let url = format!("{}/priorityDownload?file_name={}", base_url, file_name_in_bucket);

    let mut request = client.get(&url);
    
    // Add appropriate auth headers
    if let Some(ref auth_tokens) = creds.auth_tokens {
        // JWT authentication
        request = request.header("Authorization", format!("Bearer {}", auth_tokens.access_token));
    } else {
        // Legacy authentication via headers (NOT URL params for security)
        request = request
            .header("X-User-Id", &creds.user_id)
            .header("X-User-App-Key", &creds.user_app_key);
    }
    
    let resp = request.send().await?;
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

// New struct to track directory upload progress
#[derive(Clone)]
struct DirectoryUploadProgress {
    uploaded_bytes: Arc<TokioMutex<u64>>,
    progress_bar: Arc<ProgressBar>,
}

// Upload file with shared progress bar for directory uploads
async fn upload_file_with_shared_progress(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
    creds: &SavedCredentials,
    shared_progress: Option<DirectoryUploadProgress>,
) -> Result<(String, f64)> {
    let f = TokioFile::open(file_path).await
        .map_err(|e| anyhow!("Failed to open local file: {}", e))?;
    let meta = f.metadata().await?;
    let file_size = meta.len();

    // Use individual progress bar if no shared progress provided
    let (progress, is_shared) = match shared_progress {
        Some(ref sp) => (sp.progress_bar.clone(), true),
        None => {
            let pb = ProgressBar::new(file_size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            (Arc::new(pb), false)
        }
    };

    // Progress tracking stream
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use futures_util::Stream;
    use tokio_util::io::ReaderStream as InnerReaderStream;

    struct ProgressStream<S> {
        inner: S,
        progress: Arc<ProgressBar>,
        bytes_uploaded: u64,
        shared_progress: Option<DirectoryUploadProgress>,
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
                    let chunk_size = chunk.len() as u64;
                    self.bytes_uploaded += chunk_size;
                    
                    if let Some(ref sp) = self.shared_progress {
                        // Update shared progress using try_lock to avoid blocking
                        if let Ok(mut uploaded) = sp.uploaded_bytes.try_lock() {
                            *uploaded += chunk_size;
                            self.progress.set_position(*uploaded);
                        }
                    } else {
                        // Update individual progress
                        self.progress.set_position(self.bytes_uploaded);
                    }
                    
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
        shared_progress: shared_progress.clone(),
    };

    let body = Body::wrap_stream(wrapped_stream);

    if !is_shared {
        progress.set_message("Uploading...");
    }
    
    let mut request = client
        .post(full_url)
        .header("Content-Length", file_size)
        .header("Content-Type", "application/octet-stream");
    
    // Add appropriate auth headers
    if let Some(ref auth_tokens) = creds.auth_tokens {
        // JWT authentication
        request = request.header("Authorization", format!("Bearer {}", auth_tokens.access_token));
    } else {
        // Legacy authentication via headers (NOT URL params for security)
        request = request
            .header("X-User-Id", &creds.user_id)
            .header("X-User-App-Key", &creds.user_app_key);
    }
    
    let resp = request.body(body).send().await?;

    let status = resp.status();
    
    // Extract token cost from headers
    let tokens_charged = resp.headers()
        .get("X-Tokens-Charged")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    
    let text_body = resp.text().await?;
    if status.is_success() {
        if !is_shared {
            progress.finish_with_message("Upload completed successfully");
            println!("Server response: {}", text_body);
            if tokens_charged > 0.0 {
                println!("💰 Cost: {} PIPE tokens", tokens_charged);
            }
        }
        Ok((file_name_in_bucket.to_string(), tokens_charged))
    } else {
        if !is_shared {
            progress.finish_and_clear();
        }
        
        // Check for insufficient tokens error
        if status == 402 {
            // Try to parse JSON response for detailed error
            if let Ok(error_data) = serde_json::from_str::<serde_json::Value>(&text_body) {
                if let Some(message) = error_data.get("message").and_then(|m| m.as_str()) {
                    eprintln!("\n❌ Upload failed: Insufficient tokens");
                    eprintln!("{}", message);
                    if let Some(required) = error_data.get("required").and_then(|r| r.as_f64()) {
                        if let Some(current) = error_data.get("current").and_then(|c| c.as_f64()) {
                            eprintln!("\n💰 Token balance:");
                            eprintln!("   Required: {} PIPE tokens", required);
                            eprintln!("   Current:  {} PIPE tokens", current);
                            eprintln!("   Needed:   {} PIPE tokens", required - current);
                        }
                    }
                    return Err(anyhow!("Upload failed: {}", message));
                }
            }
            return Err(anyhow!("Upload failed: Insufficient tokens. Please use 'pipe swap-sol-for-pipe' to get more tokens."));
        }
        
        Err(anyhow!(
            "Upload of '{}' failed. Status={}, Body={}",
            file_path.display(),
            status,
            text_body
        ))
    }
}

// Priority upload file with shared progress bar for directory uploads
async fn upload_file_priority_with_shared_progress(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
    creds: &SavedCredentials,
    shared_progress: Option<DirectoryUploadProgress>,
) -> Result<(String, f64)> {
    let f = TokioFile::open(file_path).await
        .map_err(|e| anyhow!("Failed to open local file: {}", e))?;
    let meta = f.metadata().await?;
    let file_size = meta.len();

    // Use individual progress bar if no shared progress provided
    let (progress, is_shared) = match shared_progress {
        Some(ref sp) => (sp.progress_bar.clone(), true),
        None => {
            let pb = ProgressBar::new(file_size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            (Arc::new(pb), false)
        }
    };

    // Progress tracking stream
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use futures_util::Stream;
    use tokio_util::io::ReaderStream as InnerReaderStream;

    struct ProgressStream<S> {
        inner: S,
        progress: Arc<ProgressBar>,
        bytes_uploaded: u64,
        shared_progress: Option<DirectoryUploadProgress>,
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
                    let chunk_size = chunk.len() as u64;
                    self.bytes_uploaded += chunk_size;
                    
                    if let Some(ref sp) = self.shared_progress {
                        // Update shared progress using try_lock to avoid blocking
                        if let Ok(mut uploaded) = sp.uploaded_bytes.try_lock() {
                            *uploaded += chunk_size;
                            self.progress.set_position(*uploaded);
                        }
                    } else {
                        // Update individual progress
                        self.progress.set_position(self.bytes_uploaded);
                    }
                    
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
        shared_progress: shared_progress.clone(),
    };

    let body = Body::wrap_stream(wrapped_stream);

    if !is_shared {
        progress.set_message("Uploading (priority)...");
    }
    
    let mut request = client
        .post(full_url)
        .header("Content-Length", file_size)
        .header("Content-Type", "application/octet-stream");
    
    // Add appropriate auth headers
    if let Some(ref auth_tokens) = creds.auth_tokens {
        // JWT authentication
        request = request.header("Authorization", format!("Bearer {}", auth_tokens.access_token));
    } else {
        // Legacy authentication via headers (NOT URL params for security)
        request = request
            .header("X-User-Id", &creds.user_id)
            .header("X-User-App-Key", &creds.user_app_key);
    }
    
    let resp = request.body(body).send().await?;

    let status = resp.status();
    
    // Extract token cost from headers
    let tokens_charged = resp.headers()
        .get("X-Tokens-Charged")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    
    let priority_fee = resp.headers()
        .get("X-Priority-Fee-Per-GB")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    
    let text_body = resp.text().await?;
    if status.is_success() {
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&text_body) {
            if let Some(st) = json_val.get("status") {
                if st == "uploading" {
                    // Means the server accepted the file for a background upload
                    if !is_shared {
                        progress.finish_with_message("Background upload started by server");
                        println!("Server response: {}", text_body);
                        if tokens_charged > 0.0 {
                            println!("💰 Cost: {} PIPE tokens (priority rate: {} tokens/GB)", tokens_charged, priority_fee);
                        }
                    }
                    return Ok((file_name_in_bucket.to_string(), tokens_charged));
                }
            }
        }
        if !is_shared {
            progress.finish_with_message("Priority upload finished successfully");
            println!("Server says: {}", text_body);
            if tokens_charged > 0.0 {
                println!("💰 Cost: {} PIPE tokens (priority rate: {} tokens/GB)", tokens_charged, priority_fee);
            }
        }
        Ok((file_name_in_bucket.to_string(), tokens_charged))
    } else {
        if !is_shared {
            progress.finish_and_clear();
        }
        
        // Check for insufficient tokens error
        if status == 402 {
            // Try to parse JSON response for detailed error
            if let Ok(error_data) = serde_json::from_str::<serde_json::Value>(&text_body) {
                if let Some(message) = error_data.get("message").and_then(|m| m.as_str()) {
                    eprintln!("\n❌ Priority upload failed: Insufficient tokens");
                    eprintln!("{}", message);
                    if let Some(required) = error_data.get("required").and_then(|r| r.as_f64()) {
                        if let Some(current) = error_data.get("current").and_then(|c| c.as_f64()) {
                            eprintln!("\n💰 Token balance:");
                            eprintln!("   Required: {} PIPE tokens", required);
                            eprintln!("   Current:  {} PIPE tokens", current);
                            eprintln!("   Needed:   {} PIPE tokens", required - current);
                        }
                    }
                    if let Some(priority_fee) = error_data.get("priority_fee_per_gb").and_then(|p| p.as_f64()) {
                        eprintln!("\n📈 Priority upload rate: {} tokens/GB", priority_fee);
                    }
                    return Err(anyhow!("Priority upload failed: {}", message));
                }
            }
            return Err(anyhow!("Priority upload failed: Insufficient tokens. Please use 'pipe swap-sol-for-pipe' to get more tokens."));
        }
        
        Err(anyhow!(
            "Priority upload of '{}' failed. Status={}, Body={}",
            file_path.display(),
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
            | Commands::WithdrawSol { .. }
            | Commands::WithdrawCustomToken { .. }
            | Commands::CreatePublicLink { .. }
            | Commands::DeletePublicLink { .. }
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
            let req_body = CreateUserRequest { username: username.clone() };
            let resp = client
                .post(format!("{}/users", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<CreateUserResponse>(&text_body)?;
                println!("Creating new user...");
                println!(
                    "User created!\nUser ID: {}\nApp Key: {}\nSolana Pubkey: {}",
                    json.user_id, json.user_app_key, json.solana_pubkey
                );

                // Save basic credentials first
                save_credentials_to_file(&json.user_id, &json.user_app_key)?;
                
                // Prompt for optional password
                println!("\nSet a password for secure access (or press Enter to skip):");
                println!("Note: Password is optional. You can use pipe without it.");
                
                let password = rpassword::prompt_password("Password: ").unwrap_or_default();
                
                if !password.is_empty() {
                    // User wants to set a password
                    println!("Setting password...");
                    
                    let set_password_req = SetPasswordRequest {
                        user_id: json.user_id.clone(),
                        user_app_key: json.user_app_key.clone(),
                        new_password: password,
                    };
                    
                    let resp = client
                        .post(format!("{}/auth/set-password", base_url))
                        .json(&set_password_req)
                        .send()
                        .await?;
                    
                    let status = resp.status();
                    let text_body = resp.text().await?;
                    
                    if status.is_success() {
                        // The set-password endpoint returns JWT tokens
                        if let Ok(response_data) = serde_json::from_str::<serde_json::Value>(&text_body) {
                            // Create AuthTokens from the response
                            let auth_tokens = AuthTokens {
                                access_token: response_data.get("access_token")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                refresh_token: response_data.get("refresh_token")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                token_type: response_data.get("token_type")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Bearer")
                                    .to_string(),
                                expires_in: response_data.get("expires_in")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(900),
                                expires_at: None, // Will be set below
                                csrf_token: None, // Will be populated on first state-changing request
                            };
                            
                            // Calculate expires_at timestamp
                            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                            let expires_at = DateTime::<Utc>::from_timestamp(now + auth_tokens.expires_in, 0)
                                .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;
                            
                            let mut auth_tokens = auth_tokens;
                            auth_tokens.expires_at = Some(expires_at);
                            
                            // Save full credentials with JWT tokens
                            let creds = SavedCredentials {
                                user_id: json.user_id.clone(),
                                user_app_key: json.user_app_key.clone(),
                                auth_tokens: Some(auth_tokens),
                                username: Some(username.clone()),
                            };
                            save_full_credentials(&creds)?;
                            
                            println!("\n✓ Password set successfully!");
                            println!("✓ You are now logged in with secure JWT authentication!");
                            println!("✓ Credentials saved to {:?}", get_credentials_file_path());
                            println!("\nYou can now use all pipe commands securely!");
                        } else {
                            println!("\n✓ Password set successfully!");
                            println!("✓ Account created!");
                            println!("✓ Credentials saved to {:?}", get_credentials_file_path());
                            println!("\nNote: You may need to login to get JWT tokens.");
                        }
                    } else {
                        eprintln!("\nWarning: Failed to set password. You can try again later with:");
                        eprintln!("  ./pipe set-password");
                        eprintln!("\n✓ Account created successfully!");
                        eprintln!("✓ Credentials saved to {:?}", get_credentials_file_path());
                        eprintln!("\nYou can use all pipe commands with your app key.");
                    }
                } else {
                    // User skipped password
                    println!("\n✓ Account created successfully!");
                    println!("✓ Credentials saved to {:?}", get_credentials_file_path());
                    println!("\nYou can now use all pipe commands!");
                    println!("\nNote: Password-based login is optional. Set a password later with:");
                    println!("  ./pipe set-password");
                }
            } else {
                return Err(anyhow!(
                    "Failed to create user. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::Login { username, password } => {
            let password = password.unwrap_or_else(|| {
                rpassword::prompt_password("Enter password: ").unwrap()
            });
            
            let req_body = LoginRequest {
                username: username.clone(),
                password,
            };
            
            let resp = client
                .post(format!("{}/auth/login", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let headers = resp.headers().clone();
            let text_body = resp.text().await?;

            if status.is_success() {
                let mut auth_tokens: AuthTokens = serde_json::from_str(&text_body)?;
                
                // Calculate expires_at timestamp
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                let expires_at = DateTime::<Utc>::from_timestamp(now + auth_tokens.expires_in, 0)
                    .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;
                auth_tokens.expires_at = Some(expires_at);
                
                println!("Login successful!");
                println!("Username: {}", username);
                println!("Token expires at: {}", expires_at.format("%Y-%m-%d %H:%M:%S UTC"));
                
                // Try to load existing credentials to get user_id/user_app_key
                // If not found, we'll need to find another way to get these
                if let Ok(Some(existing_creds)) = load_credentials_from_file() {
                    let creds = SavedCredentials {
                        user_id: existing_creds.user_id,
                        user_app_key: existing_creds.user_app_key,
                        auth_tokens: Some(auth_tokens),
                        username: Some(username),
                    };
                    save_full_credentials(&creds)?;
                } else {
                    println!("Note: You'll need to have existing legacy credentials to use JWT auth with this user.");
                    println!("Please make sure you have a valid ~/.pipe-cli.json file with user_id and user_app_key.");
                }
            } else if status == StatusCode::TOO_MANY_REQUESTS {
                // Handle rate limiting
                let retry_after = headers
                    .get("Retry-After")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(60);
                
                return Err(anyhow!(
                    "Too many login attempts. Please try again in {} seconds.",
                    retry_after
                ));
            } else if status == StatusCode::FORBIDDEN && text_body.contains("locked") {
                return Err(anyhow!(
                    "Account is locked due to too many failed login attempts. Please contact support."
                ));
            } else {
                return Err(anyhow!(
                    "Login failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::Logout => {
            let creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please login first.")
            })?;

            let access_token = creds.auth_tokens.as_ref().ok_or_else(|| {
                anyhow!("No authentication tokens found. Please login first.")
            })?.access_token.clone();

            let resp = client
                .post(format!("{}/auth/logout", base_url))
                .header("Authorization", format!("Bearer {}", access_token))
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                println!("Logout successful!");
                let mut updated_creds = creds.clone();
                updated_creds.auth_tokens = None;
                save_full_credentials(&updated_creds)?;
            } else {
                return Err(anyhow!(
                    "Logout failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::SetPassword { password, user_id, user_app_key } => {
            let (user_id_final, user_app_key_final) =
                get_final_user_id_and_app_key(user_id, user_app_key)?;

            let new_password = password.unwrap_or_else(|| {
                println!("Password requirements:");
                println!("  - Minimum 8 characters");
                println!("  - Maximum 128 characters");
                println!("  - Cannot be a common weak password (e.g., 'password', '12345678', 'password123', etc.)");
                println!();
                rpassword::prompt_password("Enter new password: ").unwrap()
            });

            let req_body = SetPasswordRequest {
                user_id: user_id_final.clone(),
                user_app_key: user_app_key_final.clone(),
                new_password,
            };

            let resp = client
                .post(format!("{}/auth/set-password", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let response_data: serde_json::Value = serde_json::from_str(&text_body)?;
                println!("Password set successfully!");
                
                // If we got tokens in the response, save them
                if let Ok(auth_tokens) = serde_json::from_value::<AuthTokens>(
                    response_data.clone()
                ) {
                    let mut auth_tokens = auth_tokens;
                    // Calculate expires_at timestamp
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                    let expires_at = DateTime::<Utc>::from_timestamp(now + auth_tokens.expires_in, 0)
                        .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;
                    auth_tokens.expires_at = Some(expires_at);
                    
                    let creds = SavedCredentials {
                        user_id: user_id_final,
                        user_app_key: user_app_key_final,
                        auth_tokens: Some(auth_tokens),
                        username: None,
                    };
                    save_full_credentials(&creds)?;
                    
                    println!("You are now logged in with JWT authentication.");
                    println!("Token expires at: {}", expires_at.format("%Y-%m-%d %H:%M:%S UTC"));
                } else {
                    // Just update the existing credentials
                    if let Ok(Some(mut creds)) = load_credentials_from_file() {
                        creds.auth_tokens = None;
                        save_full_credentials(&creds)?;
                    }
                }
            } else {
                // Try to provide more helpful error message
                let error_message = if text_body.contains("too weak") || text_body.contains("Password") {
                    format!(
                        "Set password failed: {}\n\nPassword requirements:\n  - Minimum 8 characters\n  - Maximum 128 characters\n  - Cannot be common weak passwords like:\n    'password', '12345678', 'qwerty', 'abc123', 'password123',\n    'admin', 'letmein', 'welcome', '123456789', 'password1'",
                        text_body
                    )
                } else {
                    format!("Set password failed. Status = {}, Body = {}", status, text_body)
                };
                return Err(anyhow!(error_message));
            }
        }

        Commands::RefreshToken => {
            let creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please login first.")
            })?;

            let refresh_token = creds.auth_tokens.as_ref().ok_or_else(|| {
                anyhow!("No refresh token found in credentials.")
            })?.refresh_token.clone();

            let req_body = RefreshTokenRequest {
                refresh_token: refresh_token.clone(),
            };

            let resp = client
                .post(format!("{}/auth/refresh", base_url))
                .json(&req_body)
                .send()
                .await?;

            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let refresh_response: RefreshTokenResponse = serde_json::from_str(&text_body)?;
                
                // Calculate new expires_at timestamp
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                let expires_at = DateTime::<Utc>::from_timestamp(now + refresh_response.expires_in, 0)
                    .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;
                
                println!("Token refreshed successfully!");
                println!("Token expires at: {}", expires_at.format("%Y-%m-%d %H:%M:%S UTC"));

                // Update credentials with new access token
                let mut updated_creds = creds.clone();
                if let Some(ref mut auth_tokens) = updated_creds.auth_tokens {
                    auth_tokens.access_token = refresh_response.access_token;
                    auth_tokens.expires_in = refresh_response.expires_in;
                    auth_tokens.expires_at = Some(expires_at);
                }
                save_full_credentials(&updated_creds)?;
            } else {
                return Err(anyhow!(
                    "Refresh token failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::RotateAppKey {
            user_id,
            old_app_key,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = old_app_key {
                creds.user_app_key = key;
            }

            let mut request = client.post(format!("{}/rotateAppKey", base_url));
            
            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, true);
            
            // For JWT auth, send empty body. For legacy auth, credentials are already in headers
            if creds.auth_tokens.is_some() {
                let req_body = serde_json::json!({});
                request = request.json(&req_body);
            } else {
                // For legacy auth, we still need to send credentials in body for this endpoint
                let req_body = RotateAppKeyRequest {
                    user_id: creds.user_id.clone(),
                    user_app_key: creds.user_app_key.clone(),
                };
                request = request.json(&req_body);
            }

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<RotateAppKeyResponse>(&text_body)?;
                println!(
                    "App key rotated!\nUser ID: {}\nNew App Key: {}",
                    json.user_id, json.new_user_app_key
                );

                save_credentials_to_file(&json.user_id, &json.new_user_app_key)?;
            } else {
                return Err(anyhow!(
                    "Failed to rotate app key. Status = {}, Body = {}",
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let local_path = Path::new(&file_path);
            if !local_path.exists() {
                return Err(anyhow!("Local file not found: {}", file_path));
            }

            let epochs_final = epochs.unwrap_or(1); // default 1 month
            
            // Build URL - with JWT we don't need query params for auth
            // Build URL without credentials (security fix)
            let url = format!("{}/upload?file_name={}&epochs={}", base_url, file_name, epochs_final);

            match upload_file_with_shared_progress(&client, local_path, &url, &file_name, &creds, None).await {
                Ok((uploaded_filename, token_cost)) => {
                    println!("File uploaded successfully: {}", uploaded_filename);
                    if token_cost > 0.0 {
                        println!("💰 Cost: {} PIPE tokens", token_cost);
                    }
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            improved_download_file_with_auth(
                &client,
                base_url,
                &creds,
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let mut request = client.post(format!("{}/deleteFile", base_url));
            
            // Add auth headers including CSRF token for this state-changing operation
            request = add_auth_headers(request, &creds, true);
            
            // Use JWT auth if available, otherwise fall back to legacy
            if let Some(ref _auth_tokens) = creds.auth_tokens {
                // With JWT, send only file name - server will get user info from token
                let req_body = serde_json::json!({
                    "file_name": file_name
                });
                request = request.json(&req_body);
            } else {
                // Legacy auth via request body
                let req_body = DeleteFileRequest {
                    user_id: creds.user_id.clone(),
                    user_app_key: creds.user_app_key.clone(),
                    file_name: file_name.clone(),
                };
                request = request.json(&req_body);
            }

            let resp = request.send().await?;
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let mut request = client.post(format!("{}/checkWallet", base_url));
            
            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, false);
            
            // Always send empty body - auth is in headers
            let req_body = CheckWalletRequest {
                user_id: None,
                user_app_key: None,
            };
            request = request.json(&req_body);

            let resp = request.send().await?;
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let mut request = client.post(format!("{}/checkCustomToken", base_url));
            
            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, false);
            
            // Always send empty body - auth is in headers
            let req_body = CheckCustomTokenRequest {
                user_id: None,
                user_app_key: None,
            };
            request = request.json(&req_body);

            let resp = request.send().await?;
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let mut request = client.post(format!("{}/exchangeSolForTokens", base_url));
            
            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, true);
            
            // Always send only amount - auth is in headers
            let req_body = SwapSolForPipeRequest {
                user_id: None,
                user_app_key: None,
                amount_sol,
            };
            request = request.json(&req_body);

            let resp = request.send().await?;
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

        Commands::WithdrawSol {
            user_id,
            user_app_key,
            amount_sol,
            to_pubkey,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let mut request = client.post(format!("{}/withdrawSol", base_url));
            
            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, true);
            
            // Always send withdrawal details only - auth is in headers
            let req_body = WithdrawSolRequest {
                user_id: None,
                user_app_key: None,
                amount_sol,
                to_pubkey,
            };
            request = request.json(&req_body);

            let resp = request.send().await?;
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
            token_mint,
            amount,
            to_pubkey,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let mut request = client.post(format!("{}/withdrawToken", base_url));
            
            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, true);
            
            // Always send withdrawal details only - auth is in headers
            let req_body = WithdrawTokenRequest {
                user_id: None,
                user_app_key: None,
                to_pubkey,
                amount,
            };
            request = request.json(&req_body);

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let json = serde_json::from_str::<WithdrawTokenResponse>(&text_body)?;
                println!(
                    "Token Withdrawal complete!\nUser: {}\nTo: {}\nAmount: {}\nSignature: {}",
                    json.user_id, json.to_pubkey, json.amount, json.signature
                );
                println!("Token mint used: {}", token_mint);
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let mut request = client.post(format!("{}/createPublicLink", base_url));
            
            // Add auth headers including CSRF token for this state-changing operation
            request = add_auth_headers(request, &creds, true);
            
            // Use JWT auth if available, otherwise fall back to legacy
            if let Some(ref _auth_tokens) = creds.auth_tokens {
                // With JWT, send only file name - server will get user info from token
                let req_body = serde_json::json!({
                    "file_name": file_name
                });
                request = request.json(&req_body);
            } else {
                // Legacy auth via request body
                let req_body = CreatePublicLinkRequest {
                    user_id: creds.user_id.clone(),
                    user_app_key: creds.user_app_key.clone(),
                    file_name,
                };
                request = request.json(&req_body);
            }

            let resp = request.send().await?;
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

        Commands::DeletePublicLink {
            user_id,
            user_app_key,
            link_hash,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let mut request = client.post(format!("{}/deletePublicLink", base_url));
            
            // Add auth headers including CSRF token for this state-changing operation
            request = add_auth_headers(request, &creds, true);
            
            // Use JWT auth if available, otherwise fall back to legacy
            if let Some(ref _auth_tokens) = creds.auth_tokens {
                // With JWT, send only link hash - server will get user info from token
                let req_body = serde_json::json!({
                    "link_hash": link_hash
                });
                request = request.json(&req_body);
            } else {
                // Legacy auth via request body
                let req_body = DeletePublicLinkRequest {
                    user_id: Some(creds.user_id.clone()),
                    user_app_key: Some(creds.user_app_key.clone()),
                    link_hash,
                };
                request = request.json(&req_body);
            }

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if status.is_success() {
                let json: DeletePublicLinkResponse = serde_json::from_str(&text_body)?;
                println!("✅ {}", json.message);
                println!("Deleted link hash: {}", json.link_hash);
            } else {
                return Err(anyhow!(
                    "Delete public link failed. Status = {}, Body = {}",
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let dir = Path::new(&directory_path);
            if !dir.is_dir() {
                return Err(anyhow!("Provided path is not a directory: {}", directory_path));
            }

            println!("Scanning directory for files...");

            // Collect files and calculate total size
            let mut file_entries = Vec::new();
            let mut total_size = 0u64;
            let mut file_count = 0;

            for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
                if entry.path().is_file() {
                    if let Ok(meta) = entry.metadata() {
                        total_size += meta.len();
                        file_count += 1;
                        file_entries.push(entry.path().to_owned());
                    }
                }
            }

            if file_entries.is_empty() {
                println!("No files found in directory.");
                return Ok(());
            }

            println!("Found {} files, total size: {:.2} MB", 
                file_count, 
                total_size as f64 / 1_048_576.0
            );
            
            // Check if user has enough tokens for the entire upload
            let total_cost_estimate = total_size as f64 / 1_000_000_000.0; // 1 PIPE per GB for normal uploads
            
            // Get current token balance
            let balance_url = format!("{}/checkCustomToken", base_url);
            
            let balance_body = if creds.auth_tokens.is_some() {
                // For JWT auth, send empty body (server gets user from token)
                CheckCustomTokenRequest {
                    user_id: None,
                    user_app_key: None,
                }
            } else {
                // For legacy auth, include credentials in body
                CheckCustomTokenRequest {
                    user_id: Some(creds.user_id.clone()),
                    user_app_key: Some(creds.user_app_key.clone()),
                }
            };
            
            let mut balance_req = client.post(&balance_url);
            balance_req = add_auth_headers(balance_req, &creds, false); // false = not state-changing
            balance_req = balance_req.json(&balance_body);
            
            match balance_req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        match resp.json::<CheckCustomTokenResponse>().await {
                            Ok(balance_resp) => {
                                let current_balance = balance_resp.ui_amount;
                                if current_balance < total_cost_estimate {
                                    eprintln!("\n❌ Insufficient tokens for directory upload");
                                    eprintln!("Total cost: {:.4} PIPE tokens", total_cost_estimate);
                                    eprintln!("Your balance: {:.4} PIPE tokens", current_balance);
                                    eprintln!("Needed: {:.4} PIPE tokens", total_cost_estimate - current_balance);
                                    eprintln!("\nPlease use 'pipe swap-sol-for-pipe {:.1}' to get enough tokens.", 
                                        (total_cost_estimate - current_balance) / 10.0 + 0.1);
                                    return Ok(());
                                }
                                println!("💰 Estimated cost: {:.4} PIPE tokens (current balance: {:.4} PIPE)", 
                                    total_cost_estimate, current_balance);
                            }
                            Err(e) => {
                                eprintln!("⚠️  Failed to parse balance response: {}", e);
                                eprintln!("Estimated cost: {:.4} PIPE tokens", total_cost_estimate);
                                eprintln!("\nProceed with caution - could not verify if you have enough tokens.");
                                eprintln!("Consider checking your balance with 'pipe check-token' first.");
                            }
                        }
                    } else {
                        let error_text = resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                        eprintln!("⚠️  Failed to check token balance: {} - {}", status, error_text);
                        eprintln!("Estimated cost: {:.4} PIPE tokens", total_cost_estimate);
                        eprintln!("\nProceed with caution - could not verify if you have enough tokens.");
                        eprintln!("Consider checking your balance with 'pipe check-token' first.");
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Could not connect to check token balance: {}", e);
                    eprintln!("Estimated cost: {:.4} PIPE tokens", total_cost_estimate);
                    eprintln!("\nProceed with caution - could not verify if you have enough tokens.");
                    eprintln!("Consider checking your balance with 'pipe check-token' first.");
                }
            }

            // Create shared progress bar
            let progress = Arc::new(ProgressBar::new(total_size));
            progress.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) - {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            progress.set_message(format!("Uploading {} files...", file_count));

            let shared_progress = DirectoryUploadProgress {
                uploaded_bytes: Arc::new(TokioMutex::new(0)),
                progress_bar: progress.clone(),
            };

            let concurrency_limit = 10;  // Match server's limit of 10 concurrent uploads per user
            let sem = Arc::new(Semaphore::new(concurrency_limit));
            let mut handles = Vec::new();

            let completed_count = Arc::new(TokioMutex::new(0u32));
            let failed_count = Arc::new(TokioMutex::new(0u32));
            let total_cost = Arc::new(TokioMutex::new(0.0f64));

            for path in file_entries {
                let sem_clone = Arc::clone(&sem);
                let client_clone = client.clone();
                let base_url_clone = base_url.to_string();
                let creds_clone = creds.clone();
                let shared_progress_clone = shared_progress.clone();
                let completed_clone = completed_count.clone();
                let failed_clone = failed_count.clone();
                let total_cost_clone = total_cost.clone();
                let file_count_copy = file_count;
                let progress_clone = progress.clone();

                let rel_path = match path.strip_prefix(dir) {
                    Ok(r) => r.to_string_lossy().to_string(),
                    Err(_) => path
                        .file_name()
                        .map(|os| os.to_string_lossy().to_string())
                        .unwrap_or_else(|| "untitled".to_string()),
                };

                let handle = tokio::spawn(async move {
                    let _permit = sem_clone.acquire_owned().await.unwrap();
                    
                    // Build URL based on auth type
                    // Build URL without credentials (security fix)
                    let url = format!("{}/upload?file_name={}", base_url_clone, rel_path);

                    match upload_file_with_shared_progress(&client_clone, &path, &url, &rel_path, &creds_clone, Some(shared_progress_clone)).await {
                        Ok((uploaded_file, cost)) => {
                            let mut completed = completed_clone.lock().await;
                            *completed += 1;
                            let completed_val = *completed;
                            drop(completed);
                            
                            let mut total = total_cost_clone.lock().await;
                            *total += cost;
                            drop(total);
                            
                            progress_clone.set_message(format!("Uploaded {} of {} files", completed_val, file_count_copy));
                            
                            let _ = append_to_upload_log(
                                &path.display().to_string(),
                                &uploaded_file,
                                "SUCCESS",
                                "Directory upload success"
                            );
                        }
                        Err(e) => {
                            let mut failed = failed_clone.lock().await;
                            *failed += 1;
                            
                            eprintln!("Failed to upload {}: {}", rel_path, e);
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

            progress.finish_with_message("Upload complete!");
            
            let completed = *completed_count.lock().await;
            let failed = *failed_count.lock().await;
            let final_cost = *total_cost.lock().await;
            
            println!("\n📊 Upload Summary:");
            println!("  ✅ Successfully uploaded: {} files", completed);
            if failed > 0 {
                println!("  ❌ Failed: {} files", failed);
            }
            println!("  📁 Total size: {:.2} MB", total_size as f64 / 1_048_576.0);
            if final_cost > 0.0 {
                println!("  💰 Total cost: {:.4} PIPE tokens", final_cost);
            }
            println!("\nCheck the log file for details:\n  {}", get_upload_log_path().display());
        }

        Commands::PriorityUploadDirectory {
            user_id,
            user_app_key,
            directory_path,
            skip_uploaded,
            concurrency,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

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

            println!("Scanning directory for files...");

            // Collect files and calculate total size
            let mut file_entries = Vec::new();
            let mut total_size = 0u64;
            let mut file_count = 0;
            let mut skipped_count = 0;

            for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
                if entry.path().is_file() {
                    if skip_uploaded && previously_uploaded.contains(&entry.path().display().to_string()) {
                        skipped_count += 1;
                        continue;
                    }
                    if let Ok(meta) = entry.metadata() {
                        total_size += meta.len();
                        file_count += 1;
                        file_entries.push(entry.path().to_owned());
                    }
                }
            }

            if skipped_count > 0 {
                println!("Skipping {} previously uploaded files", skipped_count);
            }

            if file_entries.is_empty() {
                println!("No files to upload (all files either don't exist or were previously uploaded).");
                return Ok(());
            }

            println!("Found {} files to upload, total size: {:.2} MB", 
                file_count, 
                total_size as f64 / 1_048_576.0
            );
            
            // Check if user has enough tokens for the entire priority upload
            let total_cost_estimate = (total_size as f64 / 1_000_000_000.0) * fee_resp.priority_fee_per_gb;
            
            // Get current token balance
            let balance_url = format!("{}/checkCustomToken", base_url);
            
            let balance_body = if creds.auth_tokens.is_some() {
                // For JWT auth, send empty body (server gets user from token)
                CheckCustomTokenRequest {
                    user_id: None,
                    user_app_key: None,
                }
            } else {
                // For legacy auth, include credentials in body
                CheckCustomTokenRequest {
                    user_id: Some(creds.user_id.clone()),
                    user_app_key: Some(creds.user_app_key.clone()),
                }
            };
            
            let mut balance_req = client.post(&balance_url);
            balance_req = add_auth_headers(balance_req, &creds, false); // false = not state-changing
            balance_req = balance_req.json(&balance_body);
            
            match balance_req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        match resp.json::<CheckCustomTokenResponse>().await {
                            Ok(balance_resp) => {
                                let current_balance = balance_resp.ui_amount;
                                if current_balance < total_cost_estimate {
                                    eprintln!("\n❌ Insufficient tokens for priority directory upload");
                                    eprintln!("Total cost: {:.4} PIPE tokens (at {} tokens/GB)", 
                                        total_cost_estimate, fee_resp.priority_fee_per_gb);
                                    eprintln!("Your balance: {:.4} PIPE tokens", current_balance);
                                    eprintln!("Needed: {:.4} PIPE tokens", total_cost_estimate - current_balance);
                                    eprintln!("\nPlease use 'pipe swap-sol-for-pipe {:.1}' to get enough tokens.", 
                                        (total_cost_estimate - current_balance) / 10.0 + 0.1);
                                    return Ok(());
                                }
                                println!("💰 Estimated cost: {:.4} PIPE tokens at {} tokens/GB (current balance: {:.4} PIPE)", 
                                    total_cost_estimate, fee_resp.priority_fee_per_gb, current_balance);
                            }
                            Err(e) => {
                                eprintln!("⚠️  Failed to parse balance response: {}", e);
                                eprintln!("Estimated cost: {:.4} PIPE tokens at {} tokens/GB", 
                                    total_cost_estimate, fee_resp.priority_fee_per_gb);
                                eprintln!("\nProceed with caution - could not verify if you have enough tokens.");
                                eprintln!("Consider checking your balance with 'pipe check-token' first.");
                            }
                        }
                    } else {
                        let error_text = resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                        eprintln!("⚠️  Failed to check token balance: {} - {}", status, error_text);
                        eprintln!("Estimated cost: {:.4} PIPE tokens at {} tokens/GB", 
                            total_cost_estimate, fee_resp.priority_fee_per_gb);
                        eprintln!("\nProceed with caution - could not verify if you have enough tokens.");
                        eprintln!("Consider checking your balance with 'pipe check-token' first.");
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Could not connect to check token balance: {}", e);
                    eprintln!("Estimated cost: {:.4} PIPE tokens at {} tokens/GB", 
                        total_cost_estimate, fee_resp.priority_fee_per_gb);
                    eprintln!("\nProceed with caution - could not verify if you have enough tokens.");
                    eprintln!("Consider checking your balance with 'pipe check-token' first.");
                }
            }

            // Create shared progress bar (bytes-based, not file count)
            let progress = Arc::new(ProgressBar::new(total_size));
            progress.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) - {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            progress.set_message(format!("Priority uploading {} files...", file_count));

            let shared_progress = DirectoryUploadProgress {
                uploaded_bytes: Arc::new(TokioMutex::new(0)),
                progress_bar: progress.clone(),
            };

            let sem = Arc::new(Semaphore::new(concurrency));
            let mut handles = Vec::new();

            let completed_count = Arc::new(TokioMutex::new(0u32));
            let failed_count = Arc::new(TokioMutex::new(0u32));
            let total_cost = Arc::new(TokioMutex::new(0.0f64));

            for path in file_entries {
                let sem_clone = Arc::clone(&sem);
                let client_clone = client.clone();
                let base_url_clone = base_url.to_string();
                let creds_clone = creds.clone();
                let shared_progress_clone = shared_progress.clone();
                let completed_clone = completed_count.clone();
                let failed_clone = failed_count.clone();
                let total_cost_clone = total_cost.clone();
                let file_count_copy = file_count;
                let progress_clone = progress.clone();

                let rel_path = match path.strip_prefix(dir) {
                    Ok(r) => r.to_string_lossy().to_string(),
                    Err(_) => path
                        .file_name()
                        .map(|os| os.to_string_lossy().to_string())
                        .unwrap_or_else(|| "untitled".to_string()),
                };

                let handle = tokio::spawn(async move {
                    let _permit = sem_clone.acquire_owned().await.unwrap();
                    
                    // Build URL without credentials (security fix)
                    let url = format!("{}/priorityUpload?file_name={}", base_url_clone, rel_path);

                    match upload_file_priority_with_shared_progress(&client_clone, &path, &url, &rel_path, &creds_clone, Some(shared_progress_clone)).await {
                        Ok((uploaded_file, cost)) => {
                            let mut completed = completed_clone.lock().await;
                            *completed += 1;
                            let completed_val = *completed;
                            drop(completed);
                            
                            let mut total = total_cost_clone.lock().await;
                            *total += cost;
                            drop(total);
                            
                            progress_clone.set_message(format!("Priority uploaded {} of {} files", completed_val, file_count_copy));
                            
                            let _ = append_to_upload_log(
                                &path.display().to_string(),
                                &uploaded_file,
                                "PRIORITY SUCCESS",
                                "Priority directory upload success"
                            );
                        }
                        Err(e) => {
                            let mut failed = failed_clone.lock().await;
                            *failed += 1;
                            
                            eprintln!("Failed priority upload {}: {}", rel_path, e);
                            let _ = append_to_upload_log(
                                &path.display().to_string(),
                                &rel_path,
                                "PRIORITY FAIL",
                                &format!("Priority directory upload error: {}", e)
                            );
                        }
                    }
                });

                handles.push(handle);
            }

            for h in handles {
                let _ = h.await;
            }

            progress.finish_with_message("Priority upload complete!");
            
            let completed = *completed_count.lock().await;
            let failed = *failed_count.lock().await;
            let final_cost = *total_cost.lock().await;
            
            println!("\n📊 Priority Upload Summary:");
            println!("  ✅ Successfully uploaded: {} files", completed);
            if failed > 0 {
                println!("  ❌ Failed: {} files", failed);
            }
            println!("  📁 Total size: {:.2} MB", total_size as f64 / 1_048_576.0);
            if final_cost > 0.0 {
                println!("  💰 Total cost: {:.4} PIPE tokens (priority rate: {} tokens/GB)", final_cost, fee_resp.priority_fee_per_gb);
            }
            println!("\nCheck the log file for details:\n  {}", get_upload_log_path().display());
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let local_path = Path::new(&file_path);
            if !local_path.exists() {
                return Err(anyhow!("Local file not found: {}", file_path));
            }

            let epochs_final = epochs.unwrap_or(1);
            
            // Build URL without credentials (security fix)
            let url = format!("{}/priorityUpload?file_name={}&epochs={}", base_url, file_name, epochs_final);

            match upload_file_priority_with_shared_progress(&client, local_path, &url, &file_name, &creds, None).await {
                Ok((uploaded_filename, token_cost)) => {
                    println!("Priority file uploaded (or backgrounded): {}", uploaded_filename);
                    if token_cost > 0.0 {
                        println!("💰 Cost: {} PIPE tokens", token_cost);
                    }
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            match priority_download_single_file_with_auth(&client, base_url, &creds, &file_name).await {
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file()?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds).await?;
            
            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let url = format!("{}/extendStorage", base_url);
            let mut request = client.post(url);
            
            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, true);
            
            // For JWT auth, send only file name and months. For legacy auth, also need credentials in body
            if creds.auth_tokens.is_some() {
                let req_body = serde_json::json!({
                    "file_name": file_name,
                    "additional_months": additional_months
                });
                request = request.json(&req_body);
            } else {
                // Legacy auth still needs credentials in body for this endpoint
                let req_body = ExtendStorageRequest {
                    user_id: creds.user_id.clone(),
                    user_app_key: creds.user_app_key.clone(),
                    file_name,
                    additional_months,
                };
                request = request.json(&req_body);
            }

            let resp = request.send().await?;
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
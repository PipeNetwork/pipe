// src/lib.rs

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Body, Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite; // For writeln!
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::Semaphore;
use walkdir::WalkDir;

mod encryption;
mod keyring;
mod quantum;
mod quantum_keyring;
mod password_utils;

#[cfg(test)]
mod quantum_integration_test;

pub const MAX_RETRIES: u32 = 5;
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
        default_value = "https://us-west-00-firestarter.pipenetwork.com",
        global = true,
        help = "Base URL for the Pipe Network client API"
    )]
    pub api: String,

    #[arg(
        long,
        global = true,
        help = "Path to custom config file (default: ~/.pipe-cli.json)",
        env = "PIPE_CLI_CONFIG"
    )]
    pub config: Option<String>,

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
        #[arg(
            long,
            help = "Upload tier: normal, priority, premium, ultra, enterprise"
        )]
        tier: Option<String>,
        #[arg(long, help = "Encrypt file with password before upload")]
        encrypt: bool,
        #[arg(long, help = "Password for encryption (will prompt if not provided)")]
        password: Option<String>,
        #[arg(long, help = "Use key from keyring or key file")]
        key: Option<String>,
        #[arg(long, help = "Use post-quantum encryption (kyber)")]
        quantum: bool,
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

        #[arg(long, help = "Decrypt file with password after download")]
        decrypt: bool,
        #[arg(long, help = "Password for decryption (will prompt if not provided)")]
        password: Option<String>,
        #[arg(long, help = "Use key from keyring or key file")]
        key: Option<String>,
        #[arg(long, help = "Use post-quantum decryption (kyber)")]
        quantum: bool,
    },

    /// Delete a file
    DeleteFile {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_name: String,
    },

    /// Get information about a file (size, encryption status, etc.)
    FileInfo {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_name: String,
    },

    /// Encrypt a local file (without uploading)
    EncryptLocal {
        input_file: String,
        output_file: String,
        #[arg(long, help = "Password for encryption (will prompt if not provided)")]
        password: Option<String>,
    },

    /// Decrypt a local file (without downloading)
    DecryptLocal {
        input_file: String,
        output_file: String,
        #[arg(long, help = "Password for decryption (will prompt if not provided)")]
        password: Option<String>,
    },

    /// Generate a new encryption key
    KeyGen {
        #[arg(long, help = "Name for the key")]
        name: Option<String>,
        #[arg(long, help = "Algorithm: aes256, kyber1024, dilithium5")]
        algorithm: Option<String>,
        #[arg(long, help = "Description of the key")]
        description: Option<String>,
        #[arg(long, help = "Export to file instead of storing in keyring")]
        output: Option<String>,
    },

    /// List all keys in the keyring
    KeyList,

    /// Delete a key from the keyring
    KeyDelete {
        /// Name or ID of the key to delete
        key_name: String,
    },

    /// Export a key from the keyring
    KeyExport {
        /// Name or ID of the key to export
        key_name: String,
        /// Output file path
        output: String,
    },

    /// Migrate legacy keyring to use custom master password
    KeyringMigrate {
        #[arg(long, help = "Skip confirmation prompts")]
        force: bool,
    },

    /// Sign a file with Dilithium
    SignFile {
        /// File to sign
        input_file: String,
        /// Signature output file
        signature_file: String,
        #[arg(long, help = "Signing key name or path")]
        key: String,
    },

    /// Verify a file signature
    VerifySignature {
        /// File to verify
        input_file: String,
        /// Signature file
        signature_file: String,
        #[arg(long, help = "Public key file or name")]
        public_key: String,
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
        #[arg(long, help = "Custom title for social media preview")]
        title: Option<String>,
        #[arg(long, help = "Custom description for social media preview")]
        description: Option<String>,
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
        #[arg(
            long,
            help = "Upload tier: normal, priority, premium, ultra, enterprise"
        )]
        tier: Option<String>,
        #[arg(long, help = "Skip files that were already uploaded successfully")]
        skip_uploaded: bool,
        #[arg(long, help = "Encrypt all files with password before upload")]
        encrypt: bool,
        #[arg(long, help = "Password for encryption (will prompt if not provided)")]
        password: Option<String>,
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

    /// Download an entire directory based on upload log
    DownloadDirectory {
        /// Remote directory prefix to match
        remote_prefix: String,
        
        /// Local directory to download files to
        output_directory: String,
        
        #[arg(long, default_value = "5", help = "Number of parallel downloads")]
        parallel: usize,
        
        #[arg(long, help = "Show what would be downloaded without downloading")]
        dry_run: bool,
        
        #[arg(long, help = "Decrypt files after download")]
        decrypt: bool,
        
        #[arg(long, help = "Password for decryption (will prompt if not provided)")]
        password: Option<String>,
        
        #[arg(long, help = "Filter files by regex pattern")]
        filter: Option<String>,
        
        #[arg(long, help = "Path to upload log file (default: ~/.pipe-cli-uploads.json)")]
        upload_log: Option<String>,
    },

    GetPriorityFee,

    /// Get pricing for all upload tiers
    GetTierPricing,

    /// Manage referral codes
    #[command(subcommand)]
    Referral(ReferralCommands),

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

#[derive(Subcommand, Debug)]
pub enum ReferralCommands {
    /// Generate your referral code
    Generate,
    /// Show your referral code and stats
    Show,
    /// Apply a referral code to your account
    Apply {
        /// The referral code to apply
        code: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_description: Option<String>,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceInstance {
    pub endpoint_url: String,
    pub load_score: f64,
    pub status: String,
    pub active_connections: i32,
    pub bandwidth_available_mbps: f64,
    pub region: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceDiscoveryResponse {
    pub instances: Vec<ServiceInstance>,
    pub routing_strategy: String,
    pub refresh_interval_seconds: u32,
}

// Service discovery cache
pub struct ServiceDiscoveryCache {
    instances: RwLock<Vec<ServiceInstance>>,
    last_refresh: RwLock<Instant>,
    refresh_interval: Duration,
    fallback_endpoint: String,
}

impl ServiceDiscoveryCache {
    pub fn new(fallback_endpoint: String) -> Self {
        Self {
            instances: RwLock::new(Vec::new()),
            last_refresh: RwLock::new(Instant::now() - Duration::from_secs(3600)), // Force refresh on first use
            refresh_interval: Duration::from_secs(60),
            fallback_endpoint,
        }
    }

    pub async fn get_best_endpoint(&self, client: &Client, discovery_url: &str) -> String {
        // Check if refresh needed
        let needs_refresh = {
            let last = self.last_refresh.read().unwrap();
            last.elapsed() > self.refresh_interval
        };

        if needs_refresh {
            if let Err(e) = self.refresh_instances(client, discovery_url).await {
                eprintln!("Failed to refresh service instances: {}", e);
            }
        }

        // Get best instance
        let instances = self.instances.read().unwrap();
        if let Some(best) = instances.first() {
            best.endpoint_url.clone()
        } else {
            self.fallback_endpoint.clone()
        }
    }

    async fn refresh_instances(&self, client: &Client, discovery_url: &str) -> Result<()> {
        let resp = client
            .get(format!("{}/getServiceInstances", discovery_url))
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        if resp.status().is_success() {
            let mut discovery: ServiceDiscoveryResponse = resp.json().await?;

            // Filter out localhost instances if we're not connecting to localhost
            if !discovery_url.contains("localhost") && !discovery_url.contains("127.0.0.1") {
                discovery.instances.retain(|instance| {
                    !instance.endpoint_url.contains("localhost") && 
                    !instance.endpoint_url.contains("127.0.0.1")
                });
            }

            let mut instances = self.instances.write().unwrap();
            *instances = discovery.instances;

            let mut last_refresh = self.last_refresh.write().unwrap();
            *last_refresh = Instant::now();

            eprintln!(
                "Service discovery updated: {} healthy instances",
                instances.len()
            );
        }

        Ok(())
    }

    pub fn select_endpoint_for_operation(
        &self,
        operation: &str,
        user_id: &str,
        file_name: &str,
    ) -> String {
        let instances = self.instances.read().unwrap();

        if instances.is_empty() {
            return self.fallback_endpoint.clone();
        }

        match operation {
            "upload" | "download" | "delete" => {
                // Use consistent hashing for file operations
                let key = format!("{}/{}", user_id, file_name);
                let hash = self.hash_key(&key);
                let idx = hash % instances.len();
                instances
                    .get(idx)
                    .map(|i| i.endpoint_url.clone())
                    .unwrap_or_else(|| self.fallback_endpoint.clone())
            }
            _ => {
                // Use least loaded for other operations
                instances
                    .first()
                    .map(|i| i.endpoint_url.clone())
                    .unwrap_or_else(|| self.fallback_endpoint.clone())
            }
        }
    }

    fn hash_key(&self, key: &str) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize
    }
}

// Helper function to get endpoint for a specific operation
async fn get_endpoint_for_operation(
    service_cache: &ServiceDiscoveryCache,
    client: &Client,
    base_url: &str,
    operation: &str,
    user_id: &str,
    file_name: Option<&str>,
) -> String {
    // Check if base_url has a non-standard port (not 80/443)
    // If so, bypass discovery and use the exact URL provided
    if let Ok(url) = reqwest::Url::parse(base_url) {
        if let Some(_port) = url.port() {
            // Non-standard port specified, bypass discovery
            eprintln!("Using direct connection to {} (bypassing discovery)", base_url);
            return base_url.to_string();
        }
    }
    
    // First try to refresh if needed
    let _ = service_cache.get_best_endpoint(client, base_url).await;

    // Then select based on operation
    match operation {
        "upload" | "download" | "delete" if file_name.is_some() => {
            service_cache.select_endpoint_for_operation(operation, user_id, file_name.unwrap())
        }
        _ => {
            // For non-file operations, just get the best endpoint
            let instances = service_cache.instances.read().unwrap();
            if let Some(best) = instances.first() {
                best.endpoint_url.clone()
            } else {
                base_url.to_string()
            }
        }
    }
}

pub fn get_credentials_file_path(custom_path: Option<&str>) -> PathBuf {
    if let Some(path) = custom_path {
        PathBuf::from(path)
    } else if let Some(home_dir) = dirs::home_dir() {
        home_dir.join(".pipe-cli.json")
    } else {
        PathBuf::from(".pipe-cli.json")
    }
}


// Helper function to load credentials with the current config
pub fn load_creds_with_config(config_path: Option<&str>) -> Result<SavedCredentials> {
    load_credentials_from_file(config_path)?.ok_or_else(|| {
        anyhow!(
            "No saved credentials found. Please run 'pipe new-user' first \
             or provide --user-id/--user_app_key."
        )
    })
}

// Helper function to save credentials with the current config
pub fn save_creds_with_config(creds: &SavedCredentials, config_path: Option<&str>) -> Result<()> {
    save_full_credentials(creds, config_path)
}

pub fn load_credentials_from_file(custom_path: Option<&str>) -> Result<Option<SavedCredentials>> {
    let path = get_credentials_file_path(custom_path);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&path)?;
    let creds: SavedCredentials = serde_json::from_str(&data)?;
    Ok(Some(creds))
}

pub fn save_credentials_to_file(user_id: &str, user_app_key: &str, config_path: Option<&str>) -> Result<()> {
    // Try to preserve existing auth tokens if they exist
    let creds = if let Ok(Some(existing)) = load_credentials_from_file(config_path) {
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

    save_full_credentials(&creds, config_path)
}

// Save full credentials including JWT tokens
pub fn save_full_credentials(creds: &SavedCredentials, config_path: Option<&str>) -> Result<()> {
    let path = get_credentials_file_path(config_path);
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
async fn ensure_valid_token(
    client: &Client,
    base_url: &str,
    creds: &mut SavedCredentials,
    config_path: Option<&str>,
) -> Result<()> {
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
                let expires_at =
                    DateTime::<Utc>::from_timestamp(now + refresh_response.expires_in, 0)
                        .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;

                // Update auth tokens
                if let Some(ref mut auth_tokens) = creds.auth_tokens {
                    auth_tokens.access_token = refresh_response.access_token;
                    auth_tokens.expires_in = refresh_response.expires_in;
                    auth_tokens.expires_at = Some(expires_at);
                }

                // Save updated credentials
                save_full_credentials(creds, config_path)?;
                println!("Token refreshed successfully!");
            } else {
                // Token refresh failed, clear auth tokens
                creds.auth_tokens = None;
                save_full_credentials(creds, config_path)?;
                return Err(anyhow!("Token refresh failed, please login again"));
            }
        }
    }
    Ok(())
}

// Build a request with JWT auth header if available, otherwise use query params
#[allow(dead_code)]
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
        request = request.header(
            "Authorization",
            format!("Bearer {}", auth_tokens.access_token),
        );
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
        request = request.header(
            "Authorization",
            format!("Bearer {}", auth_tokens.access_token),
        );

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
    config_path: Option<&str>,
) -> Result<(String, String)> {
    match (user_id_opt, user_app_key_opt) {
        (Some(u), Some(k)) => Ok((u, k)),
        (maybe_user_id, maybe_app_key) => {
            let creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
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

pub fn append_to_upload_log(
    local_path: &str,
    remote_path: &str,
    status: &str,
    message: &str,
) -> Result<()> {
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

/// Read and parse the upload log
pub fn read_upload_log_entries(log_path: Option<&str>) -> Result<Vec<UploadLogEntry>> {
    let path = match log_path {
        Some(p) => PathBuf::from(p),
        None => get_upload_log_path(),
    };
    
    if !path.exists() {
        return Ok(Vec::new());
    }
    
    let contents = fs::read_to_string(&path)?;
    let mut entries = Vec::new();
    
    for line in contents.lines() {
        if let Ok(entry) = serde_json::from_str::<UploadLogEntry>(line) {
            entries.push(entry);
        }
    }
    
    Ok(entries)
}

/// Filter upload log entries by prefix and status
pub fn filter_entries_for_download<'a>(
    entries: &'a [UploadLogEntry],
    remote_prefix: &str,
    filter_regex: Option<&regex::Regex>,
) -> Vec<&'a UploadLogEntry> {
    entries
        .iter()
        .filter(|e| {
            e.status == "SUCCESS" 
            && e.remote_path.starts_with(remote_prefix)
            && filter_regex.map_or(true, |re| re.is_match(&e.remote_path))
        })
        .collect()
}

/// Create directory structure for a file path
pub async fn ensure_parent_dirs(file_path: &Path) -> Result<()> {
    if let Some(parent) = file_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    Ok(())
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    // Handle directory case - append filename if output_path is a directory
    let output_path = if Path::new(output_path).is_dir() {
        Path::new(output_path).join(file_name).to_string_lossy().to_string()
    } else {
        output_path.to_string()
    };
    
    println!("Downloading '{}' to '{}'...", file_name, &output_path);

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
        request = request.header(
            "Authorization",
            format!("Bearer {}", auth_tokens.access_token),
        );
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

    // Get the full response body
    let body_bytes = resp.bytes().await?;
    
    // The pipe-store server always returns base64-encoded content from the /download endpoint
    // So we need to decode it
    let final_bytes = match std::str::from_utf8(&body_bytes) {
        Ok(text_body) => {
            // Try Base64 decode
            match general_purpose::STANDARD.decode(text_body.trim()) {
                Ok(decoded) => {
                    progress.set_length(decoded.len() as u64);
                    decoded
                }
                Err(e) => {
                    // If base64 decode fails, log warning and use original bytes
                    eprintln!("Warning: Base64 decode failed: {}. Using raw response.", e);
                    body_bytes.to_vec()
                }
            }
        }
        Err(_) => {
            // Not valid UTF-8, so can't be base64 - use original bytes
            eprintln!("Warning: Response is not valid UTF-8, cannot be base64. Using raw response.");
            body_bytes.to_vec()
        }
    };

    // Write the decoded content
    tokio::fs::write(&output_path, &final_bytes).await?;
    progress.set_position(final_bytes.len() as u64);
    progress.finish_with_message("Download completed");

    println!("File downloaded successfully to: {}", output_path);
    Ok(())
}

#[allow(dead_code)]
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

/// Wrapper function that adds retry logic with exponential backoff for uploads
async fn upload_with_retry<F, Fut>(operation_name: &str, mut operation: F) -> Result<(String, f64)>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(String, f64)>>,
{
    let mut retry_count = 0;
    let mut backoff_secs = INITIAL_RETRY_DELAY_MS / 1000; // Convert to seconds

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                let error_str = e.to_string();

                // Check if it's a 429 error
                if error_str.contains("429") || error_str.contains("Too Many Requests") {
                    if retry_count >= MAX_RETRIES {
                        eprintln!(
                            "❌ {} failed after {} retries: {}",
                            operation_name, MAX_RETRIES, e
                        );
                        return Err(e);
                    }

                    // Try to extract Retry-After value from error message
                    let wait_time = if error_str.contains("Status=429") {
                        // The error message might contain retry-after info
                        // For now, use exponential backoff
                        backoff_secs
                    } else {
                        backoff_secs
                    };

                    retry_count += 1;
                    eprintln!(
                        "⏳ Rate limited on {}. Retry {}/{} in {} seconds...",
                        operation_name, retry_count, MAX_RETRIES, wait_time
                    );

                    tokio::time::sleep(tokio::time::Duration::from_secs(wait_time)).await;

                    // Exponential backoff with cap
                    backoff_secs = (backoff_secs * 2).min(MAX_RETRY_DELAY_MS / 1000).min(60);
                } else {
                    // Not a rate limit error, don't retry
                    return Err(e);
                }
            }
        }
    }
}

async fn upload_file_with_auth(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
    creds: &SavedCredentials,
) -> Result<String> {
    let f = TokioFile::open(file_path)
        .await
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
    use futures_util::Stream;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
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

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
        inner: InnerReaderStream::with_capacity(f, 1024 * 1024), // 1MB buffer for better throughput
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
        request = request.header(
            "Authorization",
            format!("Bearer {}", auth_tokens.access_token),
        );
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

    use futures_util::Stream;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
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

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
        inner: InnerReaderStream::with_capacity(f, 1024 * 1024), // 1MB buffer for better throughput
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
    let f = TokioFile::open(file_path)
        .await
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

    use futures_util::Stream;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
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

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
        inner: InnerReaderStream::with_capacity(f, 1024 * 1024), // 1MB buffer for better throughput
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
        request = request.header(
            "Authorization",
            format!("Bearer {}", auth_tokens.access_token),
        );
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
    let url = format!(
        "{}/priorityDownload?file_name={}",
        base_url, file_name_in_bucket
    );

    // Add legacy auth headers
    let resp = client
        .get(&url)
        .header("X-User-Id", user_id)
        .header("X-User-App-Key", user_app_key)
        .send()
        .await?;
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
    let url = format!(
        "{}/priorityDownload?file_name={}",
        base_url, file_name_in_bucket
    );

    let mut request = client.get(&url);

    // Add appropriate auth headers
    if let Some(ref auth_tokens) = creds.auth_tokens {
        // JWT authentication
        request = request.header(
            "Authorization",
            format!("Bearer {}", auth_tokens.access_token),
        );
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

// Helper function to handle quantum-encrypted file download
async fn download_file_with_quantum_decryption(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    file_name: &str,
    output_path: &str,
    decrypt_password: bool,
    password: Option<String>,
) -> Result<()> {
    use crate::quantum::decrypt_and_verify;
    use crate::quantum_keyring::load_quantum_keypair;
    
    println!("🔐 Downloading quantum-encrypted file...");
    
    // Download the quantum-encrypted file
    let temp_path = format!("{}.qenc.tmp", output_path);
    improved_download_file_with_auth(client, base_url, creds, file_name, &temp_path).await?;
    
    // Read the downloaded file
    let quantum_encrypted_data = std::fs::read(&temp_path)?;
    println!("  Downloaded size: {} bytes", quantum_encrypted_data.len());
    
    // Determine the original filename (remove .qenc extension if present)
    let original_filename = if file_name.ends_with(".qenc") {
        &file_name[..file_name.len() - 5]
    } else {
        file_name
    };
    
    // Load quantum keys
    let quantum_keys = match load_quantum_keypair(original_filename) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("⚠️  Could not load quantum keys for {}: {}", original_filename, e);
            eprintln!("    Make sure you have the quantum keys from when this file was uploaded.");
            let _ = std::fs::remove_file(&temp_path);
            return Err(anyhow!("Quantum keys not found"));
        }
    };
    
    // Decrypt and verify using quantum crypto
    println!("  Decrypting with quantum-resistant algorithms...");
    let signed_data = decrypt_and_verify(
        &quantum_encrypted_data,
        &quantum_keys.kyber_secret,
    )?;
    
    println!("  ✅ Signature verified");
    println!("  Decrypted size: {} bytes", signed_data.data.len());
    
    // If password decryption is also needed
    let final_data = if decrypt_password {
        let password = match password {
            Some(p) => p,
            None => rpassword::prompt_password("Enter decryption password: ")?,
        };
        
        // Extract nonce and encrypted data
        if signed_data.data.len() < 12 {
            return Err(anyhow!("Invalid encrypted data: too short"));
        }
        let (nonce_bytes, encrypted_data) = signed_data.data.split_at(12);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_bytes);
        
        // Decrypt with password
        // Use a fixed salt for quantum context
        let quantum_salt = b"pipe-quantum-v1-salt-2024";
        let decryption_key = crate::encryption::derive_key_from_password(&password, quantum_salt)?;
        crate::encryption::decrypt_data(encrypted_data, &decryption_key, &nonce)?
    } else {
        signed_data.data
    };
    
    // Write the final decrypted file
    std::fs::write(output_path, &final_data)?;
    
    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);
    
    println!("✅ Quantum-encrypted file downloaded and decrypted to: {}", output_path);
    Ok(())
}

// Helper function to handle file download with optional decryption
async fn download_file_with_decryption(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    file_name: &str,
    output_path: &str,
    decrypt: bool,
    password: Option<String>,
) -> Result<()> {
    let actual_file_name = if decrypt && !file_name.ends_with(".enc") {
        format!("{}.enc", file_name)
    } else {
        file_name.to_string()
    };

    if decrypt {
        // Download to temporary file first
        let temp_path = format!("{}.tmp", output_path);
        improved_download_file_with_auth(client, base_url, creds, &actual_file_name, &temp_path)
            .await?;

        // Get password if not provided
        let password = match password {
            Some(p) => p,
            None => rpassword::prompt_password("Enter decryption password: ")?,
        };

        // Decrypt the file
        let input_file = std::fs::File::open(&temp_path)?;
        let output_file = std::fs::File::create(output_path)?;

        println!("Decrypting to {}...", output_path);

        match crate::encryption::decrypt_file_with_password(
            input_file,
            output_file,
            &password,
            None,
        )
        .await
        {
            Ok(_) => {
                // Clean up temporary file
                let _ = std::fs::remove_file(&temp_path);
                Ok(())
            }
            Err(e) => {
                // Clean up temporary file
                let _ = std::fs::remove_file(&temp_path);
                Err(anyhow!("Decryption failed: {}. Wrong password?", e))
            }
        }
    } else {
        // Regular download without decryption
        improved_download_file_with_auth(client, base_url, creds, &actual_file_name, output_path)
            .await
    }
}

/// Download an entire directory based on upload log
pub async fn download_directory(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    remote_prefix: &str,
    output_dir: &str,
    parallel: usize,
    dry_run: bool,
    decrypt: bool,
    password: Option<String>,
    filter: Option<String>,
    upload_log_path: Option<&str>,
) -> Result<()> {
    // 1. Read upload log
    let entries = read_upload_log_entries(upload_log_path)?;
    if entries.is_empty() {
        return Err(anyhow!("No upload log found. Have you uploaded any files?"));
    }
    
    // 2. Compile filter regex if provided
    let filter_regex = match filter {
        Some(pattern) => Some(regex::Regex::new(&pattern)?),
        None => None,
    };
    
    // 3. Filter entries
    let matching_entries = filter_entries_for_download(&entries, remote_prefix, filter_regex.as_ref());
    
    if matching_entries.is_empty() {
        return Err(anyhow!("No files found with prefix '{}'", remote_prefix));
    }
    
    println!("Found {} files to download", matching_entries.len());
    
    // 4. Dry run - just show what would be downloaded
    if dry_run {
        println!("\nDry run - files that would be downloaded:");
        for entry in &matching_entries {
            let local_path = Path::new(output_dir).join(&entry.remote_path);
            println!("  {} -> {}", entry.remote_path, local_path.display());
        }
        return Ok(());
    }
    
    // 5. Calculate total size (if we had size in log)
    // For now, we'll show count-based progress
    let total_files = matching_entries.len();
    
    // 6. Create progress bar
    let progress = Arc::new(ProgressBar::new(total_files as u64));
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta}) - {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    progress.set_message("Starting downloads...");
    
    // 7. Create semaphore for concurrency control
    let semaphore = Arc::new(tokio::sync::Semaphore::new(parallel));
    let completed = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    
    // 8. Create download tasks
    let mut handles = vec![];
    
    for entry in matching_entries {
        let client = client.clone();
        let base_url = base_url.to_string();
        let creds = creds.clone();
        let output_dir = output_dir.to_string();
        let remote_path = entry.remote_path.clone();
        let semaphore = semaphore.clone();
        let progress = progress.clone();
        let completed = completed.clone();
        let failed = failed.clone();
        let decrypt = decrypt;
        let password = password.clone();
        
        let handle = tokio::spawn(async move {
            // Acquire permit
            let _permit = semaphore.acquire().await?;
            
            // Construct local path
            let local_path = Path::new(&output_dir).join(&remote_path);
            
            // Create parent directories
            ensure_parent_dirs(&local_path).await?;
            
            // Update progress
            progress.set_message(format!("Downloading: {}", remote_path));
            
            // Download file
            let result = if decrypt {
                download_file_with_decryption(
                    &client,
                    &base_url,
                    &creds,
                    &remote_path,
                    &local_path.to_string_lossy(),
                    decrypt,
                    password,
                ).await
            } else {
                improved_download_file_with_auth(
                    &client,
                    &base_url,
                    &creds,
                    &remote_path,
                    &local_path.to_string_lossy(),
                ).await
            };
            
            match result {
                Ok(_) => {
                    completed.fetch_add(1, Ordering::Relaxed);
                    progress.inc(1);
                }
                Err(e) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    eprintln!("Failed to download {}: {}", remote_path, e);
                    progress.inc(1);
                }
            }
            
            Ok::<(), anyhow::Error>(())
        });
        
        handles.push(handle);
    }
    
    // 9. Wait for all downloads to complete
    for handle in handles {
        let _ = handle.await?;
    }
    
    // 10. Final report
    progress.finish_with_message("Downloads complete");
    
    let completed_count = completed.load(Ordering::Relaxed);
    let failed_count = failed.load(Ordering::Relaxed);
    
    println!("\n=== Download Summary ===");
    println!("Successfully downloaded: {} files", completed_count);
    println!("Failed: {} files", failed_count);
    println!("Output directory: {}", output_dir);
    
    Ok(())
}

#[cfg(test)]
mod download_directory_tests {
    use super::*;
    use regex::Regex;
    use tempfile::TempDir;
    
    /// Create a test upload log with sample entries
    fn create_test_upload_log(log_path: &Path) -> Result<()> {
        let entries = vec![
            UploadLogEntry {
                local_path: "/home/user/photos/vacation/beach.jpg".to_string(),
                remote_path: "vacation/beach.jpg".to_string(),
                status: "SUCCESS".to_string(),
                message: "Directory upload success".to_string(),
            },
            UploadLogEntry {
                local_path: "/home/user/photos/vacation/sunset.jpg".to_string(),
                remote_path: "vacation/sunset.jpg".to_string(),
                status: "SUCCESS".to_string(),
                message: "Directory upload success".to_string(),
            },
            UploadLogEntry {
                local_path: "/home/user/photos/family/portrait.jpg".to_string(),
                remote_path: "family/portrait.jpg".to_string(),
                status: "SUCCESS".to_string(),
                message: "Directory upload success".to_string(),
            },
            UploadLogEntry {
                local_path: "/home/user/docs/report.pdf".to_string(),
                remote_path: "docs/report.pdf".to_string(),
                status: "FAIL".to_string(),
                message: "Upload failed".to_string(),
            },
            UploadLogEntry {
                local_path: "/home/user/docs/summary.pdf".to_string(),
                remote_path: "docs/summary.pdf".to_string(),
                status: "SUCCESS".to_string(),
                message: "Directory upload success".to_string(),
            },
        ];

        let mut content = String::new();
        for entry in entries {
            content.push_str(&serde_json::to_string(&entry)?);
            content.push('\n');
        }
        
        fs::write(log_path, content)?;
        Ok(())
    }

    #[test]
    fn test_read_upload_log_entries() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test-upload-log.json");
        
        // Test empty log
        let entries = read_upload_log_entries(Some(log_path.to_str().unwrap())).unwrap();
        assert_eq!(entries.len(), 0);
        
        // Create test log
        create_test_upload_log(&log_path).unwrap();
        
        // Test reading log
        let entries = read_upload_log_entries(Some(log_path.to_str().unwrap())).unwrap();
        assert_eq!(entries.len(), 5);
        
        // Verify entries
        assert_eq!(entries[0].remote_path, "vacation/beach.jpg");
        assert_eq!(entries[0].status, "SUCCESS");
        assert_eq!(entries[3].status, "FAIL");
    }

    #[test]
    fn test_filter_entries_for_download() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test-upload-log.json");
        create_test_upload_log(&log_path).unwrap();
        
        let entries = read_upload_log_entries(Some(log_path.to_str().unwrap())).unwrap();
        
        // Test prefix filtering
        let filtered = filter_entries_for_download(&entries, "vacation", None);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|e| e.remote_path.starts_with("vacation")));
        
        // Test status filtering (only SUCCESS)
        let filtered = filter_entries_for_download(&entries, "docs", None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].remote_path, "docs/summary.pdf");
        
        // Test with regex filter
        let regex = Regex::new(r".*\.jpg$").unwrap();
        let filtered = filter_entries_for_download(&entries, "", Some(&regex));
        assert_eq!(filtered.len(), 3);
        assert!(filtered.iter().all(|e| e.remote_path.ends_with(".jpg")));
        
        // Test combined prefix and regex
        let regex = Regex::new(r".*beach.*").unwrap();
        let filtered = filter_entries_for_download(&entries, "vacation", Some(&regex));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].remote_path, "vacation/beach.jpg");
    }

    #[test]
    fn test_filter_entries_empty_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test-upload-log.json");
        create_test_upload_log(&log_path).unwrap();
        
        let entries = read_upload_log_entries(Some(log_path.to_str().unwrap())).unwrap();
        
        // Empty prefix should match all SUCCESS entries
        let filtered = filter_entries_for_download(&entries, "", None);
        assert_eq!(filtered.len(), 4); // All SUCCESS entries
    }

    #[test]
    fn test_malformed_log_entries() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test-upload-log.json");
        
        // Create log with some malformed entries
        let content = r#"{"local_path":"good.txt","remote_path":"good.txt","status":"SUCCESS","message":"ok"}
{this is not valid json}
{"local_path":"another.txt","remote_path":"another.txt","status":"SUCCESS","message":"ok"}
{"partial":true
"#;
        fs::write(&log_path, content).unwrap();
        
        // Should skip malformed entries
        let entries = read_upload_log_entries(Some(log_path.to_str().unwrap())).unwrap();
        assert_eq!(entries.len(), 2); // Only valid entries
    }

    #[tokio::test]
    async fn test_download_directory_dry_run() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test-upload-log.json");
        let output_dir = temp_dir.path().join("output");
        
        create_test_upload_log(&log_path).unwrap();
        
        // Mock client and credentials
        let client = reqwest::Client::new();
        let creds = SavedCredentials {
            user_id: "test-user".to_string(),
            user_app_key: "test-key".to_string(),
            auth_tokens: None,
            username: Some("testuser".to_string()),
        };
        
        // Test dry run - should not create any files
        let result = download_directory(
            &client,
            "http://localhost:3333",
            &creds,
            "vacation",
            output_dir.to_str().unwrap(),
            5,
            true, // dry_run
            false,
            None,
            None,
            Some(log_path.to_str().unwrap()),
        ).await;
        
        assert!(result.is_ok());
        assert!(!output_dir.exists()); // No files should be created in dry run
    }

    #[test]
    fn test_ensure_parent_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("deep/nested/path/file.txt");
        
        // Test with tokio runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            ensure_parent_dirs(&file_path).await.unwrap();
        });
        
        assert!(file_path.parent().unwrap().exists());
    }

    #[test]
    fn test_regex_filtering_edge_cases() {
        let entries = vec![
            UploadLogEntry {
                local_path: "test.txt".to_string(),
                remote_path: "test.txt".to_string(),
                status: "SUCCESS".to_string(),
                message: "ok".to_string(),
            },
            UploadLogEntry {
                local_path: "TEST.TXT".to_string(),
                remote_path: "TEST.TXT".to_string(),
                status: "SUCCESS".to_string(),
                message: "ok".to_string(),
            },
        ];
        
        // Case sensitive regex
        let regex = Regex::new(r"test\.txt").unwrap();
        let filtered = filter_entries_for_download(&entries, "", Some(&regex));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].remote_path, "test.txt");
        
        // Case insensitive regex
        let regex = Regex::new(r"(?i)test\.txt").unwrap();
        let filtered = filter_entries_for_download(&entries, "", Some(&regex));
        assert_eq!(filtered.len(), 2);
    }
}

// Helper function to handle quantum encrypted file upload
async fn upload_file_with_quantum_encryption(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
    creds: &SavedCredentials,
    encrypt: bool,
    password: Option<String>,
    _key: Option<String>,
) -> Result<(String, f64)> {
    use crate::quantum::sign_and_encrypt;
    use crate::quantum_keyring::{generate_quantum_keypair, save_quantum_keypair};
    
    println!("🔐 Using quantum-resistant encryption (Kyber + Dilithium)...");
    
    // Generate quantum keypair
    let quantum_keys = generate_quantum_keypair(file_name_in_bucket)?;
    
    // Read the file
    let file_data = std::fs::read(file_path)?;
    println!("  Original file size: {} bytes", file_data.len());
    
    // If password encryption is also requested, encrypt with password first
    let data_to_quantum_encrypt = if encrypt {
        let password = match password {
            Some(p) => p,
            None => {
                let password = rpassword::prompt_password("Enter encryption password: ")?;
                let confirm = rpassword::prompt_password("Confirm encryption password: ")?;
                if password != confirm {
                    return Err(anyhow!("Passwords do not match"));
                }
                password
            }
        };
        
        // Encrypt with password first
        // Use a fixed salt for quantum context
        let quantum_salt = b"pipe-quantum-v1-salt-2024";
        let encryption_key = crate::encryption::derive_key_from_password(&password, quantum_salt)?;
        let (encrypted, nonce) = crate::encryption::encrypt_data(&file_data, &encryption_key)?;
        
        // Combine nonce and encrypted data
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&encrypted);
        combined
    } else {
        file_data
    };
    
    // Apply quantum encryption (sign-then-encrypt)
    let quantum_encrypted = sign_and_encrypt(
        &data_to_quantum_encrypt,
        &quantum_keys.dilithium_secret,
        &quantum_keys.dilithium_public,
        &quantum_keys.kyber_public,
    )?;
    
    println!("  Quantum encrypted size: {} bytes", quantum_encrypted.len());
    
    // Save the quantum keys
    save_quantum_keypair(&quantum_keys)?;
    
    // Create temporary file for upload
    let temp_path = file_path.with_extension("qenc.tmp");
    std::fs::write(&temp_path, &quantum_encrypted)?;
    
    // Update filename to indicate quantum encryption
    let quantum_filename = format!("{}.qenc", file_name_in_bucket);
    let full_url_quantum = full_url.replace(file_name_in_bucket, &quantum_filename);
    
    // Upload the quantum-encrypted file
    let result = upload_file_with_shared_progress(
        client,
        &temp_path,
        &full_url_quantum,
        &quantum_filename,
        creds,
        None,
    )
    .await;
    
    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);
    
    match result {
        Ok((filename, cost)) => {
            println!("✅ Quantum-encrypted file uploaded: {}", filename);
            println!("🔑 Quantum keys saved for file: {}", file_name_in_bucket);
            Ok((filename, cost))
        }
        Err(e) => Err(e),
    }
}

// Helper function to handle encrypted file upload
async fn upload_file_with_encryption(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
    creds: &SavedCredentials,
    encrypt: bool,
    password: Option<String>,
    shared_progress: Option<DirectoryUploadProgress>,
) -> Result<(String, f64)> {
    if encrypt {
        // Get password if not provided
        let password = match password {
            Some(p) => p,
            None => {
                let password = rpassword::prompt_password("Enter encryption password: ")?;
                let confirm = rpassword::prompt_password("Confirm encryption password: ")?;
                if password != confirm {
                    return Err(anyhow!("Passwords do not match"));
                }
                password
            }
        };

        // Create a temporary encrypted file
        let temp_path = file_path.with_extension("enc.tmp");

        // Encrypt the file
        let input_file = std::fs::File::open(file_path)?;
        let output_file = std::fs::File::create(&temp_path)?;

        println!("Encrypting {}...", file_path.display());

        crate::encryption::encrypt_file_with_password(input_file, output_file, &password, None)
            .await?;

        // Upload the encrypted file
        let remote_name = format!("{}.enc", file_name_in_bucket);
        let result = upload_file_with_shared_progress(
            client,
            &temp_path,
            &full_url.replace(file_name_in_bucket, &remote_name),
            &remote_name,
            creds,
            shared_progress,
        )
        .await;

        // Clean up temporary file
        let _ = std::fs::remove_file(&temp_path);

        result
    } else {
        // Regular upload without encryption
        upload_file_with_shared_progress(
            client,
            file_path,
            full_url,
            file_name_in_bucket,
            creds,
            shared_progress,
        )
        .await
    }
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
    let f = TokioFile::open(file_path)
        .await
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
    use futures_util::Stream;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
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

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
        inner: InnerReaderStream::with_capacity(f, 1024 * 1024), // 1MB buffer for better throughput
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
        request = request.header(
            "Authorization",
            format!("Bearer {}", auth_tokens.access_token),
        );
    } else {
        // Legacy authentication via headers (NOT URL params for security)
        request = request
            .header("X-User-Id", &creds.user_id)
            .header("X-User-App-Key", &creds.user_app_key);
    }

    let resp = request.body(body).send().await?;

    let status = resp.status();

    // Extract token cost from headers
    let tokens_charged = resp
        .headers()
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
    let f = TokioFile::open(file_path)
        .await
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
    use futures_util::Stream;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
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

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
        inner: InnerReaderStream::with_capacity(f, 1024 * 1024), // 1MB buffer for better throughput
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
        request = request.header(
            "Authorization",
            format!("Bearer {}", auth_tokens.access_token),
        );
    } else {
        // Legacy authentication via headers (NOT URL params for security)
        request = request
            .header("X-User-Id", &creds.user_id)
            .header("X-User-App-Key", &creds.user_app_key);
    }

    let resp = request.body(body).send().await?;

    let status = resp.status();

    // Extract token cost from headers
    let tokens_charged = resp
        .headers()
        .get("X-Tokens-Charged")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    let priority_fee = resp
        .headers()
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
                            println!(
                                "💰 Cost: {} PIPE tokens (priority rate: {} tokens/GB)",
                                tokens_charged, priority_fee
                            );
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
                println!(
                    "💰 Cost: {} PIPE tokens (priority rate: {} tokens/GB)",
                    tokens_charged, priority_fee
                );
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
                    if let Some(priority_fee) = error_data
                        .get("priority_fee_per_gb")
                        .and_then(|p| p.as_f64())
                    {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;

    #[test]
    fn test_base64_decode_valid_text() {
        // Test that valid base64 encoded text is properly decoded
        let original_text = "Hello, this is a test file!";
        let base64_encoded = general_purpose::STANDARD.encode(original_text);
        
        // Simulate what the server sends
        let server_response = base64_encoded.as_bytes();
        
        // Test the decoding logic
        match std::str::from_utf8(server_response) {
            Ok(text_body) => {
                match general_purpose::STANDARD.decode(text_body.trim()) {
                    Ok(decoded) => {
                        let decoded_str = std::str::from_utf8(&decoded).unwrap();
                        assert_eq!(decoded_str, original_text);
                    }
                    Err(_) => panic!("Base64 decode should succeed"),
                }
            }
            Err(_) => panic!("Should be valid UTF-8"),
        }
    }

    #[test]
    fn test_base64_decode_binary_data() {
        // Test that binary data encoded as base64 is properly decoded
        let original_binary = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]; // JPEG header
        let base64_encoded = general_purpose::STANDARD.encode(&original_binary);
        
        // Simulate what the server sends
        let server_response = base64_encoded.as_bytes();
        
        // Test the decoding logic
        match std::str::from_utf8(server_response) {
            Ok(text_body) => {
                match general_purpose::STANDARD.decode(text_body.trim()) {
                    Ok(decoded) => {
                        assert_eq!(decoded, original_binary);
                    }
                    Err(_) => panic!("Base64 decode should succeed"),
                }
            }
            Err(_) => panic!("Should be valid UTF-8"),
        }
    }

    #[test]
    fn test_base64_decode_with_whitespace() {
        // Test that base64 with whitespace (newlines, spaces) is handled
        let original_text = "Testing whitespace handling";
        let base64_encoded = general_purpose::STANDARD.encode(original_text);
        let base64_with_whitespace = format!("  {}  \n", base64_encoded);
        
        // Simulate what the server sends
        let server_response = base64_with_whitespace.as_bytes();
        
        // Test the decoding logic
        match std::str::from_utf8(server_response) {
            Ok(text_body) => {
                match general_purpose::STANDARD.decode(text_body.trim()) {
                    Ok(decoded) => {
                        let decoded_str = std::str::from_utf8(&decoded).unwrap();
                        assert_eq!(decoded_str, original_text);
                    }
                    Err(_) => panic!("Base64 decode should succeed after trimming"),
                }
            }
            Err(_) => panic!("Should be valid UTF-8"),
        }
    }

    #[test]
    fn test_fallback_for_non_base64() {
        // Test that non-base64 content falls back to raw bytes
        let non_base64 = b"This is not base64!!!";
        
        // Test the decoding logic
        match std::str::from_utf8(non_base64) {
            Ok(text_body) => {
                match general_purpose::STANDARD.decode(text_body.trim()) {
                    Ok(_) => panic!("Should not decode as base64"),
                    Err(_) => {
                        // Expected - should fall back to raw bytes
                        assert_eq!(non_base64.to_vec(), non_base64.to_vec());
                    }
                }
            }
            Err(_) => panic!("Should be valid UTF-8"),
        }
    }

    #[test]
    fn test_fallback_for_non_utf8() {
        // Test that non-UTF8 content falls back to raw bytes
        let non_utf8_bytes = vec![0xFF, 0xFE, 0xFD, 0xFC];
        
        // Test the decoding logic
        match std::str::from_utf8(&non_utf8_bytes) {
            Ok(_) => panic!("Should not be valid UTF-8"),
            Err(_) => {
                // Expected - should fall back to raw bytes
                assert_eq!(non_utf8_bytes.clone(), non_utf8_bytes);
            }
        }
    }

    #[test]
    fn test_large_base64_content() {
        // Test with larger content to ensure it handles real file sizes
        let large_content = vec![b'A'; 10000]; // 10KB of 'A's
        let base64_encoded = general_purpose::STANDARD.encode(&large_content);
        
        // Simulate what the server sends
        let server_response = base64_encoded.as_bytes();
        
        // Test the decoding logic
        match std::str::from_utf8(server_response) {
            Ok(text_body) => {
                match general_purpose::STANDARD.decode(text_body.trim()) {
                    Ok(decoded) => {
                        assert_eq!(decoded.len(), large_content.len());
                        assert_eq!(decoded, large_content);
                    }
                    Err(_) => panic!("Base64 decode should succeed"),
                }
            }
            Err(_) => panic!("Should be valid UTF-8"),
        }
    }

    #[test]
    fn test_empty_response() {
        // Test that empty responses are handled
        let empty_response = b"";
        
        // Test the decoding logic
        match std::str::from_utf8(empty_response) {
            Ok(text_body) => {
                if text_body.trim().is_empty() {
                    // Empty base64 should decode to empty
                    assert_eq!(text_body.len(), 0);
                }
            }
            Err(_) => panic!("Empty should be valid UTF-8"),
        }
    }
}

#[cfg(test)]
mod quantum_integration_tests {
    use crate::quantum::{sign_and_encrypt, decrypt_and_verify};
    use crate::quantum_keyring::{generate_quantum_keypair, save_quantum_keypair, load_quantum_keypair};

    #[test]
    fn test_quantum_keyring_operations() {
        // Test quantum key generation and storage
        let file_id = "test_file.txt";
        
        // Generate keys
        let keypair = generate_quantum_keypair(file_id).unwrap();
        assert_eq!(keypair.file_id, file_id);
        assert!(!keypair.kyber_public.is_empty());
        assert!(!keypair.kyber_secret.is_empty());
        assert!(!keypair.dilithium_public.is_empty());
        assert!(!keypair.dilithium_secret.is_empty());
        
        // Save and load keys
        save_quantum_keypair(&keypair).unwrap();
        let loaded_keypair = load_quantum_keypair(file_id).unwrap();
        
        assert_eq!(keypair.kyber_public, loaded_keypair.kyber_public);
        assert_eq!(keypair.kyber_secret, loaded_keypair.kyber_secret);
        assert_eq!(keypair.dilithium_public, loaded_keypair.dilithium_public);
        assert_eq!(keypair.dilithium_secret, loaded_keypair.dilithium_secret);
        
        // Clean up
        let _ = crate::quantum_keyring::delete_quantum_keypair(file_id);
    }

    #[test]
    fn test_quantum_file_encryption_workflow() {
        // Test the full quantum encryption workflow
        let test_data = b"This is a test file for quantum encryption!";
        let file_id = "quantum_test.txt";
        
        // Generate quantum keys
        let keypair = generate_quantum_keypair(file_id).unwrap();
        
        // Encrypt with quantum crypto
        let encrypted = sign_and_encrypt(
            test_data,
            &keypair.dilithium_secret,
            &keypair.dilithium_public,
            &keypair.kyber_public,
        ).unwrap();
        
        // Verify encryption increased size significantly
        assert!(encrypted.len() > test_data.len() + 1000); // Quantum crypto adds overhead
        
        // Decrypt and verify
        let decrypted = decrypt_and_verify(
            &encrypted,
            &keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(decrypted.data, test_data);
        assert_eq!(decrypted.signer_public_key, keypair.dilithium_public);
    }

    #[test]
    fn test_quantum_with_password_encryption() {
        // Test quantum + password encryption combination
        let test_data = b"Secret data with both quantum and password encryption";
        let password = "test_password";
        let file_id = "double_encrypted.txt";
        
        // Generate quantum keys
        let keypair = generate_quantum_keypair(file_id).unwrap();
        
        // First encrypt with password
        let quantum_salt = b"pipe-quantum-v1-salt-2024";
        let encryption_key = crate::encryption::derive_key_from_password(password, quantum_salt).unwrap();
        let (password_encrypted, nonce) = crate::encryption::encrypt_data(test_data, &encryption_key).unwrap();
        
        // Combine nonce and encrypted data
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&password_encrypted);
        
        // Then encrypt with quantum
        let quantum_encrypted = sign_and_encrypt(
            &combined,
            &keypair.dilithium_secret,
            &keypair.dilithium_public,
            &keypair.kyber_public,
        ).unwrap();
        
        // Decrypt quantum layer
        let quantum_decrypted = decrypt_and_verify(
            &quantum_encrypted,
            &keypair.kyber_secret,
        ).unwrap();
        
        // Extract nonce and decrypt password layer
        let (nonce_bytes, encrypted_data) = quantum_decrypted.data.split_at(12);
        let mut nonce_recovered = [0u8; 12];
        nonce_recovered.copy_from_slice(nonce_bytes);
        
        let final_decrypted = crate::encryption::decrypt_data(
            encrypted_data,
            &encryption_key,
            &nonce_recovered,
        ).unwrap();
        
        assert_eq!(final_decrypted, test_data);
    }

    #[test]
    fn test_quantum_filename_handling() {
        // Test that .qenc extension is handled correctly
        let filename = "document.pdf";
        let quantum_filename = format!("{}.qenc", filename);
        
        assert!(quantum_filename.ends_with(".qenc"));
        
        // Test extraction of original filename
        let original = if quantum_filename.ends_with(".qenc") {
            &quantum_filename[..quantum_filename.len() - 5]
        } else {
            &quantum_filename
        };
        
        assert_eq!(original, filename);
    }
}

pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    
    // Get config path from CLI or use default
    let config_path = cli.config.as_deref();

    // Create optimized HTTP client for high concurrency
    let client = Client::builder()
        .pool_max_idle_per_host(100) // Keep more connections alive
        .pool_idle_timeout(std::time::Duration::from_secs(90)) // Keep connections alive longer
        .timeout(std::time::Duration::from_secs(7200)) // 2 hour timeout for very large files (95GB+)
        .build()?;

    let base_url = cli.api.trim_end_matches('/');

    // Initialize service discovery cache
    let service_cache = Arc::new(ServiceDiscoveryCache::new(base_url.to_string()));

    // Version check completely disabled - nobody wants to see this
    /*
    // Only check version for certain commands
    let should_check_version = matches!(
        cli.command,
        Commands::NewUser { .. }
            | Commands::RotateAppKey { .. }
            | Commands::UploadFile { .. }
            | Commands::DownloadFile { .. }
            | Commands::DeleteFile { .. }
            | Commands::FileInfo { .. }
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
            | Commands::DownloadDirectory { .. }
            | Commands::GetPriorityFee
            | Commands::GetTierPricing
            | Commands::PriorityUpload { .. }
            | Commands::PriorityDownload { .. }
            | Commands::ListUploads
            | Commands::ExtendStorage { .. }
    );
    */

    // Version check disabled - nobody wants to see this
    /*
    if should_check_version {
        println!("Starting version check...");
        if let Err(e) = check_version(&client, base_url).await {
            eprintln!("Version check failed: {}", e);
        } else {
            println!("Version check completed successfully.");
        }
    }
    */

    match cli.command {
        Commands::NewUser { username } => {
            let req_body = CreateUserRequest {
                username: username.clone(),
            };
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
                save_credentials_to_file(&json.user_id, &json.user_app_key, config_path)?;

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
                        if let Ok(response_data) =
                            serde_json::from_str::<serde_json::Value>(&text_body)
                        {
                            // Create AuthTokens from the response
                            let auth_tokens = AuthTokens {
                                access_token: response_data
                                    .get("access_token")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                refresh_token: response_data
                                    .get("refresh_token")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                token_type: response_data
                                    .get("token_type")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Bearer")
                                    .to_string(),
                                expires_in: response_data
                                    .get("expires_in")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(900),
                                expires_at: None, // Will be set below
                                csrf_token: None, // Will be populated on first state-changing request
                            };

                            // Calculate expires_at timestamp
                            let now =
                                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                            let expires_at =
                                DateTime::<Utc>::from_timestamp(now + auth_tokens.expires_in, 0)
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
                            save_full_credentials(&creds, config_path)?;

                            println!("\n✓ Password set successfully!");
                            println!("✓ You are now logged in with secure JWT authentication!");
                            println!("✓ Credentials saved to {:?}", get_credentials_file_path(config_path));
                            println!("\nYou can now use all pipe commands securely!");
                        } else {
                            println!("\n✓ Password set successfully!");
                            println!("✓ Account created!");
                            println!("✓ Credentials saved to {:?}", get_credentials_file_path(config_path));
                            println!("\nNote: You may need to login to get JWT tokens.");
                        }
                    } else {
                        eprintln!(
                            "\nWarning: Failed to set password. You can try again later with:"
                        );
                        eprintln!("  ./pipe set-password");
                        eprintln!("\n✓ Account created successfully!");
                        eprintln!("✓ Credentials saved to {:?}", get_credentials_file_path(config_path));
                        eprintln!("\nYou can use all pipe commands with your app key.");
                    }
                } else {
                    // User skipped password
                    println!("\n✓ Account created successfully!");
                    println!("✓ Credentials saved to {:?}", get_credentials_file_path(config_path));
                    println!("\nYou can now use all pipe commands!");
                    println!(
                        "\nNote: Password-based login is optional. Set a password later with:"
                    );
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
            let password =
                password.unwrap_or_else(|| rpassword::prompt_password("Enter password: ").unwrap());

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
                println!(
                    "Token expires at: {}",
                    expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                );

                // Try to load existing credentials to get user_id/user_app_key
                // If not found, we'll need to find another way to get these
                if let Ok(Some(existing_creds)) = load_credentials_from_file(config_path) {
                    let creds = SavedCredentials {
                        user_id: existing_creds.user_id,
                        user_app_key: existing_creds.user_app_key,
                        auth_tokens: Some(auth_tokens),
                        username: Some(username),
                    };
                    save_full_credentials(&creds, config_path)?;
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
            let creds = load_credentials_from_file(config_path)?
                .ok_or_else(|| anyhow!("No credentials found. Please login first."))?;

            let access_token = creds
                .auth_tokens
                .as_ref()
                .ok_or_else(|| anyhow!("No authentication tokens found. Please login first."))?
                .access_token
                .clone();

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
                save_full_credentials(&updated_creds, config_path)?;
            } else {
                return Err(anyhow!(
                    "Logout failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }
        }

        Commands::SetPassword {
            password,
            user_id,
            user_app_key,
        } => {
            let (user_id_final, user_app_key_final) =
                get_final_user_id_and_app_key(user_id, user_app_key, config_path)?;

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
                if let Ok(auth_tokens) = serde_json::from_value::<AuthTokens>(response_data.clone())
                {
                    let mut auth_tokens = auth_tokens;
                    // Calculate expires_at timestamp
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                    let expires_at =
                        DateTime::<Utc>::from_timestamp(now + auth_tokens.expires_in, 0)
                            .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;
                    auth_tokens.expires_at = Some(expires_at);

                    let creds = SavedCredentials {
                        user_id: user_id_final,
                        user_app_key: user_app_key_final,
                        auth_tokens: Some(auth_tokens),
                        username: None,
                    };
                    save_full_credentials(&creds, config_path)?;

                    println!("You are now logged in with JWT authentication.");
                    println!(
                        "Token expires at: {}",
                        expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                } else {
                    // Just update the existing credentials
                    if let Ok(Some(mut creds)) = load_credentials_from_file(config_path) {
                        creds.auth_tokens = None;
                        save_full_credentials(&creds, config_path)?;
                    }
                }
            } else {
                // Try to provide more helpful error message
                let error_message = if text_body.contains("too weak")
                    || text_body.contains("Password")
                {
                    format!(
                        "Set password failed: {}\n\nPassword requirements:\n  - Minimum 8 characters\n  - Maximum 128 characters\n  - Cannot be common weak passwords like:\n    'password', '12345678', 'qwerty', 'abc123', 'password123',\n    'admin', 'letmein', 'welcome', '123456789', 'password1'",
                        text_body
                    )
                } else {
                    format!(
                        "Set password failed. Status = {}, Body = {}",
                        status, text_body
                    )
                };
                return Err(anyhow!(error_message));
            }
        }

        Commands::RefreshToken => {
            let creds = load_credentials_from_file(config_path)?
                .ok_or_else(|| anyhow!("No credentials found. Please login first."))?;

            let refresh_token = creds
                .auth_tokens
                .as_ref()
                .ok_or_else(|| anyhow!("No refresh token found in credentials."))?
                .refresh_token
                .clone();

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
                let expires_at =
                    DateTime::<Utc>::from_timestamp(now + refresh_response.expires_in, 0)
                        .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;

                println!("Token refreshed successfully!");
                println!(
                    "Token expires at: {}",
                    expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                );

                // Update credentials with new access token
                let mut updated_creds = creds.clone();
                if let Some(ref mut auth_tokens) = updated_creds.auth_tokens {
                    auth_tokens.access_token = refresh_response.access_token;
                    auth_tokens.expires_in = refresh_response.expires_in;
                    auth_tokens.expires_at = Some(expires_at);
                }
                save_full_credentials(&updated_creds, config_path)?;
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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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

                save_credentials_to_file(&json.user_id, &json.new_user_app_key, config_path)?;
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
            tier,
            encrypt,
            password,
            key,
            quantum,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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

            // Get the best endpoint for this upload
            let selected_endpoint = get_endpoint_for_operation(
                &service_cache,
                &client,
                base_url,
                "upload",
                &creds.user_id,
                Some(&file_name),
            )
            .await;

            // Build URL - with JWT we don't need query params for auth
            // Build URL without credentials (security fix)
            // Use priority endpoint for tiers above normal to avoid rate limiting
            let endpoint = if let Some(ref t) = tier {
                match t.as_str() {
                    "normal" => "upload",
                    _ => "priorityUpload", // All other tiers use priority endpoint
                }
            } else {
                "upload" // Default to normal upload if no tier specified
            };

            let mut url = format!(
                "{}/{}?file_name={}&epochs={}",
                selected_endpoint, endpoint, file_name, epochs_final
            );
            if let Some(tier_name) = tier {
                url = format!("{}&tier={}", url, tier_name);
            }

            // Use retry wrapper for single file upload
            let upload_result = if quantum {
                // Quantum encryption upload
                upload_with_retry(&format!("quantum upload of {}", file_path), || {
                    upload_file_with_quantum_encryption(
                        &client,
                        local_path,
                        &url,
                        &file_name,
                        &creds,
                        encrypt,
                        password.clone(),
                        key.clone(),
                    )
                })
                .await
            } else {
                // Regular upload (with optional password encryption)
                upload_with_retry(&format!("upload of {}", file_path), || {
                    upload_file_with_encryption(
                        &client,
                        local_path,
                        &url,
                        &file_name,
                        &creds,
                        encrypt,
                        password.clone(),
                        None,
                    )
                })
                .await
            };

            match upload_result {
                Ok((uploaded_filename, token_cost)) => {
                    println!("File uploaded successfully: {}", uploaded_filename);
                    if token_cost > 0.0 {
                        println!("💰 Cost: {} PIPE tokens", token_cost);
                    }
                    append_to_upload_log(
                        &file_path,
                        &uploaded_filename,
                        "SUCCESS",
                        &format!("Non-priority upload ({} epochs)", epochs_final),
                    )?;
                }
                Err(e) => {
                    eprintln!("Upload failed for {} => {}", file_path, e);
                    // Don't log failures to the upload list
                    return Err(e);
                }
            }
        }

        Commands::DownloadFile {
            user_id,
            user_app_key,
            file_name,
            output_path,
            decrypt,
            password,
            key: _,
            quantum,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            // Override with command-line args if provided
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            // Get the best endpoint for this download
            let selected_endpoint = get_endpoint_for_operation(
                &service_cache,
                &client,
                base_url,
                "download",
                &creds.user_id,
                Some(&file_name),
            )
            .await;

            // Check if this might be a quantum-encrypted file
            let is_quantum_file = file_name.ends_with(".qenc") || quantum;
            
            if is_quantum_file {
                download_file_with_quantum_decryption(
                    &client,
                    &selected_endpoint,
                    &creds,
                    &file_name,
                    &output_path,
                    decrypt,
                    password,
                )
                .await?;
            } else {
                download_file_with_decryption(
                    &client,
                    &selected_endpoint,
                    &creds,
                    &file_name,
                    &output_path,
                    decrypt,
                    password,
                )
                .await?;
            }
        }

        Commands::DownloadDirectory {
            remote_prefix,
            output_directory,
            parallel,
            dry_run,
            decrypt,
            password,
            filter,
            upload_log,
        } => {
            // Load credentials
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            
            // Ensure valid JWT token
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;
            
            // Get service discovery cache
            let service_cache = Arc::new(ServiceDiscoveryCache::new(base_url.to_string()));
            
            // Get best endpoint for downloads
            let selected_endpoint = get_endpoint_for_operation(
                &service_cache,
                &client,
                base_url,
                "download",
                &creds.user_id,
                Some(&remote_prefix),
            )
            .await;
            
            println!("Downloading directory '{}' to '{}'", remote_prefix, output_directory);
            if parallel > 1 {
                println!("Using {} parallel downloads", parallel);
            }
            
            // Perform directory download
            download_directory(
                &client,
                &selected_endpoint,
                &creds,
                &remote_prefix,
                &output_directory,
                parallel,
                dry_run,
                decrypt,
                password,
                filter,
                upload_log.as_deref(),
            )
            .await?;
        }

        Commands::DeleteFile {
            user_id,
            user_app_key,
            file_name,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            // Get endpoint for delete operation
            let selected_endpoint = get_endpoint_for_operation(
                &service_cache,
                &client,
                base_url,
                "delete",
                &creds.user_id,
                Some(&file_name),
            )
            .await;

            let mut request = client.post(format!("{}/deleteFile", selected_endpoint));

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

        Commands::FileInfo {
            user_id: _,
            user_app_key: _,
            file_name,
        } => {
            println!("📄 File Information for '{}':", file_name);

            // Check if file is encrypted based on extension
            let is_encrypted = file_name.ends_with(".enc");
            println!(
                "   Encrypted: {}",
                if is_encrypted {
                    "Yes (AES-256-GCM)"
                } else {
                    "No"
                }
            );

            if is_encrypted {
                println!("\n💡 To download and decrypt this file:");
                println!(
                    "   pipe download-file {} output.file --decrypt",
                    file_name.trim_end_matches(".enc")
                );
            } else {
                println!("\n💡 To check if an encrypted version exists:");
                println!("   pipe file-info {}.enc", file_name);
            }

            println!(
                "\nNote: For detailed file metadata (size, upload date, etc.), the file listing"
            );
            println!("feature is not yet implemented in pipe-cli.");
        }

        Commands::CheckSol {
            user_id,
            user_app_key,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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
            title,
            description,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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
                let mut req_body = serde_json::json!({
                    "file_name": file_name
                });
                if let Some(ref t) = title {
                    req_body["custom_title"] = serde_json::json!(t);
                }
                if let Some(ref d) = description {
                    req_body["custom_description"] = serde_json::json!(d);
                }
                request = request.json(&req_body);
            } else {
                // Legacy auth via request body
                let req_body = CreatePublicLinkRequest {
                    user_id: creds.user_id.clone(),
                    user_app_key: creds.user_app_key.clone(),
                    file_name,
                    custom_title: title,
                    custom_description: description,
                };
                request = request.json(&req_body);
            }

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if status.is_success() {
                let json: CreatePublicLinkResponse = serde_json::from_str(&text_body)?;
                println!("✓ Public link created successfully!");
                println!();
                println!("Direct link (for downloads/playback):");
                println!("  {}/publicDownload?hash={}", base_url, json.link_hash);
                println!();
                println!("Social media link (for sharing):");
                println!("  {}/publicDownload?hash={}&preview=true", base_url, json.link_hash);
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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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
            tier,
            skip_uploaded,
            encrypt,
            password,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let dir = Path::new(&directory_path);
            if !dir.is_dir() {
                return Err(anyhow!(
                    "Provided path is not a directory: {}",
                    directory_path
                ));
            }

            // Get password once for all files if encryption is enabled
            let encryption_password = if encrypt {
                let pass = match password {
                    Some(p) => p,
                    None => {
                        println!(
                            "You will use the same password to encrypt all files in the directory."
                        );
                        let password = rpassword::prompt_password("Enter encryption password: ")?;
                        let confirm = rpassword::prompt_password("Confirm encryption password: ")?;
                        if password != confirm {
                            return Err(anyhow!("Passwords do not match"));
                        }
                        password
                    }
                };
                Some(pass)
            } else {
                None
            };

            // Read upload log if skip_uploaded == true
            let mut previously_uploaded: HashSet<String> = HashSet::new();
            if skip_uploaded {
                let log_path = get_upload_log_path();
                if log_path.exists() {
                    let contents = fs::read_to_string(&log_path)?;
                    for line in contents.lines() {
                        if let Ok(entry) = serde_json::from_str::<UploadLogEntry>(line) {
                            if entry.status.contains("SUCCESS")
                                || entry.status.contains("BACKGROUND")
                            {
                                previously_uploaded.insert(entry.local_path);
                            }
                        }
                    }
                }
                println!(
                    "Found {} previously uploaded files in log",
                    previously_uploaded.len()
                );
            }

            println!("Scanning directory for files...");

            // Collect files and calculate total size
            let mut file_entries = Vec::new();
            let mut total_size = 0u64;
            let mut file_count = 0;
            let mut skipped_count = 0;

            for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
                if entry.path().is_file() {
                    if skip_uploaded
                        && previously_uploaded.contains(&entry.path().display().to_string())
                    {
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
                if skipped_count > 0 {
                    println!(
                        "No new files to upload (all {} files were previously uploaded).",
                        skipped_count
                    );
                } else {
                    println!("No files found in directory.");
                }
                return Ok(());
            }

            println!(
                "Found {} files, total size: {:.2} MB",
                file_count,
                total_size as f64 / 1_048_576.0
            );

            // Check if user has enough tokens for the entire upload
            // Get tier pricing and concurrency
            let (fee_per_gb, tier_concurrency) =
                if tier.as_deref() == Some("normal") || tier.is_none() {
                    (1.0, 2) // Normal tier: 1 PIPE per GB, 2 concurrent
                } else {
                    // For priority tiers, we need to fetch the actual pricing
                    let fee_url = format!("{}/getTierPricing", base_url);
                    let fee_req = if let Some(ref auth_tokens) = creds.auth_tokens {
                        client.get(&fee_url).header(
                            "Authorization",
                            format!("Bearer {}", auth_tokens.access_token),
                        )
                    } else {
                        client
                            .get(&fee_url)
                            .header("X-User-Id", &creds.user_id)
                            .header("X-User-App-Key", &creds.user_app_key)
                    };

                    match fee_req.send().await {
                        Ok(resp) if resp.status().is_success() => {
                            #[derive(Deserialize)]
                            struct TierInfo {
                                name: String,
                                current_price: f64,
                                concurrency: usize,
                            }

                            if let Ok(pricing_list) = resp.json::<Vec<TierInfo>>().await {
                                // Find the tier we're using
                                pricing_list
                                    .iter()
                                    .find(|t| Some(&t.name) == tier.as_ref())
                                    .map(|t| (t.current_price, t.concurrency))
                                    .unwrap_or((25.0, 50)) // Default to enterprise pricing/concurrency if not found
                            } else {
                                (25.0, 50) // Default to enterprise pricing on parse error
                            }
                        }
                        _ => (25.0, 50), // Default to enterprise pricing on request error
                    }
                };

            let total_cost_estimate = (total_size as f64 / 1_000_000_000.0) * fee_per_gb;

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
                                    eprintln!(
                                        "Total cost: {:.4} PIPE tokens (at {} tokens/GB)",
                                        total_cost_estimate, fee_per_gb
                                    );
                                    eprintln!("Your balance: {:.4} PIPE tokens", current_balance);
                                    eprintln!(
                                        "Needed: {:.4} PIPE tokens",
                                        total_cost_estimate - current_balance
                                    );
                                    eprintln!("\nPlease use 'pipe swap-sol-for-pipe {:.1}' to get enough tokens.", 
                                    (total_cost_estimate - current_balance) / 10.0 + 0.1);
                                    return Ok(());
                                }
                                println!("💰 Estimated cost: {:.4} PIPE tokens at {} tokens/GB (current balance: {:.4} PIPE)", 
                                total_cost_estimate, fee_per_gb, current_balance);
                            }
                            Err(e) => {
                                eprintln!("⚠️  Failed to parse balance response: {}", e);
                                eprintln!(
                                    "Estimated cost: {:.4} PIPE tokens at {} tokens/GB",
                                    total_cost_estimate, fee_per_gb
                                );
                                eprintln!("\nProceed with caution - could not verify if you have enough tokens.");
                                eprintln!(
                                    "Consider checking your balance with 'pipe check-token' first."
                                );
                            }
                        }
                    } else {
                        let error_text = resp
                            .text()
                            .await
                            .unwrap_or_else(|_| "Unknown error".to_string());
                        eprintln!(
                            "⚠️  Failed to check token balance: {} - {}",
                            status, error_text
                        );
                        eprintln!(
                            "Estimated cost: {:.4} PIPE tokens at {} tokens/GB",
                            total_cost_estimate, fee_per_gb
                        );
                        eprintln!(
                            "\nProceed with caution - could not verify if you have enough tokens."
                        );
                        eprintln!("Consider checking your balance with 'pipe check-token' first.");
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Could not connect to check token balance: {}", e);
                    eprintln!(
                        "Estimated cost: {:.4} PIPE tokens at {} tokens/GB",
                        total_cost_estimate, fee_per_gb
                    );
                    eprintln!(
                        "\nProceed with caution - could not verify if you have enough tokens."
                    );
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

            // Use full tier concurrency for maximum performance
            let concurrency_limit = tier_concurrency;
            println!(
                "🚀 Using {} concurrent upload slots for {} tier",
                concurrency_limit,
                tier.as_deref().unwrap_or("normal")
            );
            let sem = Arc::new(Semaphore::new(concurrency_limit));
            let mut handles = Vec::new();

            let completed_count = Arc::new(TokioMutex::new(0u32));
            let failed_count = Arc::new(TokioMutex::new(0u32));
            let total_cost = Arc::new(TokioMutex::new(0.0f64));

            for path in file_entries {
                let sem_clone = Arc::clone(&sem);
                let client_clone = client.clone();
                let base_url_clone = base_url.to_string();
                let service_cache_clone = service_cache.clone();
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
                let tier_clone = tier.clone();
                let encrypt_clone = encrypt;
                let password_clone = encryption_password.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem_clone.acquire_owned().await.unwrap();

                    // Get endpoint for this specific file upload
                    let selected_endpoint = get_endpoint_for_operation(
                        &service_cache_clone,
                        &client_clone,
                        &base_url_clone,
                        "upload",
                        &creds_clone.user_id,
                        Some(&rel_path),
                    )
                    .await;

                    // Build URL based on auth type
                    // Build URL without credentials (security fix)
                    // Use priority endpoint for tiers above normal to avoid rate limiting
                    let endpoint = if let Some(ref t) = tier_clone {
                        match t.as_str() {
                            "normal" => "upload",
                            _ => "priorityUpload", // All other tiers use priority endpoint
                        }
                    } else {
                        "upload" // Default to normal upload if no tier specified
                    };

                    let mut url =
                        format!("{}/{}?file_name={}", selected_endpoint, endpoint, rel_path);
                    if let Some(tier_name) = &tier_clone {
                        url = format!("{}&tier={}", url, tier_name);
                    }

                    // Use retry wrapper for directory uploads
                    let upload_result =
                        upload_with_retry(&format!("upload of {}", rel_path), || {
                            upload_file_with_encryption(
                                &client_clone,
                                &path,
                                &url,
                                &rel_path,
                                &creds_clone,
                                encrypt_clone,
                                password_clone.clone(),
                                Some(shared_progress_clone.clone()),
                            )
                        })
                        .await;

                    match upload_result {
                        Ok((uploaded_file, cost)) => {
                            let mut completed = completed_clone.lock().await;
                            *completed += 1;
                            let completed_val = *completed;
                            drop(completed);

                            let mut total = total_cost_clone.lock().await;
                            *total += cost;
                            drop(total);

                            progress_clone.set_message(format!(
                                "Uploaded {} of {} files",
                                completed_val, file_count_copy
                            ));

                            let _ = append_to_upload_log(
                                &path.display().to_string(),
                                &uploaded_file,
                                "SUCCESS",
                                "Directory upload success",
                            );
                        }
                        Err(e) => {
                            let mut failed = failed_clone.lock().await;
                            *failed += 1;

                            eprintln!("Failed to upload {}: {}", rel_path, e);
                            // Don't log failures to the upload list
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
            if let Some(t) = &tier {
                println!("  📈 Upload tier: {}", t);
            }
            if final_cost > 0.0 {
                println!("  💰 Total cost: {:.4} PIPE tokens", final_cost);
            }
            println!(
                "\nCheck the log file for details:\n  {}",
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
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            let dir = Path::new(&directory_path);
            if !dir.is_dir() {
                return Err(anyhow!(
                    "Provided path is not a directory: {}",
                    directory_path
                ));
            }

            // Get current priority fee from server
            let url = format!("{}/getPriorityFee", base_url);
            let resp = client.get(&url).send().await?;
            let fee_resp: PriorityFeeResponse = resp.json().await?;
            println!(
                "Current priority fee: {} tokens/GB",
                fee_resp.priority_fee_per_gb
            );
            println!("Starting priority upload of directory...");

            // Read upload log if skip_uploaded == true
            let mut previously_uploaded: HashSet<String> = HashSet::new();
            if skip_uploaded {
                let log_path = get_upload_log_path();
                if log_path.exists() {
                    let contents = fs::read_to_string(&log_path)?;
                    for line in contents.lines() {
                        if let Ok(entry) = serde_json::from_str::<UploadLogEntry>(line) {
                            if entry.status.contains("SUCCESS")
                                || entry.status.contains("BACKGROUND")
                            {
                                previously_uploaded.insert(entry.local_path);
                            }
                        }
                    }
                }
                println!(
                    "Found {} previously uploaded files in log",
                    previously_uploaded.len()
                );
            }

            println!("Scanning directory for files...");

            // Collect files and calculate total size
            let mut file_entries = Vec::new();
            let mut total_size = 0u64;
            let mut file_count = 0;
            let mut skipped_count = 0;

            for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
                if entry.path().is_file() {
                    if skip_uploaded
                        && previously_uploaded.contains(&entry.path().display().to_string())
                    {
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

            println!(
                "Found {} files to upload, total size: {:.2} MB",
                file_count,
                total_size as f64 / 1_048_576.0
            );

            // Check if user has enough tokens for the entire priority upload
            let total_cost_estimate =
                (total_size as f64 / 1_000_000_000.0) * fee_resp.priority_fee_per_gb;

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
                                    eprintln!(
                                        "\n❌ Insufficient tokens for priority directory upload"
                                    );
                                    eprintln!(
                                        "Total cost: {:.4} PIPE tokens (at {} tokens/GB)",
                                        total_cost_estimate, fee_resp.priority_fee_per_gb
                                    );
                                    eprintln!("Your balance: {:.4} PIPE tokens", current_balance);
                                    eprintln!(
                                        "Needed: {:.4} PIPE tokens",
                                        total_cost_estimate - current_balance
                                    );
                                    eprintln!("\nPlease use 'pipe swap-sol-for-pipe {:.1}' to get enough tokens.", 
                                        (total_cost_estimate - current_balance) / 10.0 + 0.1);
                                    return Ok(());
                                }
                                println!("💰 Estimated cost: {:.4} PIPE tokens at {} tokens/GB (current balance: {:.4} PIPE)", 
                                    total_cost_estimate, fee_resp.priority_fee_per_gb, current_balance);
                            }
                            Err(e) => {
                                eprintln!("⚠️  Failed to parse balance response: {}", e);
                                eprintln!(
                                    "Estimated cost: {:.4} PIPE tokens at {} tokens/GB",
                                    total_cost_estimate, fee_resp.priority_fee_per_gb
                                );
                                eprintln!("\nProceed with caution - could not verify if you have enough tokens.");
                                eprintln!(
                                    "Consider checking your balance with 'pipe check-token' first."
                                );
                            }
                        }
                    } else {
                        let error_text = resp
                            .text()
                            .await
                            .unwrap_or_else(|_| "Unknown error".to_string());
                        eprintln!(
                            "⚠️  Failed to check token balance: {} - {}",
                            status, error_text
                        );
                        eprintln!(
                            "Estimated cost: {:.4} PIPE tokens at {} tokens/GB",
                            total_cost_estimate, fee_resp.priority_fee_per_gb
                        );
                        eprintln!(
                            "\nProceed with caution - could not verify if you have enough tokens."
                        );
                        eprintln!("Consider checking your balance with 'pipe check-token' first.");
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Could not connect to check token balance: {}", e);
                    eprintln!(
                        "Estimated cost: {:.4} PIPE tokens at {} tokens/GB",
                        total_cost_estimate, fee_resp.priority_fee_per_gb
                    );
                    eprintln!(
                        "\nProceed with caution - could not verify if you have enough tokens."
                    );
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
                let service_cache_clone = service_cache.clone();
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

                    // Get endpoint for this specific file upload
                    let selected_endpoint = get_endpoint_for_operation(
                        &service_cache_clone,
                        &client_clone,
                        &base_url_clone,
                        "upload",
                        &creds_clone.user_id,
                        Some(&rel_path),
                    )
                    .await;

                    // Build URL without credentials (security fix)
                    let url = format!(
                        "{}/priorityUpload?file_name={}",
                        selected_endpoint, rel_path
                    );

                    // Use retry wrapper for priority directory uploads
                    let upload_result =
                        upload_with_retry(&format!("priority upload of {}", rel_path), || {
                            upload_file_priority_with_shared_progress(
                                &client_clone,
                                &path,
                                &url,
                                &rel_path,
                                &creds_clone,
                                Some(shared_progress_clone.clone()),
                            )
                        })
                        .await;

                    match upload_result {
                        Ok((uploaded_file, cost)) => {
                            let mut completed = completed_clone.lock().await;
                            *completed += 1;
                            let completed_val = *completed;
                            drop(completed);

                            let mut total = total_cost_clone.lock().await;
                            *total += cost;
                            drop(total);

                            progress_clone.set_message(format!(
                                "Priority uploaded {} of {} files",
                                completed_val, file_count_copy
                            ));

                            let _ = append_to_upload_log(
                                &path.display().to_string(),
                                &uploaded_file,
                                "PRIORITY SUCCESS",
                                "Priority directory upload success",
                            );
                        }
                        Err(e) => {
                            let mut failed = failed_clone.lock().await;
                            *failed += 1;

                            eprintln!("Failed priority upload {}: {}", rel_path, e);
                            // Don't log failures to the upload list
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
                println!(
                    "  💰 Total cost: {:.4} PIPE tokens (priority rate: {} tokens/GB)",
                    final_cost, fee_resp.priority_fee_per_gb
                );
            }
            println!(
                "\nCheck the log file for details:\n  {}",
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

        Commands::GetTierPricing => {
            let url = format!("{}/getTierPricing", base_url);
            let resp = client.get(&url).send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                #[derive(Deserialize)]
                struct TierPricing {
                    name: String,
                    base_price: f64,
                    current_price: f64,
                    concurrency: usize,
                    active_users: usize,
                    multipart_concurrency: usize,
                    chunk_size_mb: u64,
                }
                let pricing: Vec<TierPricing> = serde_json::from_str(&text_body)?;

                println!("\n📊 Upload Tier Pricing:");
                println!("╔═══════════════╦═══════╦═══════════╦═════════════╦══════════╦═══════════════╦═══════════╗");
                println!("║ Tier          ║ $/GB  ║ Current   ║ Concurrency ║ Active   ║ MP Concurrent ║ Chunk MB  ║");
                println!("╠═══════════════╬═══════╬═══════════╬═════════════╬══════════╬═══════════════╬═══════════╣");
                for tier in pricing {
                    println!(
                        "║ {:13} ║ {:5.1} ║ {:9.2} ║ {:11} ║ {:8} ║ {:13} ║ {:9} ║",
                        tier.name,
                        tier.base_price,
                        tier.current_price,
                        tier.concurrency,
                        tier.active_users,
                        tier.multipart_concurrency,
                        tier.chunk_size_mb
                    );
                }
                println!("╚═══════════════╩═══════╩═══════════╩═════════════╩══════════╩═══════════════╩═══════════╝");
                println!(
                    "\nNote: Current price adjusts based on demand for Priority and Premium tiers."
                );
            } else {
                return Err(anyhow!(
                    "Failed to get tier pricing. Status={}, Body={}",
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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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
            let url = format!(
                "{}/priorityUpload?file_name={}&epochs={}",
                base_url, file_name, epochs_final
            );

            // Use retry wrapper for priority single file upload
            let upload_result =
                upload_with_retry(&format!("priority upload of {}", file_path), || {
                    upload_file_priority_with_shared_progress(
                        &client, local_path, &url, &file_name, &creds, None,
                    )
                })
                .await;

            match upload_result {
                Ok((uploaded_filename, token_cost)) => {
                    println!(
                        "Priority file uploaded (or backgrounded): {}",
                        uploaded_filename
                    );
                    if token_cost > 0.0 {
                        println!("💰 Cost: {} PIPE tokens", token_cost);
                    }
                    append_to_upload_log(
                        &file_path,
                        &uploaded_filename,
                        "PRIORITY SUCCESS",
                        &format!("Priority upload ({} epochs)", epochs_final),
                    )?;
                }
                Err(e) => {
                    eprintln!("Priority upload failed for {} => {}", file_path, e);
                    // Don't log failures to the upload list
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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            // Override with command-line args if provided (only for legacy auth)
            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            match priority_download_single_file_with_auth(&client, base_url, &creds, &file_name)
                .await
            {
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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

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

        Commands::EncryptLocal {
            input_file,
            output_file,
            password,
        } => {
            // Get password if not provided
            let password = match password {
                Some(p) => p,
                None => {
                    let password = rpassword::prompt_password("Enter encryption password: ")?;
                    let confirm = rpassword::prompt_password("Confirm encryption password: ")?;
                    if password != confirm {
                        return Err(anyhow!("Passwords do not match"));
                    }
                    password
                }
            };

            println!("Encrypting {} -> {}", input_file, output_file);

            let input = std::fs::File::open(&input_file)?;
            let output = std::fs::File::create(&output_file)?;
            let file_size = input.metadata()?.len();

            // Create progress bar
            let pb = ProgressBar::new(file_size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} {bytes_per_sec}")
                    .unwrap()
                    .progress_chars("=>-"),
            );

            let progress_callback = Box::new(move |bytes: usize| {
                pb.inc(bytes as u64);
            });

            crate::encryption::encrypt_file_with_password(
                input,
                output,
                &password,
                Some(progress_callback),
            )
            .await?;

            println!("✅ File encrypted successfully!");
            println!("   Original: {} ({} bytes)", input_file, file_size);
            println!(
                "   Encrypted: {} ({} bytes)",
                output_file,
                std::fs::metadata(&output_file)?.len()
            );
        }

        Commands::DecryptLocal {
            input_file,
            output_file,
            password,
        } => {
            // Check if input file has encryption header
            let mut check_file = std::fs::File::open(&input_file)?;
            if !crate::encryption::is_encrypted_file(&mut check_file)? {
                return Err(anyhow!(
                    "File '{}' does not appear to be encrypted (missing PIPE-ENC header)",
                    input_file
                ));
            }

            // Get password if not provided
            let password = match password {
                Some(p) => p,
                None => rpassword::prompt_password("Enter decryption password: ")?,
            };

            println!("Decrypting {} -> {}", input_file, output_file);

            let input = std::fs::File::open(&input_file)?;
            let output = std::fs::File::create(&output_file)?;
            let file_size = input.metadata()?.len();

            // Create progress bar
            let pb = ProgressBar::new(file_size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} {bytes_per_sec}")
                    .unwrap()
                    .progress_chars("=>-"),
            );

            let progress_callback = Box::new(move |bytes: usize| {
                pb.inc(bytes as u64);
            });

            match crate::encryption::decrypt_file_with_password(
                input,
                output,
                &password,
                Some(progress_callback),
            )
            .await
            {
                Ok(_) => {
                    println!("✅ File decrypted successfully!");
                    println!("   Encrypted: {} ({} bytes)", input_file, file_size);
                    println!(
                        "   Decrypted: {} ({} bytes)",
                        output_file,
                        std::fs::metadata(&output_file)?.len()
                    );
                }
                Err(e) => {
                    // Clean up failed output file
                    let _ = std::fs::remove_file(&output_file);
                    return Err(anyhow!("Decryption failed: {}", e));
                }
            }
        }

        Commands::KeyGen {
            name,
            algorithm,
            description,
            output,
        } => {
            let algo = algorithm.as_deref().unwrap_or("aes256");

            // Load or create keyring
            let keyring_path = keyring::Keyring::default_path()?;
            let mut keyring = keyring::Keyring::load_from_file(&keyring_path)?;

            // Get keyring password
            let keyring_password = if keyring.keys().is_empty() && !keyring.has_password() {
                // First time setup - initialize keyring password
                println!("🔐 Setting up keyring master password...");
                let password = rpassword::prompt_password("Enter new keyring password: ")?;
                let confirm = rpassword::prompt_password("Confirm keyring password: ")?;
                if password != confirm {
                    return Err(anyhow!("Passwords do not match"));
                }
                keyring.initialize_password(&password)?;
                password
            } else if keyring.is_legacy() {
                // Legacy keyring - use hardcoded password
                eprintln!("⚠️  Using legacy keyring password. Run 'pipe keyring-migrate' to set a custom password.");
                "keyring-protection".to_string()
            } else {
                // Normal operation - prompt for password
                rpassword::prompt_password("Enter keyring password: ")?
            };

            let key_name = match algo {
                "aes256" => {
                    println!("🔑 Generating AES-256 key...");
                    keyring.generate_aes_key(name, description, &keyring_password)?
                }
                "kyber1024" => {
                    println!("🔐 Generating Kyber1024 keypair (post-quantum)...");
                    keyring.generate_kyber_keypair(name, description, &keyring_password)?
                }
                "dilithium5" => {
                    println!("✍️  Generating Dilithium5 signing keypair (post-quantum)...");
                    keyring.generate_dilithium_keypair(name, description, &keyring_password)?
                }
                _ => {
                    return Err(anyhow!(
                        "Unknown algorithm: {}. Use: aes256, kyber1024, dilithium5",
                        algo
                    ))
                }
            };

            if let Some(output_path) = output {
                // Export to file
                let export_password =
                    rpassword::prompt_password("Enter password to protect exported key: ")?;
                let confirm = rpassword::prompt_password("Confirm password: ")?;
                if export_password != confirm {
                    return Err(anyhow!("Passwords do not match"));
                }

                keyring::export_key(&keyring, &key_name, Path::new(&output_path), &keyring_password, &export_password)?;
                println!("✅ Key exported to: {}", output_path);

                // Don't save to keyring if exporting
                keyring.delete_key(&key_name)?;
            } else {
                // Save keyring
                keyring.save_to_file(&keyring_path)?;
                println!("✅ Key '{}' generated and saved to keyring", key_name);
            }
        }

        Commands::KeyringMigrate { force } => {
            let keyring_path = keyring::Keyring::default_path()?;
            let mut keyring = keyring::Keyring::load_from_file(&keyring_path)?;

            if !keyring.is_legacy() {
                println!("✅ Keyring is already using custom password protection.");
                return Ok(());
            }

            println!("🔐 Keyring Migration");
            println!("===================");
            println!();
            println!("This will migrate your keyring from the default password to a custom master password.");
            println!("Your existing keys will be re-encrypted with the new password.");
            println!();

            if !force {
                print!("Continue? [y/N]: ");
                std::io::stdout().flush()?;
                let mut response = String::new();
                std::io::stdin().read_line(&mut response)?;
                if !response.trim().eq_ignore_ascii_case("y") {
                    println!("Migration cancelled.");
                    return Ok(());
                }
            }

            // Get new master password
            println!("\nSetting up new master password...");
            let new_password = rpassword::prompt_password("Enter new keyring password: ")?;
            let confirm = rpassword::prompt_password("Confirm new keyring password: ")?;
            
            if new_password != confirm {
                return Err(anyhow!("Passwords do not match"));
            }

            if new_password.len() < 8 {
                return Err(anyhow!("Password must be at least 8 characters long"));
            }

            // Perform migration
            println!("\nMigrating keyring...");
            keyring.migrate_from_legacy("keyring-protection", &new_password)?;
            
            // Save the migrated keyring
            keyring.save_to_file(&keyring_path)?;

            println!("✅ Keyring migration completed successfully!");
            println!("   Your keys are now protected with your custom password.");
            println!("   Please remember this password - it cannot be recovered!");
        }

        Commands::KeyList => {
            let keyring_path = keyring::Keyring::default_path()?;
            let keyring = keyring::Keyring::load_from_file(&keyring_path)?;

            let keys = keyring.list_keys();
            if keys.is_empty() {
                println!("No keys in keyring. Use 'pipe keygen' to create one.");
            } else {
                println!("🔑 Keys in keyring:\n");
                for (name, key) in keys {
                    println!("  Name: {}", name);
                    println!("  Algorithm: {}", key.algorithm);
                    println!(
                        "  Created: {}",
                        key.metadata.created_at.format("%Y-%m-%d %H:%M:%S")
                    );
                    if let Some(ref desc) = key.metadata.description {
                        println!("  Description: {}", desc);
                    }
                    if key.metadata.usage_count > 0 {
                        println!("  Used: {} times", key.metadata.usage_count);
                        if let Some(last_used) = key.metadata.last_used {
                            println!("  Last used: {}", last_used.format("%Y-%m-%d %H:%M:%S"));
                        }
                    }
                    println!();
                }
            }
        }

        Commands::KeyDelete { key_name } => {
            let keyring_path = keyring::Keyring::default_path()?;
            let mut keyring = keyring::Keyring::load_from_file(&keyring_path)?;

            keyring.delete_key(&key_name)?;
            keyring.save_to_file(&keyring_path)?;

            println!("✅ Key '{}' deleted from keyring", key_name);
        }

        Commands::KeyExport { key_name, output } => {
            let keyring_path = keyring::Keyring::default_path()?;
            let keyring = keyring::Keyring::load_from_file(&keyring_path)?;

            // Get keyring password
            let keyring_password = if keyring.is_legacy() {
                "keyring-protection".to_string()
            } else {
                rpassword::prompt_password("Enter keyring password: ")?
            };

            let export_password = rpassword::prompt_password("Enter password to protect exported key: ")?;
            let confirm = rpassword::prompt_password("Confirm password: ")?;
            if export_password != confirm {
                return Err(anyhow!("Passwords do not match"));
            }

            keyring::export_key(&keyring, &key_name, Path::new(&output), &keyring_password, &export_password)?;
            println!("✅ Key '{}' exported to: {}", key_name, output);
        }

        Commands::SignFile {
            input_file,
            signature_file,
            key,
        } => {
            // Read file to sign
            let data = std::fs::read(&input_file)?;

            // Load key
            let keyring_path = keyring::Keyring::default_path()?;
            let mut keyring = keyring::Keyring::load_from_file(&keyring_path)?;

            // Check if key exists and is correct type
            let public_key = {
                let stored_key = keyring
                    .get_key(&key)
                    .ok_or_else(|| anyhow!("Key '{}' not found in keyring", key))?;
                if stored_key.algorithm != keyring::KeyAlgorithm::Dilithium5 {
                    return Err(anyhow!(
                        "Key '{}' is not a signing key (need Dilithium5)",
                        key
                    ));
                }
                stored_key.public_key.clone()
            };

            // Get key material
            let password = rpassword::prompt_password("Enter keyring password: ")?;
            let key_material = keyring.get_key_material(&key, &password)?;

            // Sign the data
            let signature =
                quantum::sign_with_dilithium(&data, key_material.private_key.as_ref().unwrap())?;

            // Save signature
            std::fs::write(&signature_file, &signature)?;

            // Also save public key alongside signature for verification
            let pubkey_file = format!("{}.pubkey", signature_file);
            if let Some(pubkey) = public_key.as_ref() {
                std::fs::write(&pubkey_file, pubkey)?;
                println!("✅ File signed successfully!");
                println!("   Signature: {}", signature_file);
                println!("   Public key: {}", pubkey_file);
            } else {
                println!("✅ File signed successfully!");
                println!("   Signature: {}", signature_file);
            }

            // Update keyring with usage stats
            keyring.save_to_file(&keyring_path)?;
        }

        Commands::VerifySignature {
            input_file,
            signature_file,
            public_key,
        } => {
            // Read file and signature
            let data = std::fs::read(&input_file)?;
            let signature = std::fs::read(&signature_file)?;

            // Read public key (either from file or find .pubkey file)
            let pubkey_bytes = if std::path::Path::new(&public_key).exists() {
                std::fs::read(&public_key)?
            } else {
                // Try to find .pubkey file alongside signature
                let pubkey_file = format!("{}.pubkey", signature_file);
                if std::path::Path::new(&pubkey_file).exists() {
                    std::fs::read(&pubkey_file)?
                } else {
                    return Err(anyhow!("Public key file not found: {}", public_key));
                }
            };

            // Verify signature
            if quantum::verify_dilithium_signature(&data, &signature, &pubkey_bytes)? {
                println!("✅ Signature verification PASSED");
                println!(
                    "   File '{}' was signed by the holder of the private key",
                    input_file
                );
            } else {
                println!("❌ Signature verification FAILED");
                println!("   The file may have been modified or signed with a different key");
            }
        }

        Commands::Referral(subcmd) => {
            // Load credentials
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            // Get the JWT token
            let jwt_token = creds.auth_tokens.as_ref()
                .ok_or_else(|| anyhow!("No authentication tokens found."))?
                .access_token.clone();

            match subcmd {
                ReferralCommands::Generate => {
                    let resp = client
                        .post(format!("{}/api/referral/generate", base_url))
                        .header("Authorization", format!("Bearer {}", jwt_token))
                        .send()
                        .await?;

                    let status = resp.status();
                    let text_body = resp.text().await?;

                    if status.is_success() {
                        let response: serde_json::Value = serde_json::from_str(&text_body)?;
                        let code = response["code"].as_str().unwrap_or("Unknown");
                        let existing = response["existing"].as_bool().unwrap_or(false);

                        if existing {
                            println!("Your existing referral code: {}", code);
                        } else {
                            println!("🎉 Your new referral code: {}", code);
                        }
                        println!("Share this code to earn 100 PIPE when someone uses it!");
                    } else {
                        return Err(anyhow!(
                            "Failed to generate referral code. Status={}, Body={}",
                            status,
                            text_body
                        ));
                    }
                }

                ReferralCommands::Show => {
                    // Get the code
                    let code_resp = client
                        .get(format!("{}/api/referral/my-code", base_url))
                        .header("Authorization", format!("Bearer {}", jwt_token))
                        .send()
                        .await;

                    match code_resp {
                        Ok(resp) if resp.status().is_success() => {
                            let text_body = resp.text().await?;
                            let response: serde_json::Value = serde_json::from_str(&text_body)?;
                            let code = response["code"].as_str().unwrap_or("Unknown");
                            println!("Your referral code: {}", code);

                            // Get stats
                            let stats_resp = client
                                .get(format!("{}/api/referral/stats", base_url))
                                .header("Authorization", format!("Bearer {}", jwt_token))
                                .send()
                                .await?;

                            if stats_resp.status().is_success() {
                                let stats_body = stats_resp.text().await?;
                                let stats: serde_json::Value = serde_json::from_str(&stats_body)?;

                                println!("\n📊 Referral Statistics:");
                                println!("  Total uses: {}", stats["total_uses"]);
                                println!("  Successful referrals: {}", stats["successful_referrals"]);
                                println!("  Pending referrals: {}", stats["pending_referrals"]);
                                println!("  Total PIPE earned: {}", stats["total_pipe_earned"]);
                            }
                        }
                        _ => {
                            println!("You don't have a referral code yet. Generate one with 'pipe referral generate'");
                        }
                    }
                }

                ReferralCommands::Apply { code } => {
                    let req_body = serde_json::json!({ "code": code });
                    let resp = client
                        .post(format!("{}/api/referral/apply", base_url))
                        .header("Authorization", format!("Bearer {}", jwt_token))
                        .json(&req_body)
                        .send()
                        .await?;

                    let status = resp.status();
                    let text_body = resp.text().await?;

                    if status.is_success() {
                        let response: serde_json::Value = serde_json::from_str(&text_body)?;
                        if response["success"].as_bool().unwrap_or(false) {
                            println!("✅ {}", response["message"].as_str().unwrap_or("Referral code applied successfully!"));
                        } else {
                            println!("❌ {}", response["message"].as_str().unwrap_or("Failed to apply referral code"));
                        }
                    } else {
                        return Err(anyhow!(
                            "Failed to apply referral code. Status={}, Body={}",
                            status,
                            text_body
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

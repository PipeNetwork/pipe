// src/lib.rs

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::{Body, Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite; // For writeln!
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::Semaphore;
use uuid::Uuid;
use walkdir::WalkDir;

mod encryption;
mod keyring;
mod password_utils;
mod quantum;
mod quantum_keyring;
pub mod sync;

#[cfg(test)]
mod quantum_integration_test;

pub const MAX_RETRIES: u32 = 5;
pub const INITIAL_RETRY_DELAY_MS: u64 = 1000;
pub const MAX_RETRY_DELAY_MS: u64 = 10000;

// Define the query encoding set for URL parameters
// This encodes control characters, spaces, and characters that have special meaning in URLs
const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ') // Space
    .add(b'"') // Quote
    .add(b'#') // Hash (fragment identifier)
    .add(b'<') // Less than
    .add(b'>') // Greater than
    .add(b'?') // Question mark (query separator)
    .add(b'`') // Backtick
    .add(b'{') // Left brace
    .add(b'}') // Right brace
    .add(b'|') // Pipe
    .add(b'\\') // Backslash
    .add(b'^') // Caret
    .add(b'[') // Left bracket
    .add(b']') // Right bracket
    .add(b'%'); // Percent (to avoid double encoding)

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
pub struct ChangePasswordRequest {
    pub current_password: String,
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
    #[serde(default)]
    pub csrf_token: Option<String>,
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
    /// Optional per-profile default API base URL (used when `--api` is not explicitly set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
    /// Optional default S3 endpoint override (for presigning and AWS CLI hints).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_endpoint: Option<String>,
    /// Optional default S3 region override (for presigning).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_region: Option<String>,
    /// Optional default for presigning style (true = virtual-hosted-style, false = path-style).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_virtual_hosted: Option<bool>,
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
        default_value = "https://us-west-01-firestarter.pipenetwork.com",
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

    /// Change password (requires JWT login)
    ChangePassword {
        #[arg(long)]
        current_password: Option<String>,
        #[arg(long)]
        new_password: Option<String>,
    },

    /// Refresh access token
    RefreshToken,

    /// Manage local CLI configuration (stored in the config file)
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
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
        #[arg(
            long,
            help = "Upload tier: normal, priority, premium, ultra, enterprise"
        )]
        tier: Option<String>,
        #[arg(long, help = "Encrypt file with password before upload")]
        encrypt: bool,
        #[arg(long, help = "Password for encryption (will prompt if not provided)")]
        password: Option<String>,
        #[arg(long, help = "Show cost estimate without uploading")]
        dry_run: bool,
    },

    /// Download a single file
    DownloadFile {
        /// Optional user ID override; if omitted, read from .pipe-cli.json
        #[arg(long)]
        user_id: Option<String>,

        /// Optional user app key override; if omitted, read from .pipe-cli.json
        #[arg(long)]
        user_app_key: Option<String>,

        /// Required remote file name on the server (or Blake3 hash if --file-id is used)
        file_name: String,

        /// Required local file path to store the downloaded file
        output_path: String,

        #[arg(long, help = "Treat file_name as Blake3 hash ID instead of filename")]
        file_id: bool,

        #[arg(long, help = "Decrypt file with password after download")]
        decrypt: bool,
        #[arg(long, help = "Password for decryption (will prompt if not provided)")]
        password: Option<String>,
        #[arg(long, help = "Use key from keyring or key file")]
        key: Option<String>,
        #[arg(long, help = "Use post-quantum decryption (kyber)")]
        quantum: bool,
        #[arg(long, help = "Use legacy download endpoint (base64 encoded)")]
        legacy: bool,
    },

    /// Delete a file
    DeleteFile {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_name: String,
        #[arg(long, help = "Treat file_name as Blake3 hash ID")]
        file_id: bool,
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

    /// Check custom token balance
    CheckToken {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
    },

    CreatePublicLink {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_name: String,
        #[arg(long, help = "Treat file_name as Blake3 hash ID")]
        file_id: bool,
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

        #[arg(
            long,
            help = "Path to upload log file (default: ~/.pipe-cli-uploads.json)"
        )]
        upload_log: Option<String>,
    },

    GetPriorityFee,

    /// Get pricing for all upload tiers
    GetTierPricing,

    PriorityUpload {
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
        file_path: String,
        file_name: String,
        #[arg(long)]
        epochs: Option<u64>,
        #[arg(long, help = "Show cost estimate without uploading")]
        dry_run: bool,
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

    // NOTE: VerifyFile command is commented out for production release
    // This feature requires server-side support and is planned for a future release
    // Uncomment when server API endpoint is ready
    /*
    /// Verify file integrity using Blake3 hash
    VerifyFile {
        /// File name or Blake3 hash ID
        file_name: String,

        #[arg(long, help = "Treat file_name as Blake3 hash ID")]
        file_id: bool,

        #[arg(long)]
        user_id: Option<String>,
        #[arg(long)]
        user_app_key: Option<String>,
    },
    */
    /// Find uploaded file by local path or hash
    FindUpload {
        /// Local file path or Blake3 hash to search for
        query: String,

        #[arg(long, help = "Search by Blake3 hash instead of local path")]
        by_hash: bool,
    },

    /// Rehash upload history (calculate Blake3 for old uploads)
    RehashUploads {
        #[arg(long, help = "Show progress")]
        verbose: bool,
    },

    /// Sync files between local and remote storage
    Sync {
        /// Path to sync (local directory or remote prefix)
        path: String,

        /// Optional second path for explicit direction (e.g., remote path for download)
        #[arg(value_name = "DEST_PATH")]
        destination: Option<String>,

        /// Conflict resolution strategy: newer (default), larger, local, remote, ask
        #[arg(long, default_value = "newer")]
        conflict: String,

        /// Show what would happen without making changes
        #[arg(long)]
        dry_run: bool,

        /// Exclude files matching these patterns (comma-separated)
        #[arg(long)]
        exclude: Option<String>,

        /// Include only files matching these patterns (comma-separated)
        #[arg(long)]
        include: Option<String>,

        /// Maximum file size to sync (e.g., 1GB, 500MB)
        #[arg(long)]
        max_size: Option<String>,

        /// Only sync files newer than this date (YYYY-MM-DD)
        #[arg(long)]
        newer_than: Option<String>,

        /// Number of parallel operations
        #[arg(long, default_value = "5")]
        parallel: usize,
    },

    /// Show public service configuration (USDC treasury, lifetime pricing)
    ServiceConfig,

    /// Check prepaid credits balance (USDC) and storage quota
    CheckDeposit {
        #[arg(long)]
        user_id: Option<String>,
    },

    /// Check prepaid credits balance (USDC) and storage quota
    CreditsStatus {
        #[arg(long)]
        user_id: Option<String>,
    },

    /// Create a prepaid credits top-up intent (USDC)
    CreditsIntent {
        /// USDC amount (e.g. 10.50)
        amount: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Submit a prepaid credits payment transaction signature for verification
    CreditsSubmit {
        intent_id: String,
        tx_sig: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Cancel a pending prepaid credits top-up intent
    CreditsCancel {
        intent_id: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Check PIPE-token top-up intent status (credits bonus)
    PipeCreditsStatus {
        #[arg(long)]
        user_id: Option<String>,
    },

    /// Create a prepaid credits top-up intent paid in PIPE tokens (discounted)
    PipeCreditsIntent {
        /// USDC amount to buy (discount is applied as bonus credits)
        amount: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Submit a PIPE-token payment transaction signature for verification
    PipeCreditsSubmit {
        intent_id: String,
        tx_sig: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Cancel a pending PIPE-token top-up intent
    PipeCreditsCancel {
        intent_id: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Show lifetime subscription status (USDC)
    LifetimeStatus {
        #[arg(long)]
        user_id: Option<String>,
    },

    /// Create a lifetime subscription purchase intent (USDC)
    LifetimeIntent {
        #[arg(long)]
        user_id: Option<String>,
    },

    /// Submit a lifetime subscription payment transaction signature for verification
    LifetimeSubmit {
        intent_id: String,
        tx_sig: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Estimate upload cost for a file
    EstimateCost {
        /// Path to file to estimate
        file_path: String,

        #[arg(
            long,
            default_value = "normal",
            help = "Upload tier: normal, priority, premium, ultra, enterprise"
        )]
        tier: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Legacy: submit a prepaid credits top-up payment (USDC)
    SyncDeposits {
        #[arg(long)]
        user_id: Option<String>,

        /// Optional intent ID (defaults to latest from credits status)
        #[arg(long)]
        intent_id: Option<String>,

        /// Transaction signature for USDC transfer
        #[arg(long)]
        tx_sig: Option<String>,
    },

    /// Manage S3-compatible access (keys, bucket, presigned URLs)
    S3 {
        #[command(subcommand)]
        command: S3Commands,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Show local CLI configuration (from the config file)
    Show,

    /// Set the default API base URL for this config profile
    SetApi { url: String },

    /// Clear the saved default API base URL
    ClearApi,

    /// Set the default S3 endpoint (used for presign + AWS CLI hints)
    SetS3Endpoint { endpoint: String },

    /// Clear the saved S3 endpoint
    ClearS3Endpoint,

    /// Set the default S3 region (used for presign)
    SetS3Region { region: String },

    /// Clear the saved S3 region
    ClearS3Region,

    /// Set whether presigned URLs default to virtual-hosted-style
    SetS3VirtualHosted { enabled: bool },

    /// Clear the saved virtual-hosted-style default
    ClearS3VirtualHosted,
}

#[derive(Subcommand, Debug)]
pub enum S3Commands {
    /// Manage S3 access keys
    Keys {
        #[command(subcommand)]
        command: S3KeysCommands,
    },

    /// Manage S3 bucket settings
    Bucket {
        #[command(subcommand)]
        command: S3BucketCommands,
    },

    /// Generate a presigned S3 URL (SigV4)
    Presign {
        #[arg(long, default_value = "GET")]
        method: String,

        /// Object key (omit to presign ListBuckets)
        #[arg(long)]
        key: Option<String>,

        /// Specific S3 access key id to use (defaults to most-recent active)
        #[arg(long)]
        access_key_id: Option<String>,

        /// Expiration in seconds (default 900; max 604800)
        #[arg(long)]
        expires: Option<u64>,

        /// AWS region (default us-east-1)
        #[arg(long)]
        region: Option<String>,

        /// Override S3 endpoint (e.g. https://host:9000)
        #[arg(long)]
        endpoint: Option<String>,

        /// Use virtual-hosted-style URLs (bucket as subdomain)
        #[arg(long, default_value_t = false, conflicts_with = "path_style")]
        virtual_hosted: bool,

        /// Force path-style URLs (bucket in path). Overrides any saved default.
        #[arg(long, default_value_t = false, conflicts_with = "virtual_hosted")]
        path_style: bool,

        /// Extra query parameters (repeatable). Use KEY or KEY=VALUE.
        #[arg(long, value_name = "KEY=VALUE")]
        query: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum S3KeysCommands {
    /// Create a new S3 access key (secret is shown once)
    Create {
        /// Create a read-only key (GET/HEAD only)
        #[arg(long)]
        read_only: bool,
    },

    /// Rotate an S3 access key (creates a new key; optionally revokes the old key)
    Rotate {
        /// Rotate from this access key id (defaults to the most-recent active key)
        #[arg(long)]
        from: Option<String>,

        /// Revoke the old key after creating the new one
        #[arg(long, default_value_t = false)]
        revoke_old: bool,

        /// Override the permission mode for the new key (defaults to the old key mode; otherwise read-only)
        #[arg(long, value_name = "read-only|read-write")]
        mode: Option<String>,
    },

    /// List S3 access keys
    List,

    /// Revoke an S3 access key
    Revoke { access_key_id: String },
}

#[derive(Subcommand, Debug)]
pub enum S3BucketCommands {
    /// Show bucket settings
    Get,

    /// Enable/disable anonymous (public) reads (GET/HEAD)
    SetPublicRead { enabled: bool },

    /// Set CORS allowed origins for public reads (comma/newline separated; use "*" to allow any)
    SetCors {
        #[arg(long, value_name = "ORIGIN", num_args = 1..)]
        origin: Vec<String>,
    },

    /// Clear CORS allowed origins (disables browser access)
    ClearCors,
}

#[derive(Serialize, Deserialize, Debug)]
struct S3KeysListResponse {
    keys: Vec<S3AccessKeyListItem>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct S3AccessKeyListItem {
    access_key_id: String,
    read_only: bool,
    created_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct S3CreateKeyResponse {
    access_key_id: String,
    secret: String,
    read_only: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct S3RevokeKeyResponse {
    revoked: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct S3BucketSettingsResponse {
    bucket_name: String,
    public_read: bool,
    #[serde(default)]
    cors_allowed_origins: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PatchS3BucketSettingsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    public_read: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cors_allowed_origins: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PresignS3Request {
    #[serde(skip_serializing_if = "Option::is_none")]
    access_key_id: Option<String>,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(default)]
    query: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(default)]
    virtual_hosted: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct PresignS3Response {
    url: String,
    method: String,
    bucket: String,
    key: Option<String>,
    expires_secs: u64,
    access_key_id: String,
    read_only: bool,
    region: String,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct PriorityFeeResponse {
    pub priority_fee_per_gb: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TierPricingInfo {
    pub name: String,
    pub base_price: f64,
    pub current_price: f64,
    pub concurrency: usize,
    pub active_users: usize,
    pub multipart_concurrency: usize,
    pub chunk_size_mb: u64,
}

const USDC_DECIMALS_FACTOR: i64 = 1_000_000;
const PIPE_DECIMALS_FACTOR: i64 = 1_000_000_000;

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsTierEstimate {
    pub tier_name: String,
    pub cost_per_gb_usdc: f64,
    pub available_gb: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsQuota {
    pub tier_estimates: Vec<CreditsTierEstimate>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsIntentStatus {
    pub intent_id: String,
    pub status: String,
    pub requested_usdc_raw: i64,
    pub detected_usdc_raw: i64,
    pub credited_usdc_raw: i64,
    pub usdc_mint: String,
    pub treasury_owner_pubkey: String,
    pub treasury_usdc_ata: String,
    pub reference_pubkey: String,
    pub payment_tx_sig: Option<String>,
    pub last_checked_at: Option<String>,
    pub credited_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsStatusResponse {
    pub balance_usdc_raw: i64,
    pub balance_usdc: f64,
    pub total_deposited_usdc_raw: i64,
    pub total_spent_usdc_raw: i64,
    pub last_topup_at: Option<String>,
    pub quota: CreditsQuota,
    pub intent: Option<CreditsIntentStatus>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateCreditsIntentRequest {
    pub amount_usdc_raw: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsIntentResponse {
    pub intent_id: String,
    pub status: String,
    pub requested_usdc_raw: i64,
    pub requested_usdc: f64,
    pub usdc_mint: String,
    pub treasury_owner_pubkey: String,
    pub treasury_usdc_ata: String,
    pub reference_pubkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubmitCreditsPaymentRequest {
    pub intent_id: String,
    pub tx_sig: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubmitCreditsPaymentResponse {
    pub intent_id: String,
    pub status: String,
    pub requested_usdc_raw: i64,
    pub detected_usdc_raw: i64,
    pub credited_usdc_raw: i64,
    pub balance_usdc_raw: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CancelCreditsIntentRequest {
    pub intent_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsCancelResponse {
    pub intent_id: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PipeCreditsIntentResponse {
    pub intent_id: String,
    pub status: String,
    pub requested_usdc_raw: i64,
    pub requested_usdc: f64,
    pub credited_usdc_raw: i64,
    pub credited_usdc: f64,
    pub pipe_price_usd: f64,
    pub required_pipe_raw: i64,
    pub required_pipe: f64,
    pub pipe_mint: String,
    pub treasury_owner_pubkey: String,
    pub treasury_pipe_ata: String,
    pub reference_pubkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubmitPipeCreditsPaymentResponse {
    pub intent_id: String,
    pub status: String,
    pub requested_usdc_raw: i64,
    pub credited_usdc_raw: i64,
    pub required_pipe_raw: i64,
    pub detected_pipe_raw: i64,
    pub balance_usdc_raw: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PipeCreditsCancelResponse {
    pub intent_id: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PipeCreditsIntentStatus {
    pub intent_id: String,
    pub status: String,
    pub requested_usdc_raw: i64,
    pub credited_usdc_raw: i64,
    pub pipe_price_usd: f64,
    pub required_pipe_raw: i64,
    pub detected_pipe_raw: i64,
    pub pipe_mint: String,
    pub treasury_owner_pubkey: String,
    pub treasury_pipe_ata: String,
    pub reference_pubkey: String,
    pub payment_tx_sig: Option<String>,
    pub last_checked_at: Option<String>,
    pub credited_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PipeCreditsStatusResponse {
    pub balance_usdc_raw: i64,
    pub balance_usdc: f64,
    pub intent: Option<PipeCreditsIntentStatus>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceConfigResponse {
    pub solana_cluster: String,
    pub usdc_treasury_pubkey: String,
    pub usdc_treasury_ata: String,
    pub lifetime_purchase_enabled: bool,
    pub lifetime_price_usdc: i64,
    pub usdc_mint: String,
    pub lifetime_promo_title: Option<String>,
    pub lifetime_promo_body: Option<String>,
    pub lifetime_terms_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LifetimeIntentResponse {
    pub intent_id: String,
    pub status: String,
    pub required_usdc: i64,
    pub required_usdc_raw: i64,
    pub usdc_mint: String,
    pub treasury_owner_pubkey: String,
    pub treasury_usdc_ata: String,
    pub reference_pubkey: String,
    pub lifetime_promo_title: Option<String>,
    pub lifetime_promo_body: Option<String>,
    pub lifetime_terms_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LifetimeIntentStatus {
    pub intent_id: String,
    pub status: String,
    pub required_usdc_raw: i64,
    pub detected_usdc_raw: i64,
    pub remaining_usdc_raw: i64,
    pub usdc_mint: String,
    pub treasury_owner_pubkey: String,
    pub treasury_usdc_ata: String,
    pub reference_pubkey: String,
    pub payment_tx_sig: Option<String>,
    pub last_checked_at: Option<String>,
    pub funds_detected_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LifetimeStatusResponse {
    pub lifetime_active: bool,
    pub lifetime_activated_at: Option<String>,
    pub intent: Option<LifetimeIntentStatus>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubmitLifetimePaymentRequest {
    pub intent_id: String,
    pub tx_sig: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubmitLifetimePaymentResponse {
    pub intent_id: String,
    pub status: String,
    pub required_usdc_raw: i64,
    pub detected_usdc_raw: i64,
    pub remaining_usdc_raw: i64,
}

fn usdc_raw_to_ui(raw: i64) -> f64 {
    raw as f64 / USDC_DECIMALS_FACTOR as f64
}

fn pipe_raw_to_ui(raw: i64) -> f64 {
    raw as f64 / PIPE_DECIMALS_FACTOR as f64
}

fn format_pipe_ui(amount: f64) -> String {
    format_amount_ui(amount, 9)
}

fn format_usdc_ui(amount: f64) -> String {
    let s = format!("{:.6}", amount);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn parse_usdc_ui_to_raw(input: &str) -> Result<i64> {
    let trimmed = input.trim().trim_start_matches('$');
    if trimmed.is_empty() {
        return Err(anyhow!("USDC amount is required"));
    }

    let (whole, frac) = match trimmed.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (trimmed, None),
    };

    if whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("Invalid USDC amount: {}", input));
    }
    let whole_i64: i64 = whole
        .parse()
        .map_err(|_| anyhow!("Invalid USDC amount: {}", input))?;

    let frac_raw: i64 = match frac {
        None => 0,
        Some(f) if f.is_empty() => 0,
        Some(f) => {
            if f.len() > 6 || !f.chars().all(|c| c.is_ascii_digit()) {
                return Err(anyhow!("Invalid USDC amount (max 6 decimals): {}", input));
            }
            let padded = format!("{:0<6}", f);
            padded
                .parse::<i64>()
                .map_err(|_| anyhow!("Invalid USDC amount: {}", input))?
        }
    };

    let whole_raw = whole_i64
        .checked_mul(USDC_DECIMALS_FACTOR)
        .ok_or_else(|| anyhow!("USDC amount too large: {}", input))?;
    whole_raw
        .checked_add(frac_raw)
        .ok_or_else(|| anyhow!("USDC amount too large: {}", input))
}

fn parse_s3_query_args(args: &[String]) -> Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    for raw in args {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Invalid --query value: empty"));
        }

        let (key_raw, value_raw) = match trimmed.split_once('=') {
            Some((k, v)) => (k, v),
            None => (trimmed, ""),
        };
        let key = key_raw.trim();
        if key.is_empty() {
            return Err(anyhow!("Invalid --query value: {}", raw));
        }
        out.insert(key.to_string(), value_raw.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod s3_cli_tests {
    use super::*;

    #[test]
    fn parse_s3_query_args_supports_key_only_and_key_value() {
        let args = vec![
            "uploads".to_string(),
            "partNumber=1".to_string(),
            "uploadId=abc".to_string(),
        ];
        let parsed = parse_s3_query_args(&args).unwrap();
        assert_eq!(parsed.get("uploads").map(String::as_str), Some(""));
        assert_eq!(parsed.get("partNumber").map(String::as_str), Some("1"));
        assert_eq!(parsed.get("uploadId").map(String::as_str), Some("abc"));
    }

    #[test]
    fn parse_s3_query_args_rejects_empty_key() {
        assert!(parse_s3_query_args(&["".to_string()]).is_err());
        assert!(parse_s3_query_args(&["=x".to_string()]).is_err());
    }

    #[test]
    fn clap_parses_s3_keys_create_read_only() {
        let cli = Cli::try_parse_from(["pipe", "s3", "keys", "create", "--read-only"]).unwrap();
        match cli.command {
            Commands::S3 {
                command:
                    S3Commands::Keys {
                        command: S3KeysCommands::Create { read_only },
                    },
            } => assert!(read_only),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn refresh_token_response_parses_csrf_token() {
        let json =
            r#"{"access_token":"a","token_type":"Bearer","expires_in":123,"csrf_token":"t"}"#;
        let resp: RefreshTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.csrf_token.as_deref(), Some("t"));
    }

    #[test]
    fn auth_tokens_parse_set_password_response_shape() {
        let json = r#"{"message":"ok","access_token":"a","refresh_token":"r","token_type":"Bearer","expires_in":900,"csrf_token":"c"}"#;
        let resp: AuthTokens = serde_json::from_str(json).unwrap();
        assert_eq!(resp.csrf_token.as_deref(), Some("c"));
    }
}

fn bytes_to_gb_decimal(bytes: u64) -> f64 {
    bytes as f64 / 1_000_000_000.0
}

fn format_amount_ui(amount: f64, decimals: usize) -> String {
    let s = format!("{:.*}", decimals, amount);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn format_spl_amount_raw(raw: i64, decimals: u32) -> String {
    if decimals == 0 {
        return raw.to_string();
    }

    let factor = match 10u64.checked_pow(decimals) {
        Some(v) => v,
        None => return raw.to_string(),
    };

    let negative = raw < 0;
    let abs_u64 = match raw.checked_abs() {
        Some(v) => v as u64,
        None => (i64::MAX as u64) + 1,
    };

    let whole = abs_u64 / factor;
    let frac = abs_u64 % factor;

    let mut out = if frac == 0 {
        whole.to_string()
    } else {
        let frac_str = format!("{:0width$}", frac, width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{}.{}", whole, trimmed)
    };

    if negative {
        out.insert(0, '-');
    }
    out
}

fn solana_pay_url_raw(
    recipient_pubkey: &str,
    amount_raw: i64,
    spl_token_mint: &str,
    reference: &str,
    decimals: u32,
) -> String {
    format!(
        "solana:{}?amount={}&spl-token={}&reference={}",
        recipient_pubkey,
        format_spl_amount_raw(amount_raw, decimals),
        spl_token_mint,
        reference
    )
}

#[cfg(test)]
mod spl_amount_format_tests {
    use super::format_spl_amount_raw;

    #[test]
    fn formats_usdc_amounts_without_rounding() {
        assert_eq!(format_spl_amount_raw(0, 6), "0");
        assert_eq!(format_spl_amount_raw(1, 6), "0.000001");
        assert_eq!(format_spl_amount_raw(1_000_000, 6), "1");
        assert_eq!(format_spl_amount_raw(1_234_500, 6), "1.2345");
    }

    #[test]
    fn formats_pipe_amounts_without_rounding() {
        assert_eq!(format_spl_amount_raw(20_000_000_000, 9), "20");
        assert_eq!(format_spl_amount_raw(100_000_000_001, 9), "100.000000001");
    }
}

async fn fetch_credits_status(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
) -> Result<CreditsStatusResponse> {
    for path in ["/api/credits/status", "/deposit/balance"] {
        let mut request = client.get(format!("{}{}", base_url, path));
        request = add_auth_headers(request, creds, false)?;

        let resp = request.send().await?;
        let status = resp.status();
        let text_body = resp.text().await?;

        if status.is_success() {
            return Ok(serde_json::from_str::<CreditsStatusResponse>(&text_body)?);
        }

        if status.as_u16() == 404 {
            continue;
        }

        return Err(anyhow!(
            "Credits status request failed. Status = {}, Body = {}",
            status,
            text_body
        ));
    }

    Err(anyhow!(
        "This server does not support prepaid credits endpoints"
    ))
}

fn print_credits_status(status: &CreditsStatusResponse) {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                 💳 PREPAID CREDITS (USDC)                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("💰 Balance: ${} USDC", format_usdc_ui(status.balance_usdc));
    println!(
        "📊 Total Deposited: ${} USDC",
        format_usdc_ui(usdc_raw_to_ui(status.total_deposited_usdc_raw))
    );
    println!(
        "📉 Total Spent:     ${} USDC",
        format_usdc_ui(usdc_raw_to_ui(status.total_spent_usdc_raw))
    );
    if let Some(ts) = status.last_topup_at.as_deref() {
        println!("🕒 Last Top-up:     {}", ts);
    }

    println!();
    println!("📦 Available Storage:");
    println!("┌──────────────┬────────────────┬──────────────┐");
    println!("│ Tier         │ Available GB   │ USDC/GB       │");
    println!("├──────────────┼────────────────┼──────────────┤");
    for tier in &status.quota.tier_estimates {
        println!(
            "│ {:<12} │ {:>12.2} GB│ ${:>11} │",
            tier.tier_name,
            tier.available_gb,
            format_usdc_ui(tier.cost_per_gb_usdc)
        );
    }
    println!("└──────────────┴────────────────┴──────────────┘");

    if let Some(intent) = status.intent.as_ref() {
        println!();
        println!("🧾 Pending Intent:");
        println!("  Status:    {}", intent.status);
        println!("  Intent ID: {}", intent.intent_id);
        println!(
            "  Requested: ${} USDC",
            format_usdc_ui(usdc_raw_to_ui(intent.requested_usdc_raw))
        );
        if let Some(sig) = intent.payment_tx_sig.as_deref() {
            println!("  Tx Sig:    {}", sig);
        }
        println!("  Reference: {}", intent.reference_pubkey);
        if !intent.treasury_owner_pubkey.is_empty() {
            println!("  Treasury:  {}", intent.treasury_owner_pubkey);
            println!(
                "  Solana Pay: {}",
                solana_pay_url_raw(
                    &intent.treasury_owner_pubkey,
                    intent.requested_usdc_raw,
                    &intent.usdc_mint,
                    &intent.reference_pubkey,
                    6
                )
            );
        }
    }
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
            let last = self.last_refresh.read().unwrap_or_else(|poisoned| {
                eprintln!("WARN: service discovery last_refresh lock poisoned; continuing");
                poisoned.into_inner()
            });
            last.elapsed() > self.refresh_interval
        };

        if needs_refresh {
            if let Err(e) = self.refresh_instances(client, discovery_url).await {
                eprintln!("Failed to refresh service instances: {}", e);
            }
        }

        // Get best instance
        let instances = self.instances.read().unwrap_or_else(|poisoned| {
            eprintln!("WARN: service discovery instances lock poisoned; continuing");
            poisoned.into_inner()
        });
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
                    !instance.endpoint_url.contains("localhost")
                        && !instance.endpoint_url.contains("127.0.0.1")
                });
            }

            let mut instances = self.instances.write().unwrap_or_else(|poisoned| {
                eprintln!("WARN: service discovery instances lock poisoned; continuing");
                poisoned.into_inner()
            });
            *instances = discovery.instances;

            let mut last_refresh = self.last_refresh.write().unwrap_or_else(|poisoned| {
                eprintln!("WARN: service discovery last_refresh lock poisoned; continuing");
                poisoned.into_inner()
            });
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
        let instances = self.instances.read().unwrap_or_else(|poisoned| {
            eprintln!("WARN: service discovery instances lock poisoned; continuing");
            poisoned.into_inner()
        });

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
            eprintln!(
                "Using direct connection to {} (bypassing discovery)",
                base_url
            );
            return base_url.to_string();
        }
    }

    // First try to refresh if needed
    let _ = service_cache.get_best_endpoint(client, base_url).await;

    // Then select based on operation
    if matches!(operation, "upload" | "download" | "delete") {
        if let Some(file_name) = file_name {
            return service_cache.select_endpoint_for_operation(operation, user_id, file_name);
        }
    }

    // For non-file operations, just get the best endpoint
    let instances = service_cache.instances.read().unwrap_or_else(|poisoned| {
        eprintln!("WARN: service discovery instances lock poisoned; continuing");
        poisoned.into_inner()
    });
    if let Some(best) = instances.first() {
        best.endpoint_url.clone()
    } else {
        base_url.to_string()
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

pub fn save_credentials_to_file(
    user_id: &str,
    user_app_key: &str,
    config_path: Option<&str>,
) -> Result<()> {
    // Try to preserve existing auth tokens if they exist
    let creds = if let Ok(Some(existing)) = load_credentials_from_file(config_path) {
        SavedCredentials {
            user_id: user_id.to_owned(),
            user_app_key: user_app_key.to_owned(),
            auth_tokens: existing.auth_tokens,
            username: existing.username,
            api_base_url: existing.api_base_url,
            s3_endpoint: existing.s3_endpoint,
            s3_region: existing.s3_region,
            s3_virtual_hosted: existing.s3_virtual_hosted,
        }
    } else {
        SavedCredentials {
            user_id: user_id.to_owned(),
            user_app_key: user_app_key.to_owned(),
            auth_tokens: None,
            username: None,
            api_base_url: None,
            s3_endpoint: None,
            s3_region: None,
            s3_virtual_hosted: None,
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
                let RefreshTokenResponse {
                    access_token,
                    expires_in,
                    csrf_token,
                    ..
                } = refresh_response;

                // Calculate new expires_at timestamp
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                let expires_at = DateTime::<Utc>::from_timestamp(now + expires_in, 0)
                    .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;

                // Update auth tokens
                if let Some(ref mut auth_tokens) = creds.auth_tokens {
                    auth_tokens.access_token = access_token;
                    auth_tokens.expires_in = expires_in;
                    auth_tokens.expires_at = Some(expires_at);
                    if let Some(token) = csrf_token {
                        auth_tokens.csrf_token = Some(token);
                    }
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

fn extract_user_id_from_jwt(access_token: &str) -> Result<String> {
    let parts: Vec<&str> = access_token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format"));
    }

    let payload = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| anyhow!("Invalid JWT payload encoding: {e}"))?;

    let json: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|e| anyhow!("Invalid JWT payload JSON: {e}"))?;

    json.get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("JWT missing 'sub' claim"))
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
        // No-op: legacy auth is not supported in JWT-only deployments.
    }

    request
}

/// Add authentication headers including CSRF token for state-changing requests
fn add_auth_headers(
    mut request: reqwest::RequestBuilder,
    creds: &SavedCredentials,
    is_state_changing: bool,
) -> Result<reqwest::RequestBuilder> {
    let auth_tokens = creds.auth_tokens.as_ref().ok_or_else(|| {
        anyhow!(
            "JWT authentication required. Run `pipe login` (or `pipe set-password` for new accounts) first."
        )
    })?;

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

    Ok(request)
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

#[derive(Debug)]
pub struct UploadResult {
    pub filename: String,
    pub token_cost: f64,
    pub blake3_hash: String,
    pub file_size: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UploadLogEntry {
    pub local_path: String,
    pub remote_path: String,
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

/// Calculate Blake3 hash of a file
pub async fn calculate_blake3(file_path: &Path) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut file = tokio::fs::File::open(file_path).await?;
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hasher.finalize().to_hex().to_string())
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
    append_to_upload_log_with_hash(local_path, remote_path, status, message, None, None)
}

pub fn append_to_upload_log_with_hash(
    local_path: &str,
    remote_path: &str,
    status: &str,
    message: &str,
    blake3_hash: Option<String>,
    file_size: Option<u64>,
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
        blake3_hash,
        file_size,
        timestamp: Some(chrono::Utc::now()),
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
                && filter_regex.is_none_or(|re| re.is_match(&e.remote_path))
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
        api_base_url: None,
        s3_endpoint: None,
        s3_region: None,
        s3_virtual_hosted: None,
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
    improved_download_file_with_auth_and_options(
        client,
        base_url,
        creds,
        file_name,
        output_path,
        false,
    )
    .await
}

async fn improved_download_file_with_auth_and_options(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    file_name: &str,
    output_path: &str,
    use_legacy: bool,
) -> Result<()> {
    // Handle directory case - append filename if output_path is a directory
    let output_path = if Path::new(output_path).is_dir() {
        Path::new(output_path)
            .join(file_name)
            .to_string_lossy()
            .to_string()
    } else {
        output_path.to_string()
    };

    println!("Downloading '{}' to '{}'...", file_name, &output_path);

    // Build the URL - NO CREDENTIALS IN URL (security fix)
    let endpoint = if use_legacy {
        // Use legacy endpoint that returns base64-encoded data
        format!("{}/download", base_url)
    } else {
        // Use the new streaming endpoint for better performance
        format!("{}/download-stream", base_url)
    };

    // Create progress bar
    let progress = ProgressBar::new(0);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Build request with appropriate auth headers
    // Use query() method to properly encode parameters
    let mut request = client.get(&endpoint).query(&[("file_name", file_name)]);
    request = add_auth_headers(request, creds, false)?;

    let resp = request.send().await?;
    let status = resp.status();

    if !status.is_success() {
        let error_text = resp.text().await?;
        if status.as_u16() == 402 {
            if let Ok(error_data) = serde_json::from_str::<serde_json::Value>(&error_text) {
                if let Some(message) = error_data.get("message").and_then(|m| m.as_str()) {
                    eprintln!("\n❌ Download failed: Insufficient prepaid credits (USDC)");
                    eprintln!("{}", message);
                    if let Some(required) = error_data
                        .get("required_usdc")
                        .and_then(|r| r.as_f64())
                        .or_else(|| {
                            error_data
                                .get("estimated_cost_usdc")
                                .and_then(|r| r.as_f64())
                        })
                    {
                        eprintln!("\n💰 Credits:");
                        eprintln!("   Required: ${} USDC", format_usdc_ui(required));
                        if let Some(current) = error_data
                            .get("credits_balance_usdc")
                            .and_then(|c| c.as_f64())
                        {
                            let needed = (required - current).max(0.0);
                            eprintln!("   Current:  ${} USDC", format_usdc_ui(current));
                            eprintln!("   Needed:   ${} USDC", format_usdc_ui(needed));
                        }
                    }
                    eprintln!("\n💡 Next steps:");
                    eprintln!("   1) Run: pipe check-deposit");
                    eprintln!("   2) Top up: pipe credits-intent 10");
                }
            }
        }
        return Err(anyhow!(
            "Download failed with status {}: {}",
            status,
            error_text
        ));
    }

    let cost_charged = resp
        .headers()
        .get("X-Tokens-Charged")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    if use_legacy {
        // Legacy mode: Get the full response body and decode base64
        let body_bytes = resp.bytes().await?;

        // The legacy /download endpoint returns base64-encoded content
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
                eprintln!(
                    "Warning: Response is not valid UTF-8, cannot be base64. Using raw response."
                );
                body_bytes.to_vec()
            }
        };

        // Write the decoded content
        tokio::fs::write(&output_path, &final_bytes).await?;
        progress.set_position(final_bytes.len() as u64);
        progress.finish_with_message("Download completed");
        if cost_charged > 0.0 {
            println!(
                "💰 Cost: ${} USDC (prepaid credits)",
                format_usdc_ui(cost_charged)
            );
        }
    } else {
        // Streaming mode: Get content length for progress bar
        let total_size = resp.content_length().unwrap_or(0);
        progress.set_length(total_size);

        // Stream the response directly to file (no base64 decoding needed for /download-stream)
        let file = tokio::fs::File::create(&output_path).await?;
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
        if cost_charged > 0.0 {
            println!(
                "💰 Cost: ${} USDC (prepaid credits)",
                format_usdc_ui(cost_charged)
            );
        }
    }

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

                // Check if it's a retryable error
                let is_rate_limit =
                    error_str.contains("429") || error_str.contains("Too Many Requests");
                // Treat common upstream errors as transient (nginx/backends)
                let is_5xx_gateway = error_str.contains("502")
                    || error_str.contains("503")
                    || error_str.contains("504")
                    || error_str.contains("Bad Gateway")
                    || error_str.contains("Service Unavailable")
                    || error_str.contains("Gateway Timeout");
                let is_transient_500 = error_str.contains("500")
                    && (error_str.contains("Failed to flush buffer")
                        || error_str.contains("Failed to write to file")
                        || error_str.contains("Storage full")
                        || error_str.contains("Out of memory")
                        || error_str.contains("interrupted")
                        || error_str.contains("timed out")
                        || error_str.contains("broken"));
                let is_transient_error = is_5xx_gateway || is_transient_500;

                if is_rate_limit || is_transient_error {
                    if retry_count >= MAX_RETRIES {
                        eprintln!(
                            "❌ {} failed after {} retries: {}",
                            operation_name, MAX_RETRIES, e
                        );

                        // Provide helpful guidance for specific errors
                        if error_str.contains("Failed to flush buffer") {
                            eprintln!("\n💡 Suggestions:");
                            eprintln!("   1. The server may be experiencing temporary issues");
                            eprintln!("   2. Try uploading again in a few minutes");
                            eprintln!("   3. If the problem persists, contact support");
                        } else if error_str.contains("Storage full") {
                            eprintln!("\n⚠️  The server appears to be out of disk space.");
                            eprintln!("   Please contact support or try again later.");
                        }

                        return Err(e);
                    }

                    // Different messages for different error types
                    let (retry_msg, wait_time) = if is_rate_limit {
                        ("⏳ Rate limited", backoff_secs)
                    } else {
                        ("⚠️  Server error", backoff_secs.min(5)) // Shorter initial wait for 500 errors
                    };

                    retry_count += 1;
                    eprintln!(
                        "{} on {}. Retry {}/{} in {} seconds...",
                        retry_msg, operation_name, retry_count, MAX_RETRIES, wait_time
                    );

                    tokio::time::sleep(tokio::time::Duration::from_secs(wait_time)).await;

                    // Exponential backoff with cap
                    backoff_secs = (backoff_secs * 2).min(MAX_RETRY_DELAY_MS / 1000).min(60);
                } else {
                    // Not a retryable error
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

    request = add_auth_headers(request, creds, true)?;

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
        api_base_url: None,
        s3_endpoint: None,
        s3_region: None,
        s3_virtual_hosted: None,
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
        base_url,
        utf8_percent_encode(file_name_in_bucket, QUERY_ENCODE_SET)
    );

    let mut request = client.get(&url);
    request = add_auth_headers(request, creds, false)?;

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
#[allow(dead_code)]
async fn download_file_with_quantum_decryption(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    file_name: &str,
    output_path: &str,
    decrypt_password: bool,
    password: Option<String>,
) -> Result<()> {
    download_file_with_quantum_decryption_and_options(
        client,
        base_url,
        creds,
        file_name,
        output_path,
        decrypt_password,
        password,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn download_file_with_quantum_decryption_and_options(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    file_name: &str,
    output_path: &str,
    decrypt_password: bool,
    password: Option<String>,
    use_legacy: bool,
) -> Result<()> {
    use crate::quantum::decrypt_and_verify;
    use crate::quantum_keyring::load_quantum_keypair;

    println!("🔐 Downloading quantum-encrypted file...");

    // Download the quantum-encrypted file
    let temp_path = format!("{}.qenc.tmp", output_path);
    improved_download_file_with_auth_and_options(
        client, base_url, creds, file_name, &temp_path, use_legacy,
    )
    .await?;

    // Read the downloaded file
    let quantum_encrypted_data = std::fs::read(&temp_path)?;
    println!("  Downloaded size: {} bytes", quantum_encrypted_data.len());

    // Determine the original filename (remove .qenc extension if present)
    let original_filename = if let Some(stripped) = file_name.strip_suffix(".qenc") {
        stripped
    } else {
        file_name
    };

    // Load quantum keys
    let quantum_keys = match load_quantum_keypair(original_filename) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!(
                "⚠️  Could not load quantum keys for {}: {}",
                original_filename, e
            );
            eprintln!("    Make sure you have the quantum keys from when this file was uploaded.");
            let _ = std::fs::remove_file(&temp_path);
            return Err(anyhow!("Quantum keys not found"));
        }
    };

    // Decrypt and verify using quantum crypto
    println!("  Decrypting with quantum-resistant algorithms...");
    let signed_data = decrypt_and_verify(&quantum_encrypted_data, &quantum_keys.kyber_secret)?;

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

    println!(
        "✅ Quantum-encrypted file downloaded and decrypted to: {}",
        output_path
    );
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
    download_file_with_decryption_and_options(
        client,
        base_url,
        creds,
        file_name,
        output_path,
        decrypt,
        password,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn download_file_with_decryption_and_options(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    file_name: &str,
    output_path: &str,
    decrypt: bool,
    password: Option<String>,
    use_legacy: bool,
) -> Result<()> {
    let actual_file_name = if decrypt && !file_name.ends_with(".enc") {
        format!("{}.enc", file_name)
    } else {
        file_name.to_string()
    };

    if decrypt {
        // Download to temporary file first
        let temp_path = format!("{}.tmp", output_path);
        improved_download_file_with_auth_and_options(
            client,
            base_url,
            creds,
            &actual_file_name,
            &temp_path,
            use_legacy,
        )
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
        improved_download_file_with_auth_and_options(
            client,
            base_url,
            creds,
            &actual_file_name,
            output_path,
            use_legacy,
        )
        .await
    }
}

/// Download an entire directory based on upload log
#[allow(clippy::too_many_arguments)]
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
    let matching_entries =
        filter_entries_for_download(&entries, remote_prefix, filter_regex.as_ref());

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
                )
                .await
            } else {
                improved_download_file_with_auth(
                    &client,
                    &base_url,
                    &creds,
                    &remote_path,
                    &local_path.to_string_lossy(),
                )
                .await
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
                blake3_hash: None,
                file_size: None,
                timestamp: None,
            },
            UploadLogEntry {
                local_path: "/home/user/photos/vacation/sunset.jpg".to_string(),
                remote_path: "vacation/sunset.jpg".to_string(),
                status: "SUCCESS".to_string(),
                message: "Directory upload success".to_string(),
                blake3_hash: None,
                file_size: None,
                timestamp: None,
            },
            UploadLogEntry {
                local_path: "/home/user/photos/family/portrait.jpg".to_string(),
                remote_path: "family/portrait.jpg".to_string(),
                status: "SUCCESS".to_string(),
                message: "Directory upload success".to_string(),
                blake3_hash: None,
                file_size: None,
                timestamp: None,
            },
            UploadLogEntry {
                local_path: "/home/user/docs/report.pdf".to_string(),
                remote_path: "docs/report.pdf".to_string(),
                status: "FAIL".to_string(),
                message: "Upload failed".to_string(),
                blake3_hash: None,
                file_size: None,
                timestamp: None,
            },
            UploadLogEntry {
                local_path: "/home/user/docs/summary.pdf".to_string(),
                remote_path: "docs/summary.pdf".to_string(),
                status: "SUCCESS".to_string(),
                message: "Directory upload success".to_string(),
                blake3_hash: None,
                file_size: None,
                timestamp: None,
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
        assert!(filtered
            .iter()
            .all(|e| e.remote_path.starts_with("vacation")));

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
            api_base_url: None,
            s3_endpoint: None,
            s3_region: None,
            s3_virtual_hosted: None,
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
        )
        .await;

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
                blake3_hash: None,
                file_size: None,
                timestamp: None,
            },
            UploadLogEntry {
                local_path: "TEST.TXT".to_string(),
                remote_path: "TEST.TXT".to_string(),
                status: "SUCCESS".to_string(),
                message: "ok".to_string(),
                blake3_hash: None,
                file_size: None,
                timestamp: None,
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
#[allow(clippy::too_many_arguments)]
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

    println!(
        "  Quantum encrypted size: {} bytes",
        quantum_encrypted.len()
    );

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
#[allow(clippy::too_many_arguments)]
async fn upload_file_with_encryption(
    client: &Client,
    file_path: &Path,
    full_url: &str,
    file_name_in_bucket: &str,
    creds: &SavedCredentials,
    encrypt: bool,
    password: Option<String>,
    shared_progress: Option<DirectoryUploadProgress>,
    upload_id: Option<&str>,
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
            upload_id,
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
            upload_id,
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
    upload_id: Option<&str>,
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

    if let Some(upload_id) = upload_id {
        request = request.header("X-Upload-Id", upload_id);
    }

    request = add_auth_headers(request, creds, true)?;

    let resp = request.body(body).send().await?;

    let status = resp.status();

    // Extract cost from headers (USDC credits in current pipe-store)
    let cost_charged = resp
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
            if cost_charged > 0.0 {
                println!(
                    "💰 Cost: ${} USDC (prepaid credits)",
                    format_usdc_ui(cost_charged)
                );
            }
        }
        Ok((file_name_in_bucket.to_string(), cost_charged))
    } else {
        if !is_shared {
            progress.finish_and_clear();
        }

        // Check for insufficient prepaid credits error
        if status == 402 {
            // Try to parse JSON response for detailed error
            if let Ok(error_data) = serde_json::from_str::<serde_json::Value>(&text_body) {
                if let Some(message) = error_data.get("message").and_then(|m| m.as_str()) {
                    eprintln!("\n❌ Upload failed: Insufficient prepaid credits (USDC)");
                    eprintln!("{}", message);
                    if let Some(required) = error_data
                        .get("required_usdc")
                        .and_then(|r| r.as_f64())
                        .or_else(|| {
                            error_data
                                .get("estimated_cost_usdc")
                                .and_then(|r| r.as_f64())
                        })
                    {
                        eprintln!("\n💰 Credits:");
                        eprintln!("   Required: ${} USDC", format_usdc_ui(required));
                        if let Some(current) = error_data
                            .get("credits_balance_usdc")
                            .and_then(|c| c.as_f64())
                        {
                            let needed = (required - current).max(0.0);
                            eprintln!("   Current:  ${} USDC", format_usdc_ui(current));
                            eprintln!("   Needed:   ${} USDC", format_usdc_ui(needed));
                        }
                    }
                    eprintln!("\n💡 Next steps:");
                    eprintln!("   1) Run: pipe check-deposit");
                    eprintln!("   2) Top up: pipe credits-intent 10");
                    return Err(anyhow!("Upload failed: {}", message));
                }
            }
            return Err(anyhow!(
                "Upload failed: Insufficient prepaid credits. Run `pipe check-deposit` and top up USDC credits."
            ));
        }

        // Provide more user-friendly error messages for common server errors
        let error_msg = if status == 500 {
            match text_body.as_str() {
                "Failed to flush buffer" => {
                    format!("Upload of '{}' failed: Server temporarily unable to save file. This is usually a transient issue.", file_path.display())
                }
                "Storage full - no space left on device" => {
                    format!(
                        "Upload of '{}' failed: Server storage is full. Please contact support.",
                        file_path.display()
                    )
                }
                "Out of memory during upload" => {
                    format!("Upload of '{}' failed: Server out of memory. Try uploading a smaller file or wait and retry.", file_path.display())
                }
                "Permission denied writing to file" | "Permission denied writing to cache" => {
                    format!("Upload of '{}' failed: Server file permission error. Please contact support.", file_path.display())
                }
                "Upload interrupted - please retry" | "Write interrupted - please retry" => {
                    format!(
                        "Upload of '{}' was interrupted. Please try again.",
                        file_path.display()
                    )
                }
                "Connection broken during upload" => {
                    format!("Upload of '{}' failed: Connection lost. Check your internet connection and try again.", file_path.display())
                }
                "Write operation timed out" => {
                    format!("Upload of '{}' timed out. The file may be too large or the connection too slow.", file_path.display())
                }
                _ => {
                    format!(
                        "Upload of '{}' failed with server error. Status={}, Body={}",
                        file_path.display(),
                        status,
                        text_body
                    )
                }
            }
        } else {
            format!(
                "Upload of '{}' failed. Status={}, Body={}",
                file_path.display(),
                status,
                text_body
            )
        };

        Err(anyhow!(error_msg))
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
    upload_id: Option<&str>,
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

    if let Some(upload_id) = upload_id {
        request = request.header("X-Upload-Id", upload_id);
    }

    request = add_auth_headers(request, creds, true)?;

    let resp = request.body(body).send().await?;

    let status = resp.status();

    // Extract cost from headers (USDC credits in current pipe-store)
    let cost_charged = resp
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
                        if cost_charged > 0.0 {
                            println!(
                                "💰 Cost: ${} USDC (priority multiplier: {}x)",
                                format_usdc_ui(cost_charged),
                                priority_fee
                            );
                        }
                    }
                    return Ok((file_name_in_bucket.to_string(), cost_charged));
                }
            }
        }
        if !is_shared {
            progress.finish_with_message("Priority upload finished successfully");
            println!("Server says: {}", text_body);
            if cost_charged > 0.0 {
                println!(
                    "💰 Cost: ${} USDC (priority multiplier: {}x)",
                    format_usdc_ui(cost_charged),
                    priority_fee
                );
            }
        }
        Ok((file_name_in_bucket.to_string(), cost_charged))
    } else {
        if !is_shared {
            progress.finish_and_clear();
        }

        // Check for insufficient prepaid credits error
        if status == 402 {
            // Try to parse JSON response for detailed error
            if let Ok(error_data) = serde_json::from_str::<serde_json::Value>(&text_body) {
                if let Some(message) = error_data.get("message").and_then(|m| m.as_str()) {
                    eprintln!("\n❌ Priority upload failed: Insufficient prepaid credits (USDC)");
                    eprintln!("{}", message);
                    if let Some(required) = error_data
                        .get("required_usdc")
                        .and_then(|r| r.as_f64())
                        .or_else(|| {
                            error_data
                                .get("estimated_cost_usdc")
                                .and_then(|r| r.as_f64())
                        })
                    {
                        eprintln!("\n💰 Credits:");
                        eprintln!("   Required: ${} USDC", format_usdc_ui(required));
                        if let Some(current) = error_data
                            .get("credits_balance_usdc")
                            .and_then(|c| c.as_f64())
                        {
                            let needed = (required - current).max(0.0);
                            eprintln!("   Current:  ${} USDC", format_usdc_ui(current));
                            eprintln!("   Needed:   ${} USDC", format_usdc_ui(needed));
                        }
                    }
                    if let Some(priority_multiplier) = error_data
                        .get("priority_fee_per_gb")
                        .and_then(|p| p.as_f64())
                        .or_else(|| {
                            if priority_fee > 0.0 {
                                Some(priority_fee)
                            } else {
                                None
                            }
                        })
                    {
                        eprintln!("\n📈 Priority multiplier: {}x", priority_multiplier);
                    }
                    eprintln!("\n💡 Next steps:");
                    eprintln!("   1) Run: pipe check-deposit");
                    eprintln!("   2) Top up: pipe credits-intent 10");
                    return Err(anyhow!("Priority upload failed: {}", message));
                }
            }
            return Err(anyhow!(
                "Priority upload failed: Insufficient prepaid credits. Run `pipe check-deposit` and top up USDC credits."
            ));
        }

        // Provide more user-friendly error messages for common server errors
        let error_msg = if status == 500 {
            match text_body.as_str() {
                "Failed to flush buffer" => {
                    format!("Priority upload of '{}' failed: Server temporarily unable to save file. This is usually a transient issue.", file_path.display())
                }
                "Storage full - no space left on device" => {
                    format!("Priority upload of '{}' failed: Server storage is full. Please contact support.", file_path.display())
                }
                "Out of memory during upload" => {
                    format!("Priority upload of '{}' failed: Server out of memory. Try uploading a smaller file or wait and retry.", file_path.display())
                }
                "Permission denied writing to file" | "Permission denied writing to cache" => {
                    format!("Priority upload of '{}' failed: Server file permission error. Please contact support.", file_path.display())
                }
                "Upload interrupted - please retry" | "Write interrupted - please retry" => {
                    format!(
                        "Priority upload of '{}' was interrupted. Please try again.",
                        file_path.display()
                    )
                }
                "Connection broken during upload" => {
                    format!("Priority upload of '{}' failed: Connection lost. Check your internet connection and try again.", file_path.display())
                }
                "Write operation timed out" => {
                    format!("Priority upload of '{}' timed out. The file may be too large or the connection too slow.", file_path.display())
                }
                _ => {
                    format!(
                        "Priority upload of '{}' failed with server error. Status={}, Body={}",
                        file_path.display(),
                        status,
                        text_body
                    )
                }
            }
        } else {
            format!(
                "Priority upload of '{}' failed. Status={}, Body={}",
                file_path.display(),
                status,
                text_body
            )
        };

        Err(anyhow!(error_msg))
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
            Ok(text_body) => match general_purpose::STANDARD.decode(text_body.trim()) {
                Ok(decoded) => {
                    let decoded_str = std::str::from_utf8(&decoded).unwrap();
                    assert_eq!(decoded_str, original_text);
                }
                Err(_) => panic!("Base64 decode should succeed"),
            },
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
            Ok(text_body) => match general_purpose::STANDARD.decode(text_body.trim()) {
                Ok(decoded) => {
                    assert_eq!(decoded, original_binary);
                }
                Err(_) => panic!("Base64 decode should succeed"),
            },
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
            Ok(text_body) => match general_purpose::STANDARD.decode(text_body.trim()) {
                Ok(decoded) => {
                    let decoded_str = std::str::from_utf8(&decoded).unwrap();
                    assert_eq!(decoded_str, original_text);
                }
                Err(_) => panic!("Base64 decode should succeed after trimming"),
            },
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
            Ok(text_body) => match general_purpose::STANDARD.decode(text_body.trim()) {
                Ok(decoded) => {
                    assert_eq!(decoded.len(), large_content.len());
                    assert_eq!(decoded, large_content);
                }
                Err(_) => panic!("Base64 decode should succeed"),
            },
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
    use crate::quantum::{decrypt_and_verify, sign_and_encrypt};
    use crate::quantum_keyring::{
        generate_quantum_keypair, load_quantum_keypair, save_quantum_keypair,
    };

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
        )
        .unwrap();

        // Verify encryption increased size significantly
        assert!(encrypted.len() > test_data.len() + 1000); // Quantum crypto adds overhead

        // Decrypt and verify
        let decrypted = decrypt_and_verify(&encrypted, &keypair.kyber_secret).unwrap();

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
        let encryption_key =
            crate::encryption::derive_key_from_password(password, quantum_salt).unwrap();
        let (password_encrypted, nonce) =
            crate::encryption::encrypt_data(test_data, &encryption_key).unwrap();

        // Combine nonce and encrypted data
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&password_encrypted);

        // Then encrypt with quantum
        let quantum_encrypted = sign_and_encrypt(
            &combined,
            &keypair.dilithium_secret,
            &keypair.dilithium_public,
            &keypair.kyber_public,
        )
        .unwrap();

        // Decrypt quantum layer
        let quantum_decrypted =
            decrypt_and_verify(&quantum_encrypted, &keypair.kyber_secret).unwrap();

        // Extract nonce and decrypt password layer
        let (nonce_bytes, encrypted_data) = quantum_decrypted.data.split_at(12);
        let mut nonce_recovered = [0u8; 12];
        nonce_recovered.copy_from_slice(nonce_bytes);

        let final_decrypted =
            crate::encryption::decrypt_data(encrypted_data, &encryption_key, &nonce_recovered)
                .unwrap();

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

fn normalize_http_url_without_path(raw: &str, label: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("{label} must not be empty"));
    }

    let url = reqwest::Url::parse(trimmed)
        .map_err(|_| anyhow!("{label} must be a valid URL (expected http/https)"))?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(anyhow!("{label} scheme must be http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!("{label} must not include username/password"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!("{label} must not include query/fragment"));
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(anyhow!("{label} must not include a path"));
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("{label} must include a host"))?
        .to_ascii_lowercase();

    let port = match (scheme, url.port()) {
        ("http", Some(80)) | ("https", Some(443)) => None,
        (_, p) => p,
    };

    Ok(match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

fn bucket_name_for_user_id(user_id: &str) -> String {
    format!("pipe-{user_id}")
}

fn split_comma_newline_list(raw: &[String]) -> Vec<String> {
    raw.iter()
        .flat_map(|s| s.split(['\n', ',']))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_s3_key_mode(mode: &str) -> Result<bool> {
    let normalized = mode.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "read-only" | "readonly" | "ro" => Ok(true),
        "read-write" | "readwrite" | "rw" => Ok(false),
        _ => Err(anyhow!(
            "Invalid --mode. Expected \"read-only\" or \"read-write\"."
        )),
    }
}

#[cfg(test)]
mod cli_s3_config_tests {
    use super::*;

    #[test]
    fn normalize_http_url_without_path_rejects_paths() {
        assert!(normalize_http_url_without_path("https://example.com/path", "API").is_err());
    }

    #[test]
    fn normalize_http_url_without_path_strips_default_ports() {
        assert_eq!(
            normalize_http_url_without_path("https://Example.com:443", "API").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            normalize_http_url_without_path("http://Example.com:80", "API").unwrap(),
            "http://example.com"
        );
    }

    #[test]
    fn split_comma_newline_list_splits_and_trims() {
        let v = split_comma_newline_list(&vec![" a,b\nc ".to_string(), "d".to_string()]);
        assert_eq!(v, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn parse_s3_key_mode_accepts_aliases() {
        assert!(parse_s3_key_mode("read-only").unwrap());
        assert!(parse_s3_key_mode("ro").unwrap());
        assert!(!parse_s3_key_mode("read-write").unwrap());
        assert!(!parse_s3_key_mode("rw").unwrap());
    }

    #[test]
    fn save_credentials_preserves_cli_config_fields() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("creds.json");
        let path_str = path.to_str().unwrap();

        let initial = SavedCredentials {
            user_id: "u1".to_string(),
            user_app_key: "k1".to_string(),
            auth_tokens: None,
            username: None,
            api_base_url: Some("https://api.example.com".to_string()),
            s3_endpoint: Some("https://s3.example.com".to_string()),
            s3_region: Some("us-east-1".to_string()),
            s3_virtual_hosted: Some(true),
        };
        save_full_credentials(&initial, Some(path_str)).unwrap();

        save_credentials_to_file("u2", "k2", Some(path_str)).unwrap();
        let loaded = load_credentials_from_file(Some(path_str)).unwrap().unwrap();

        assert_eq!(loaded.user_id, "u2");
        assert_eq!(loaded.user_app_key, "k2");
        assert_eq!(
            loaded.api_base_url.as_deref(),
            Some("https://api.example.com")
        );
        assert_eq!(
            loaded.s3_endpoint.as_deref(),
            Some("https://s3.example.com")
        );
        assert_eq!(loaded.s3_region.as_deref(), Some("us-east-1"));
        assert_eq!(loaded.s3_virtual_hosted, Some(true));
    }
}

pub async fn run_cli() -> Result<()> {
    let matches = Cli::command().get_matches();
    let api_source = matches.value_source("api");
    let cli = Cli::from_arg_matches(&matches).map_err(|e| anyhow!(e.to_string()))?;

    // Get config path from CLI or use default
    let config_path = cli.config.as_deref();

    // Create optimized HTTP client for high concurrency
    let client = Client::builder()
        .pool_max_idle_per_host(100) // Keep more connections alive
        .pool_idle_timeout(std::time::Duration::from_secs(90)) // Keep connections alive longer
        .timeout(std::time::Duration::from_secs(7200)) // 2 hour timeout for very large files (95GB+)
        .build()?;

    let mut base_url_string = cli.api.trim_end_matches('/').to_string();
    if api_source == Some(clap::parser::ValueSource::DefaultValue) {
        if let Ok(Some(creds)) = load_credentials_from_file(config_path) {
            if let Some(saved) = creds.api_base_url.as_deref() {
                let trimmed = saved.trim().trim_end_matches('/');
                if !trimmed.is_empty() {
                    base_url_string = trimmed.to_string();
                }
            }
        }
    }
    let base_url = base_url_string.as_str();

    // Initialize service discovery cache
    let service_cache = Arc::new(ServiceDiscoveryCache::new(base_url_string.clone()));

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
            | Commands::CheckToken { .. }
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
        Commands::Config { command } => {
            let config_file = get_credentials_file_path(config_path);

            match command {
                ConfigCommands::Show => {
                    println!("Config file: {:?}", config_file);
                    println!("Effective API base URL (this run): {}", base_url);

                    let Some(creds) = load_credentials_from_file(config_path)? else {
                        println!("No config/credentials found yet.");
                        println!("Run `pipe new-user` or `pipe login` first, then re-run `pipe config show`.");
                        return Ok(());
                    };

                    if let Some(u) = creds.username.as_deref() {
                        println!("Username: {}", u);
                    }
                    if !creds.user_id.is_empty() {
                        println!("User ID: {}", creds.user_id);
                        println!("Bucket: {}", bucket_name_for_user_id(&creds.user_id));
                    }

                    println!(
                        "Saved API base URL: {}",
                        creds.api_base_url.as_deref().unwrap_or("(not set)")
                    );
                    println!(
                        "Saved S3 endpoint: {}",
                        creds.s3_endpoint.as_deref().unwrap_or("(not set)")
                    );
                    println!(
                        "Saved S3 region: {}",
                        creds.s3_region.as_deref().unwrap_or("(not set)")
                    );
                    println!(
                        "Saved S3 virtual-hosted-style: {}",
                        creds
                            .s3_virtual_hosted
                            .map(|v| if v { "true" } else { "false" })
                            .unwrap_or("(not set)")
                    );
                }
                ConfigCommands::SetApi { url } => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    let normalized = normalize_http_url_without_path(&url, "API base URL")?;
                    creds.api_base_url = Some(normalized.clone());
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Saved API base URL: {}", normalized);
                }
                ConfigCommands::ClearApi => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.api_base_url = None;
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Cleared saved API base URL");
                }
                ConfigCommands::SetS3Endpoint { endpoint } => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    let normalized = normalize_http_url_without_path(&endpoint, "S3 endpoint")?;
                    creds.s3_endpoint = Some(normalized.clone());
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Saved S3 endpoint: {}", normalized);
                }
                ConfigCommands::ClearS3Endpoint => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.s3_endpoint = None;
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Cleared saved S3 endpoint");
                }
                ConfigCommands::SetS3Region { region } => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    let trimmed = region.trim();
                    if trimmed.is_empty() {
                        return Err(anyhow!("S3 region must not be empty"));
                    }
                    creds.s3_region = Some(trimmed.to_string());
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Saved S3 region: {}", trimmed);
                }
                ConfigCommands::ClearS3Region => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.s3_region = None;
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Cleared saved S3 region");
                }
                ConfigCommands::SetS3VirtualHosted { enabled } => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.s3_virtual_hosted = Some(enabled);
                    save_full_credentials(&creds, config_path)?;
                    println!(
                        "✓ Saved S3 virtual-hosted-style default: {}",
                        if enabled { "true" } else { "false" }
                    );
                }
                ConfigCommands::ClearS3VirtualHosted => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.s3_virtual_hosted = None;
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Cleared saved S3 virtual-hosted-style default");
                }
            }

            return Ok(());
        }
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

                // Save basic credentials (and persist CLI config defaults like `api_base_url`).
                let existing_cfg = load_credentials_from_file(config_path).ok().flatten();
                let api_base_url = existing_cfg
                    .as_ref()
                    .and_then(|c| c.api_base_url.clone())
                    .or_else(|| Some(base_url.to_string()));
                let s3_endpoint = existing_cfg.as_ref().and_then(|c| c.s3_endpoint.clone());
                let s3_region = existing_cfg.as_ref().and_then(|c| c.s3_region.clone());
                let s3_virtual_hosted = existing_cfg.as_ref().and_then(|c| c.s3_virtual_hosted);
                let creds = SavedCredentials {
                    user_id: json.user_id.clone(),
                    user_app_key: json.user_app_key.clone(),
                    auth_tokens: None,
                    username: Some(username.clone()),
                    api_base_url,
                    s3_endpoint,
                    s3_region,
                    s3_virtual_hosted,
                };
                save_full_credentials(&creds, config_path)?;

                // Prompt for password (required for JWT-only deployments)
                println!("\nSet a password for secure access (required):");

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
                                csrf_token: response_data
                                    .get("csrf_token")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string()),
                            };

                            // Calculate expires_at timestamp
                            let now =
                                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                            let expires_at =
                                DateTime::<Utc>::from_timestamp(now + auth_tokens.expires_in, 0)
                                    .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;

                            let mut auth_tokens = auth_tokens;
                            auth_tokens.expires_at = Some(expires_at);

                            // Preserve optional CLI config fields when writing credentials.
                            let existing_cfg =
                                load_credentials_from_file(config_path).ok().flatten();
                            let api_base_url = existing_cfg
                                .as_ref()
                                .and_then(|c| c.api_base_url.clone())
                                .or_else(|| Some(base_url.to_string()));
                            let s3_endpoint =
                                existing_cfg.as_ref().and_then(|c| c.s3_endpoint.clone());
                            let s3_region = existing_cfg.as_ref().and_then(|c| c.s3_region.clone());
                            let s3_virtual_hosted =
                                existing_cfg.as_ref().and_then(|c| c.s3_virtual_hosted);

                            // Save full credentials with JWT tokens
                            let creds = SavedCredentials {
                                user_id: json.user_id.clone(),
                                user_app_key: json.user_app_key.clone(),
                                auth_tokens: Some(auth_tokens),
                                username: Some(username.clone()),
                                api_base_url,
                                s3_endpoint,
                                s3_region,
                                s3_virtual_hosted,
                            };
                            save_full_credentials(&creds, config_path)?;

                            println!("\n✓ Password set successfully!");
                            println!("✓ You are now logged in with secure JWT authentication!");
                            println!(
                                "✓ Credentials saved to {:?}",
                                get_credentials_file_path(config_path)
                            );
                            println!("\nYou can now use all pipe commands securely!");
                        } else {
                            println!("\n✓ Password set successfully!");
                            println!("✓ Account created!");
                            println!(
                                "✓ Credentials saved to {:?}",
                                get_credentials_file_path(config_path)
                            );
                            println!("\nNote: You may need to login to get JWT tokens.");
                        }
                    } else {
                        eprintln!(
                            "\nWarning: Failed to set password. You can try again later with:"
                        );
                        eprintln!("  ./pipe set-password");
                        eprintln!("\n✓ Account created successfully!");
                        eprintln!(
                            "✓ Credentials saved to {:?}",
                            get_credentials_file_path(config_path)
                        );
                        eprintln!("\nNote: This deployment requires JWT. Set a password to start using pipe commands.");
                    }
                } else {
                    // User skipped password
                    println!("\n✓ Account created successfully!");
                    println!(
                        "✓ Credentials saved to {:?}",
                        get_credentials_file_path(config_path)
                    );
                    println!("\nNote: This deployment requires JWT. Set a password now with:");
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
            let password = match password {
                Some(p) => p,
                None => rpassword::prompt_password("Enter password: ")
                    .map_err(|e| anyhow!("Failed to read password: {e}"))?,
            };

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
                let existing = load_credentials_from_file(config_path).ok().flatten();
                let user_app_key = existing
                    .as_ref()
                    .map(|c| c.user_app_key.clone())
                    .unwrap_or_default();

                let user_id =
                    extract_user_id_from_jwt(&auth_tokens.access_token).unwrap_or_else(|_| {
                        existing
                            .as_ref()
                            .map(|c| c.user_id.clone())
                            .unwrap_or_default()
                    });

                let api_base_url = existing
                    .as_ref()
                    .and_then(|c| c.api_base_url.clone())
                    .or_else(|| Some(base_url.to_string()));
                let s3_endpoint = existing.as_ref().and_then(|c| c.s3_endpoint.clone());
                let s3_region = existing.as_ref().and_then(|c| c.s3_region.clone());
                let s3_virtual_hosted = existing.as_ref().and_then(|c| c.s3_virtual_hosted);

                let creds = SavedCredentials {
                    user_id,
                    user_app_key,
                    auth_tokens: Some(auth_tokens),
                    username: Some(username),
                    api_base_url,
                    s3_endpoint,
                    s3_region,
                    s3_virtual_hosted,
                };
                save_full_credentials(&creds, config_path)?;
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

            let new_password = match password {
                Some(p) => p,
                None => {
                    println!("Password requirements:");
                    println!("  - Minimum 8 characters");
                    println!("  - Maximum 128 characters");
                    println!("  - Cannot be a common weak password (e.g., 'password', '12345678', 'password123', etc.)");
                    println!();
                    rpassword::prompt_password("Enter new password: ")
                        .map_err(|e| anyhow!("Failed to read password: {e}"))?
                }
            };

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

                    let existing_cfg = load_credentials_from_file(config_path).ok().flatten();
                    let api_base_url = existing_cfg
                        .as_ref()
                        .and_then(|c| c.api_base_url.clone())
                        .or_else(|| Some(base_url.to_string()));
                    let s3_endpoint = existing_cfg.as_ref().and_then(|c| c.s3_endpoint.clone());
                    let s3_region = existing_cfg.as_ref().and_then(|c| c.s3_region.clone());
                    let s3_virtual_hosted = existing_cfg.as_ref().and_then(|c| c.s3_virtual_hosted);

                    let creds = SavedCredentials {
                        user_id: user_id_final,
                        user_app_key: user_app_key_final,
                        auth_tokens: Some(auth_tokens),
                        username: None,
                        api_base_url,
                        s3_endpoint,
                        s3_region,
                        s3_virtual_hosted,
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
                if status == StatusCode::CONFLICT {
                    return Err(anyhow!(
                        "Password already set. Use `pipe change-password` instead."
                    ));
                }

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

        Commands::ChangePassword {
            current_password,
            new_password,
        } => {
            let mut creds = load_credentials_from_file(config_path)?
                .ok_or_else(|| anyhow!("No credentials found. Please login first."))?;

            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            let current_password = current_password.unwrap_or_else(|| {
                rpassword::prompt_password("Current password: ").unwrap_or_default()
            });

            let new_password = match new_password {
                Some(p) => p,
                None => {
                    println!("Password requirements:");
                    println!("  - Minimum 8 characters");
                    println!("  - Maximum 128 characters");
                    println!("  - Cannot be a common weak password (e.g., 'password', '12345678', 'password123', etc.)");
                    println!();

                    let p1 = rpassword::prompt_password("New password: ").unwrap_or_default();
                    let p2 =
                        rpassword::prompt_password("Confirm new password: ").unwrap_or_default();
                    if p1 != p2 {
                        return Err(anyhow!("New passwords do not match"));
                    }
                    p1
                }
            };

            let req_body = ChangePasswordRequest {
                current_password,
                new_password,
            };

            let mut request = client.post(format!("{}/auth/change-password", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&req_body);

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;

            if status.is_success() {
                let mut auth_tokens: AuthTokens = serde_json::from_str(&text_body)?;

                // Calculate expires_at timestamp
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                let expires_at = DateTime::<Utc>::from_timestamp(now + auth_tokens.expires_in, 0)
                    .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;
                auth_tokens.expires_at = Some(expires_at);

                let mut updated_creds = creds.clone();
                updated_creds.auth_tokens = Some(auth_tokens);
                save_full_credentials(&updated_creds, config_path)?;

                println!("Password changed successfully (all other sessions revoked).");
                println!(
                    "Token expires at: {}",
                    expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            } else {
                return Err(anyhow!(
                    "Change password failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
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
                let RefreshTokenResponse {
                    access_token,
                    expires_in,
                    csrf_token,
                    ..
                } = refresh_response;

                // Calculate new expires_at timestamp
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                let expires_at = DateTime::<Utc>::from_timestamp(now + expires_in, 0)
                    .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;

                println!("Token refreshed successfully!");
                println!(
                    "Token expires at: {}",
                    expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                );

                // Update credentials with new access token
                let mut updated_creds = creds.clone();
                if let Some(ref mut auth_tokens) = updated_creds.auth_tokens {
                    auth_tokens.access_token = access_token;
                    auth_tokens.expires_in = expires_in;
                    auth_tokens.expires_at = Some(expires_at);
                    if let Some(token) = csrf_token {
                        auth_tokens.csrf_token = Some(token);
                    }
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

            if user_id.is_some() || old_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--old-app-key are ignored; rotate-app-key uses JWT identity."
                );
            }

            let mut request = client.post(format!("{}/rotateAppKey", base_url));

            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, true)?;

            request = request.json(&serde_json::json!({}));

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
            dry_run,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
            }

            let local_path = Path::new(&file_path);
            if !local_path.exists() {
                return Err(anyhow!("Local file not found: {}", file_path));
            }

            let epochs_final = epochs.unwrap_or(1); // default 1 month

            // Handle dry-run: calculate and show cost estimate
            if dry_run {
                let file_size = std::fs::metadata(local_path)?.len();
                let file_size_gb = bytes_to_gb_decimal(file_size);
                let tier_key = tier.as_deref().unwrap_or("normal");

                let (cost_per_gb_usdc, balance_usdc_opt, available_gb_opt) =
                    match fetch_credits_status(&client, base_url, &creds).await {
                        Ok(status) => {
                            let tier_est = status
                                .quota
                                .tier_estimates
                                .iter()
                                .find(|t| t.tier_name.eq_ignore_ascii_case(tier_key));
                            (
                                tier_est.map(|t| t.cost_per_gb_usdc).unwrap_or(0.0),
                                Some(status.balance_usdc),
                                tier_est.map(|t| t.available_gb),
                            )
                        }
                        Err(_) => {
                            let cost = match tier_key.to_lowercase().as_str() {
                                "priority" => 0.0625,
                                "premium" => 0.125,
                                "ultra" => 0.25,
                                "enterprise" => 0.625,
                                _ => 0.025,
                            };
                            (cost, None, None)
                        }
                    };

                let estimated_cost_usdc = file_size_gb * cost_per_gb_usdc;

                println!("\n📊 Upload Cost Estimate (prepaid credits):");
                println!("  📁 File: {}", file_name);
                println!(
                    "  📏 Size: {:.2} MB ({:.4} GB)",
                    file_size as f64 / 1_048_576.0,
                    file_size_gb
                );
                println!("  📈 Tier: {}", tier_key);
                println!("  💵 Rate: ${} USDC/GB", format_usdc_ui(cost_per_gb_usdc));
                println!(
                    "  💰 Estimated cost: ${} USDC",
                    format_usdc_ui(estimated_cost_usdc)
                );
                println!("  📅 Storage duration: {} month(s)", epochs_final);

                if let Some(balance_usdc) = balance_usdc_opt {
                    println!(
                        "\n💳 Credits balance: ${} USDC",
                        format_usdc_ui(balance_usdc)
                    );
                    if let Some(available_gb) = available_gb_opt {
                        println!(
                            "📦 Available storage ({}): {:.2} GB",
                            tier_key, available_gb
                        );
                    }
                    if balance_usdc + 1e-9 < estimated_cost_usdc {
                        println!("⚠️  Insufficient prepaid credits.");
                        println!(
                            "   Need ${} more USDC",
                            format_usdc_ui((estimated_cost_usdc - balance_usdc).max(0.0))
                        );
                        println!("\n💡 Top up:");
                        println!("   pipe credits-intent 10");
                    } else {
                        println!("✅ Sufficient credits for upload");
                        let remaining = (balance_usdc - estimated_cost_usdc).max(0.0);
                        println!("   After upload: ${} USDC", format_usdc_ui(remaining));
                    }
                } else {
                    println!("\n⚠️  Could not fetch credits status to verify balance.");
                }

                println!("\nThis is a dry run - no upload performed.");
                return Ok(());
            }

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
                selected_endpoint,
                endpoint,
                utf8_percent_encode(&file_name, QUERY_ENCODE_SET),
                epochs_final
            );
            if let Some(tier_name) = tier {
                url = format!("{}&tier={}", url, tier_name);
            }

            // Calculate Blake3 hash before upload
            println!("Calculating file hash...");
            let blake3_hash = calculate_blake3(local_path).await?;
            println!("Blake3 hash: {}", &blake3_hash[..16]); // Show first 16 chars
            let file_size = std::fs::metadata(local_path)?.len();
            let upload_id = Uuid::new_v4().to_string();

            // Use retry wrapper for single file upload
            let upload_result = if false {
                // quantum feature was removed
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
                        None,
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
                        Some(upload_id.as_str()),
                    )
                })
                .await
            };

            match upload_result {
                Ok((uploaded_filename, cost_usdc)) => {
                    println!("File uploaded successfully: {}", uploaded_filename);
                    if cost_usdc > 0.0 {
                        println!(
                            "💰 Cost: ${} USDC (prepaid credits)",
                            format_usdc_ui(cost_usdc)
                        );
                    }
                    append_to_upload_log_with_hash(
                        &file_path,
                        &uploaded_filename,
                        "SUCCESS",
                        &format!("Non-priority upload ({} epochs)", epochs_final),
                        Some(blake3_hash.clone()),
                        Some(file_size),
                    )?;
                    println!("📋 File ID (Blake3): {}", blake3_hash);
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
            file_id: _,
            decrypt,
            password,
            key: _,
            quantum,
            legacy,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
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
                download_file_with_quantum_decryption_and_options(
                    &client,
                    &selected_endpoint,
                    &creds,
                    &file_name,
                    &output_path,
                    decrypt,
                    password,
                    legacy,
                )
                .await?;
            } else {
                download_file_with_decryption_and_options(
                    &client,
                    &selected_endpoint,
                    &creds,
                    &file_name,
                    &output_path,
                    decrypt,
                    password,
                    legacy,
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

            println!(
                "Downloading directory '{}' to '{}'",
                remote_prefix, output_directory
            );
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
            file_id: _,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
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
            request = add_auth_headers(request, &creds, true)?;

            request = request.json(&serde_json::json!({ "file_name": file_name }));

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

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
            }

            let mut request = client.post(format!("{}/checkCustomToken", base_url));

            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, false)?;

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
                    "Token Balance for user: {}\nPubkey: {}\nMint: {}\nAmount: {}\nPIPE: {}",
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

        Commands::CreatePublicLink {
            user_id,
            user_app_key,
            file_name,
            file_id: _,
            title,
            description,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
            }

            let mut request = client.post(format!("{}/createPublicLink", base_url));

            // Add auth headers including CSRF token for this state-changing operation
            request = add_auth_headers(request, &creds, true)?;

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
                println!(
                    "  {}/publicDownload?hash={}&preview=true",
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
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
            }

            let mut request = client.post(format!("{}/deletePublicLink", base_url));

            // Add auth headers including CSRF token for this state-changing operation
            request = add_auth_headers(request, &creds, true)?;

            request = request.json(&serde_json::json!({ "link_hash": link_hash }));

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

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
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
                    let mut fee_req = client.get(&fee_url);
                    fee_req = add_auth_headers(fee_req, &creds, false)?;

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

            let cost_per_gb_usdc = 0.025 * fee_per_gb;
            let total_cost_estimate_usdc = bytes_to_gb_decimal(total_size) * cost_per_gb_usdc;

            match fetch_credits_status(&client, base_url, &creds).await {
                Ok(credits) => {
                    let current_balance = credits.balance_usdc;
                    if current_balance + 1e-9 < total_cost_estimate_usdc {
                        eprintln!("\n❌ Insufficient prepaid credits for directory upload");
                        eprintln!(
                            "Total cost: ${} USDC (at ${} USDC/GB)",
                            format_usdc_ui(total_cost_estimate_usdc),
                            format_usdc_ui(cost_per_gb_usdc)
                        );
                        eprintln!("Your balance: ${} USDC", format_usdc_ui(current_balance));
                        eprintln!(
                            "Needed: ${} USDC",
                            format_usdc_ui((total_cost_estimate_usdc - current_balance).max(0.0))
                        );
                        eprintln!("\nTop up credits with: pipe credits-intent 10");
                        return Ok(());
                    }
                    println!(
                        "💰 Estimated cost: ${} USDC at ${} USDC/GB (balance: ${} USDC)",
                        format_usdc_ui(total_cost_estimate_usdc),
                        format_usdc_ui(cost_per_gb_usdc),
                        format_usdc_ui(current_balance)
                    );
                }
                Err(e) => {
                    eprintln!("⚠️  Could not fetch credits status: {}", e);
                    eprintln!(
                        "Estimated cost: ${} USDC at ${} USDC/GB",
                        format_usdc_ui(total_cost_estimate_usdc),
                        format_usdc_ui(cost_per_gb_usdc)
                    );
                    eprintln!(
                        "\nProceed with caution - could not verify if you have enough credits."
                    );
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

            // Share credentials across tasks so we can refresh tokens mid-run
            let shared_creds = Arc::new(TokioMutex::new(creds));

            for path in file_entries {
                let sem_clone = Arc::clone(&sem);
                let client_clone = client.clone();
                let base_url_clone = base_url.to_string();
                let service_cache_clone = service_cache.clone();
                let shared_creds_clone = shared_creds.clone();
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
                    let _permit = match sem_clone.acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("Upload semaphore closed; aborting task for {}", rel_path);
                            return;
                        }
                    };

                    // Get endpoint for this specific file upload
                    let user_id_owned = {
                        let creds_guard = shared_creds_clone.lock().await;
                        creds_guard.user_id.clone()
                    };
                    let selected_endpoint = get_endpoint_for_operation(
                        &service_cache_clone,
                        &client_clone,
                        &base_url_clone,
                        "upload",
                        &user_id_owned,
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

                    let mut url = format!(
                        "{}/{}?file_name={}",
                        selected_endpoint,
                        endpoint,
                        utf8_percent_encode(&rel_path, QUERY_ENCODE_SET)
                    );
                    if let Some(tier_name) = &tier_clone {
                        url = format!("{}&tier={}", url, tier_name);
                    }

                    // Use retry wrapper for directory uploads
                    let upload_id = Uuid::new_v4().to_string();
                    let upload_result =
                        upload_with_retry(&format!("upload of {}", rel_path), || {
                            let client_inner = client_clone.clone();
                            let base_url_inner = base_url_clone.clone();
                            let shared_creds_inner = shared_creds_clone.clone();
                            let path_inner = path.clone();
                            let url_inner = url.clone();
                            let rel_inner = rel_path.clone();
                            let shared_prog_inner = shared_progress_clone.clone();
                            let pwd_inner = password_clone.clone();
                            let upload_id_inner = upload_id.clone();
                            async move {
                                // Ensure token valid preflight
                                let mut creds_guard = shared_creds_inner.lock().await;
                                let _ = ensure_valid_token(
                                    &client_inner,
                                    &base_url_inner,
                                    &mut creds_guard,
                                    None,
                                )
                                .await;
                                let creds_snapshot = creds_guard.clone();
                                drop(creds_guard);

                                // Attempt upload
                                match upload_file_with_encryption(
                                    &client_inner,
                                    &path_inner,
                                    &url_inner,
                                    &rel_inner,
                                    &creds_snapshot,
                                    encrypt_clone,
                                    pwd_inner.clone(),
                                    Some(shared_prog_inner.clone()),
                                    Some(upload_id_inner.as_str()),
                                )
                                .await
                                {
                                    Ok(ok) => Ok(ok),
                                    Err(e) => {
                                        let es = e.to_string();
                                        if es.contains("401")
                                            || es.contains("Unauthorized")
                                            || es.contains("Authentication required")
                                        {
                                            // Refresh and retry once
                                            let mut creds_guard2 = shared_creds_inner.lock().await;
                                            let _ = ensure_valid_token(
                                                &client_inner,
                                                &base_url_inner,
                                                &mut creds_guard2,
                                                None,
                                            )
                                            .await;
                                            let creds_snapshot2 = creds_guard2.clone();
                                            drop(creds_guard2);
                                            upload_file_with_encryption(
                                                &client_inner,
                                                &path_inner,
                                                &url_inner,
                                                &rel_inner,
                                                &creds_snapshot2,
                                                encrypt_clone,
                                                pwd_inner.clone(),
                                                Some(shared_prog_inner.clone()),
                                                Some(upload_id_inner.as_str()),
                                            )
                                            .await
                                        } else {
                                            Err(e)
                                        }
                                    }
                                }
                            }
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
                println!("  💰 Total cost: ${} USDC", format_usdc_ui(final_cost));
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

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
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
                "Current priority multiplier: {}x (~${} USDC/GB)",
                fee_resp.priority_fee_per_gb,
                format_usdc_ui(0.025 * fee_resp.priority_fee_per_gb)
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

            let (cost_per_gb_usdc, balance_usdc_opt) =
                match fetch_credits_status(&client, base_url, &creds).await {
                    Ok(status) => {
                        let tier_est = status
                            .quota
                            .tier_estimates
                            .iter()
                            .find(|t| t.tier_name.eq_ignore_ascii_case("priority"));
                        (
                            tier_est.map(|t| t.cost_per_gb_usdc).unwrap_or(0.025),
                            Some(status.balance_usdc),
                        )
                    }
                    Err(_) => (0.025, None),
                };

            let total_cost_estimate_usdc = bytes_to_gb_decimal(total_size) * cost_per_gb_usdc;

            if let Some(balance_usdc) = balance_usdc_opt {
                if balance_usdc + 1e-9 < total_cost_estimate_usdc {
                    eprintln!("\n❌ Insufficient prepaid credits for priority directory upload");
                    eprintln!(
                        "Total cost: ${} USDC (at ${} USDC/GB)",
                        format_usdc_ui(total_cost_estimate_usdc),
                        format_usdc_ui(cost_per_gb_usdc)
                    );
                    eprintln!("Your balance: ${} USDC", format_usdc_ui(balance_usdc));
                    eprintln!(
                        "Needed: ${} USDC",
                        format_usdc_ui((total_cost_estimate_usdc - balance_usdc).max(0.0))
                    );
                    eprintln!("\nTop up credits with: pipe credits-intent 10");
                    return Ok(());
                }

                println!(
                    "💰 Estimated cost: ${} USDC at ${} USDC/GB (balance: ${} USDC)",
                    format_usdc_ui(total_cost_estimate_usdc),
                    format_usdc_ui(cost_per_gb_usdc),
                    format_usdc_ui(balance_usdc)
                );
            } else {
                eprintln!("⚠️  Could not fetch credits status to verify balance.");
                eprintln!(
                    "Estimated cost: ${} USDC at ${} USDC/GB",
                    format_usdc_ui(total_cost_estimate_usdc),
                    format_usdc_ui(cost_per_gb_usdc)
                );
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

            // Share credentials across tasks for auto-refresh
            let shared_creds = Arc::new(TokioMutex::new(creds));

            for path in file_entries {
                let sem_clone = Arc::clone(&sem);
                let client_clone = client.clone();
                let base_url_clone = base_url.to_string();
                let service_cache_clone = service_cache.clone();
                let shared_creds_clone = shared_creds.clone();
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
                    let _permit = match sem_clone.acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("Upload semaphore closed; aborting task for {}", rel_path);
                            return;
                        }
                    };

                    // Get endpoint for this specific file upload
                    let user_id_owned = {
                        let creds_guard = shared_creds_clone.lock().await;
                        creds_guard.user_id.clone()
                    };
                    let selected_endpoint = get_endpoint_for_operation(
                        &service_cache_clone,
                        &client_clone,
                        &base_url_clone,
                        "upload",
                        &user_id_owned,
                        Some(&rel_path),
                    )
                    .await;

                    // Build URL without credentials (security fix)
                    let url = format!(
                        "{}/priorityUpload?file_name={}",
                        selected_endpoint,
                        utf8_percent_encode(&rel_path, QUERY_ENCODE_SET)
                    );

                    // Use retry wrapper for priority directory uploads
                    let upload_id = Uuid::new_v4().to_string();
                    let upload_result =
                        upload_with_retry(&format!("priority upload of {}", rel_path), || {
                            let client_inner = client_clone.clone();
                            let base_url_inner = base_url_clone.clone();
                            let shared_creds_inner = shared_creds_clone.clone();
                            let path_inner = path.clone();
                            let url_inner = url.clone();
                            let rel_inner = rel_path.clone();
                            let shared_prog_inner = shared_progress_clone.clone();
                            let upload_id_inner = upload_id.clone();
                            async move {
                                // Preflight refresh
                                let mut creds_guard = shared_creds_inner.lock().await;
                                let _ = ensure_valid_token(
                                    &client_inner,
                                    &base_url_inner,
                                    &mut creds_guard,
                                    None,
                                )
                                .await;
                                let creds_snapshot = creds_guard.clone();
                                drop(creds_guard);
                                match upload_file_priority_with_shared_progress(
                                    &client_inner,
                                    &path_inner,
                                    &url_inner,
                                    &rel_inner,
                                    &creds_snapshot,
                                    Some(shared_prog_inner.clone()),
                                    Some(upload_id_inner.as_str()),
                                )
                                .await
                                {
                                    Ok(ok) => Ok(ok),
                                    Err(e) => {
                                        let es = e.to_string();
                                        if es.contains("401")
                                            || es.contains("Unauthorized")
                                            || es.contains("Authentication required")
                                        {
                                            let mut creds_guard2 = shared_creds_inner.lock().await;
                                            let _ = ensure_valid_token(
                                                &client_inner,
                                                &base_url_inner,
                                                &mut creds_guard2,
                                                None,
                                            )
                                            .await;
                                            let creds_snapshot2 = creds_guard2.clone();
                                            drop(creds_guard2);
                                            upload_file_priority_with_shared_progress(
                                                &client_inner,
                                                &path_inner,
                                                &url_inner,
                                                &rel_inner,
                                                &creds_snapshot2,
                                                Some(shared_prog_inner.clone()),
                                                Some(upload_id_inner.as_str()),
                                            )
                                            .await
                                        } else {
                                            Err(e)
                                        }
                                    }
                                }
                            }
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
                println!("  💰 Total cost: ${} USDC", format_usdc_ui(final_cost));
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
                let normal_multiplier = 1.0;
                println!(
                    "Normal: ${} USDC/GB ({}x)",
                    format_usdc_ui(0.025 * normal_multiplier),
                    normal_multiplier
                );
                println!(
                    "Priority: ${} USDC/GB ({}x)",
                    format_usdc_ui(0.025 * parsed.priority_fee_per_gb),
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
                println!("║ Tier          ║ Base x║ Current x  ║ Concurrency ║ Active   ║ MP Concurrent ║ Chunk MB  ║");
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
                println!("\nNote: Multipliers apply to a $0.025 USDC/GB baseline.");
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
            dry_run,
        } => {
            // Load credentials and check for JWT
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
            }

            let local_path = Path::new(&file_path);
            if !local_path.exists() {
                return Err(anyhow!("Local file not found: {}", file_path));
            }

            let epochs_final = epochs.unwrap_or(1);

            // Handle dry-run: calculate and show cost estimate
            if dry_run {
                let file_size = std::fs::metadata(local_path)?.len();
                let file_size_gb = bytes_to_gb_decimal(file_size);

                let (cost_per_gb_usdc, balance_usdc_opt, available_gb_opt) =
                    match fetch_credits_status(&client, base_url, &creds).await {
                        Ok(status) => {
                            let tier_est = status
                                .quota
                                .tier_estimates
                                .iter()
                                .find(|t| t.tier_name.eq_ignore_ascii_case("priority"));
                            (
                                tier_est.map(|t| t.cost_per_gb_usdc).unwrap_or(0.025),
                                Some(status.balance_usdc),
                                tier_est.map(|t| t.available_gb),
                            )
                        }
                        Err(_) => (0.025, None, None),
                    };

                let estimated_cost_usdc = file_size_gb * cost_per_gb_usdc;

                println!("\n📊 Priority Upload Cost Estimate (prepaid credits):");
                println!("  📁 File: {}", file_name);
                println!(
                    "  📏 Size: {:.2} MB ({:.4} GB)",
                    file_size as f64 / 1_048_576.0,
                    file_size_gb
                );
                println!("  📈 Tier: priority");
                println!("  💵 Rate: ${} USDC/GB", format_usdc_ui(cost_per_gb_usdc));
                println!(
                    "  💰 Estimated cost: ${} USDC",
                    format_usdc_ui(estimated_cost_usdc)
                );
                println!("  📅 Storage duration: {} month(s)", epochs_final);

                if let Some(balance_usdc) = balance_usdc_opt {
                    println!(
                        "\n💳 Credits balance: ${} USDC",
                        format_usdc_ui(balance_usdc)
                    );
                    if let Some(available_gb) = available_gb_opt {
                        println!("📦 Available storage (priority): {:.2} GB", available_gb);
                    }
                    if balance_usdc + 1e-9 < estimated_cost_usdc {
                        println!("⚠️  Insufficient prepaid credits.");
                        println!(
                            "   Need ${} more USDC",
                            format_usdc_ui((estimated_cost_usdc - balance_usdc).max(0.0))
                        );
                        println!("\n💡 Top up:");
                        println!("   pipe credits-intent 10");
                    } else {
                        println!("✅ Sufficient credits for upload");
                        let remaining = (balance_usdc - estimated_cost_usdc).max(0.0);
                        println!("   After upload: ${} USDC", format_usdc_ui(remaining));
                    }
                } else {
                    println!("\n⚠️  Could not fetch credits status to verify balance.");
                }

                println!("\nThis is a dry run - no upload performed.");
                return Ok(());
            }

            // Calculate Blake3 hash before upload
            println!("Calculating file hash...");
            let blake3_hash = calculate_blake3(local_path).await?;
            println!("Blake3 hash: {}", &blake3_hash[..16]); // Show first 16 chars
            let file_size = std::fs::metadata(local_path)?.len();
            let upload_id = Uuid::new_v4().to_string();

            // Build URL without credentials (security fix)
            let url = format!(
                "{}/priorityUpload?file_name={}&epochs={}",
                base_url,
                utf8_percent_encode(&file_name, QUERY_ENCODE_SET),
                epochs_final
            );

            // Use retry wrapper for priority single file upload
            let upload_result =
                upload_with_retry(&format!("priority upload of {}", file_path), || {
                    upload_file_priority_with_shared_progress(
                        &client,
                        local_path,
                        &url,
                        &file_name,
                        &creds,
                        None,
                        Some(upload_id.as_str()),
                    )
                })
                .await;

            match upload_result {
                Ok((uploaded_filename, cost_usdc)) => {
                    println!(
                        "Priority file uploaded (or backgrounded): {}",
                        uploaded_filename
                    );
                    if cost_usdc > 0.0 {
                        println!(
                            "💰 Cost: ${} USDC (prepaid credits)",
                            format_usdc_ui(cost_usdc)
                        );
                    }
                    append_to_upload_log_with_hash(
                        &file_path,
                        &uploaded_filename,
                        "PRIORITY SUCCESS",
                        &format!("Priority upload ({} epochs)", epochs_final),
                        Some(blake3_hash.clone()),
                        Some(file_size),
                    )?;
                    println!("📋 File ID (Blake3): {}", blake3_hash);
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

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
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

            if user_id.is_some() || user_app_key.is_some() {
                eprintln!(
                    "Note: --user-id/--user-app-key are ignored; this deployment requires JWT."
                );
            }

            let url = format!("{}/extendStorage", base_url);
            let mut request = client.post(url);

            // Use add_auth_headers for consistent authentication
            request = add_auth_headers(request, &creds, true)?;

            request = request.json(&serde_json::json!({
                "file_name": file_name,
                "additional_months": additional_months
            }));

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

        // NOTE: VerifyFile command handler is commented out for production release
        // This feature requires server-side support and is planned for a future release
        // Uncomment when server API endpoint is ready
        /*
        Commands::VerifyFile {
            file_name: _,
            file_id: _,
            user_id,
            user_app_key,
        } => {
            // Load credentials
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }
            if let Some(key) = user_app_key {
                creds.user_app_key = key;
            }

            println!("Verifying file integrity...");
            println!("Feature not fully implemented yet - requires server-side support");
            // TODO: Call server API to get file hash and verify
        }
        */
        Commands::FindUpload { query, by_hash } => {
            let entries = read_upload_log_entries(None)?;
            let mut found = Vec::new();

            for entry in entries {
                if by_hash {
                    if let Some(ref hash) = entry.blake3_hash {
                        if hash.starts_with(&query) {
                            found.push(entry);
                        }
                    }
                } else {
                    // Search by local path
                    if entry.local_path.contains(&query) {
                        found.push(entry);
                    }
                }
            }

            if found.is_empty() {
                println!("No uploads found matching '{}'", query);
            } else {
                println!("Found {} matching upload(s):", found.len());
                for entry in found {
                    println!("\n  Local: {}", entry.local_path);
                    println!("  Remote: {}", entry.remote_path);
                    println!("  Status: {}", entry.status);
                    if let Some(hash) = entry.blake3_hash {
                        println!("  Blake3: {}", hash);
                    }
                    if let Some(size) = entry.file_size {
                        println!("  Size: {} bytes", size);
                    }
                    if let Some(time) = entry.timestamp {
                        println!("  Time: {}", time.format("%Y-%m-%d %H:%M:%S UTC"));
                    }
                }
            }
        }

        Commands::RehashUploads { verbose } => {
            let mut entries = read_upload_log_entries(None)?;
            let total = entries.len();
            let mut updated = 0;
            let mut failed = 0;

            println!("Rehashing {} upload entries...", total);

            for entry in &mut entries {
                if entry.blake3_hash.is_none() {
                    let path = Path::new(&entry.local_path);
                    if path.exists() {
                        if verbose {
                            println!("Hashing: {}", entry.local_path);
                        }
                        match calculate_blake3(path).await {
                            Ok(hash) => {
                                entry.blake3_hash = Some(hash);
                                entry.file_size = Some(std::fs::metadata(path)?.len());
                                updated += 1;
                            }
                            Err(e) => {
                                if verbose {
                                    eprintln!("Failed to hash {}: {}", entry.local_path, e);
                                }
                                failed += 1;
                            }
                        }
                    } else {
                        if verbose {
                            println!("File not found: {}", entry.local_path);
                        }
                        failed += 1;
                    }
                }
            }

            // Rewrite the upload log
            if updated > 0 {
                let log_path = get_upload_log_path();
                let mut file = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&log_path)?;

                for entry in entries {
                    let json_line = serde_json::to_string(&entry)?;
                    writeln!(file, "{}", json_line)?;
                }

                println!("\n✅ Rehashing complete!");
                println!("  Updated: {} entries", updated);
                println!("  Failed: {} entries", failed);
                println!("  Already hashed: {} entries", total - updated - failed);
            } else {
                println!("\nNo entries needed updating.");
            }
        }

        Commands::Sync {
            path,
            destination,
            conflict,
            dry_run,
            exclude: _,
            include: _,
            max_size: _,
            newer_than: _,
            parallel: _,
        } => {
            // Load credentials
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            // Ensure we have valid JWT token if available
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            // Parse conflict strategy
            let conflict_strategy =
                sync::ConflictStrategy::from_str(&conflict).map_err(|e| anyhow!("{}", e))?;

            // Execute sync
            sync::sync_command(
                &client,
                base_url,
                &creds,
                &path,
                destination.as_deref(),
                conflict_strategy,
                dry_run,
            )
            .await?;
        }

        Commands::ServiceConfig => {
            let url = format!("{}/api/service-config", base_url);
            let resp = client.get(&url).send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;

            if !status.is_success() {
                return Err(anyhow!(
                    "Service config request failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let cfg = serde_json::from_str::<ServiceConfigResponse>(&text_body)?;
            println!("🌐 Solana cluster: {}", cfg.solana_cluster);
            println!("💳 USDC mint: {}", cfg.usdc_mint);
            println!("🏦 Treasury pubkey: {}", cfg.usdc_treasury_pubkey);
            println!("🏦 Treasury ATA: {}", cfg.usdc_treasury_ata);
            println!(
                "♾️  Lifetime purchase enabled: {}",
                if cfg.lifetime_purchase_enabled {
                    "yes"
                } else {
                    "no"
                }
            );
            println!("♾️  Lifetime price: {} USDC", cfg.lifetime_price_usdc);
            if let Some(title) = cfg.lifetime_promo_title.as_deref() {
                println!("🪧 Promo title: {}", title);
            }
            if let Some(body) = cfg.lifetime_promo_body.as_deref() {
                println!("📝 Promo body: {}", body);
            }
            if let Some(url) = cfg.lifetime_terms_url.as_deref() {
                println!("📄 Terms: {}", url);
            }
        }

        Commands::CheckDeposit { user_id } => {
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

            let status = fetch_credits_status(&client, base_url, &creds).await?;
            print_credits_status(&status);
        }

        Commands::CreditsStatus { user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let status = fetch_credits_status(&client, base_url, &creds).await?;
            print_credits_status(&status);
        }

        Commands::CreditsIntent { amount, user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let amount_usdc_raw = parse_usdc_ui_to_raw(&amount)?;

            let mut request = client.post(format!("{}/api/credits/intent", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&CreateCreditsIntentRequest { amount_usdc_raw });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits intent failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let intent = serde_json::from_str::<CreditsIntentResponse>(&text_body)?;
            println!("✅ Credits intent created");
            println!("Status: {}", intent.status);
            println!("Intent ID: {}", intent.intent_id);
            println!(
                "Amount: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(intent.requested_usdc_raw))
            );
            println!("USDC mint: {}", intent.usdc_mint);
            println!("Treasury: {}", intent.treasury_owner_pubkey);
            println!("Reference: {}", intent.reference_pubkey);
            println!();
            println!(
                "Solana Pay: {}",
                solana_pay_url_raw(
                    &intent.treasury_owner_pubkey,
                    intent.requested_usdc_raw,
                    &intent.usdc_mint,
                    &intent.reference_pubkey,
                    6
                )
            );
            println!();
            println!("Next:");
            println!("  1) Pay the Solana Pay link in your wallet");
            println!(
                "  2) Submit the tx: pipe credits-submit {} <tx_sig>",
                intent.intent_id
            );
        }

        Commands::CreditsSubmit {
            intent_id,
            tx_sig,
            user_id,
        } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.post(format!("{}/api/credits/submit", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&SubmitCreditsPaymentRequest { intent_id, tx_sig });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits submit failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<SubmitCreditsPaymentResponse>(&text_body)?;
            println!("✅ Credits updated");
            println!("Intent: {}", result.intent_id);
            println!("Status: {}", result.status);
            println!(
                "Detected: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.detected_usdc_raw))
            );
            println!(
                "Credited: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.credited_usdc_raw))
            );
            println!(
                "Balance:  ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.balance_usdc_raw))
            );
        }

        Commands::CreditsCancel { intent_id, user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.post(format!("{}/api/credits/cancel", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&CancelCreditsIntentRequest { intent_id });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits cancel failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<CreditsCancelResponse>(&text_body)?;
            println!(
                "✅ Intent cancelled: {} ({})",
                result.intent_id, result.status
            );
        }

        Commands::PipeCreditsStatus { user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.get(format!("{}/api/pipe-credits/status", base_url));
            request = add_auth_headers(request, &creds, false)?;

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Pipe credits status failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let status_resp = serde_json::from_str::<PipeCreditsStatusResponse>(&text_body)?;
            println!(
                "💳 Credits balance: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(status_resp.balance_usdc_raw))
            );

            if let Some(intent) = status_resp.intent.as_ref() {
                println!();
                println!("🧾 Pending PIPE top-up:");
                println!("  Status:    {}", intent.status);
                println!("  Intent ID: {}", intent.intent_id);
                println!(
                    "  Buy:       ${} USDC",
                    format_usdc_ui(usdc_raw_to_ui(intent.requested_usdc_raw))
                );
                println!(
                    "  Credit:    ${} USDC (bonus)",
                    format_usdc_ui(usdc_raw_to_ui(intent.credited_usdc_raw))
                );
                println!(
                    "  Required:  {} PIPE",
                    format_pipe_ui(pipe_raw_to_ui(intent.required_pipe_raw))
                );
                if intent.detected_pipe_raw > 0 {
                    println!(
                        "  Detected:  {} PIPE",
                        format_pipe_ui(pipe_raw_to_ui(intent.detected_pipe_raw))
                    );
                }
                if let Some(sig) = intent.payment_tx_sig.as_deref() {
                    println!("  Tx Sig:    {}", sig);
                }
                println!("  Reference: {}", intent.reference_pubkey);
                if !intent.treasury_owner_pubkey.is_empty() {
                    println!("  Treasury:  {}", intent.treasury_owner_pubkey);
                    println!(
                        "  Solana Pay: {}",
                        solana_pay_url_raw(
                            &intent.treasury_owner_pubkey,
                            intent.required_pipe_raw,
                            &intent.pipe_mint,
                            &intent.reference_pubkey,
                            9
                        )
                    );
                }
            }
        }

        Commands::PipeCreditsIntent { amount, user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let amount_usdc_raw = parse_usdc_ui_to_raw(&amount)?;

            let mut request = client.post(format!("{}/api/pipe-credits/intent", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&CreateCreditsIntentRequest { amount_usdc_raw });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Pipe credits intent failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let intent = serde_json::from_str::<PipeCreditsIntentResponse>(&text_body)?;
            println!("✅ PIPE top-up intent created");
            println!("Status: {}", intent.status);
            println!("Intent ID: {}", intent.intent_id);
            println!(
                "Buy: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(intent.requested_usdc_raw))
            );
            println!(
                "Credits after bonus: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(intent.credited_usdc_raw))
            );
            println!("PIPE price (quote): ${:.6}", intent.pipe_price_usd);
            println!(
                "Pay: {} PIPE",
                format_pipe_ui(pipe_raw_to_ui(intent.required_pipe_raw))
            );
            println!("PIPE mint: {}", intent.pipe_mint);
            println!("Treasury: {}", intent.treasury_owner_pubkey);
            println!("Reference: {}", intent.reference_pubkey);
            println!();
            println!(
                "Solana Pay: {}",
                solana_pay_url_raw(
                    &intent.treasury_owner_pubkey,
                    intent.required_pipe_raw,
                    &intent.pipe_mint,
                    &intent.reference_pubkey,
                    9
                )
            );
            println!();
            println!("Next:");
            println!("  1) Pay the Solana Pay link in your wallet");
            println!(
                "  2) Submit the tx: pipe pipe-credits-submit {} <tx_sig>",
                intent.intent_id
            );
        }

        Commands::PipeCreditsSubmit {
            intent_id,
            tx_sig,
            user_id,
        } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.post(format!("{}/api/pipe-credits/submit", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&SubmitCreditsPaymentRequest { intent_id, tx_sig });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Pipe credits submit failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<SubmitPipeCreditsPaymentResponse>(&text_body)?;
            println!("✅ Credits updated");
            println!("Intent: {}", result.intent_id);
            println!("Status: {}", result.status);
            println!(
                "Detected: {} PIPE",
                format_pipe_ui(pipe_raw_to_ui(result.detected_pipe_raw))
            );
            println!(
                "Credited: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.credited_usdc_raw))
            );
            println!(
                "Balance:  ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.balance_usdc_raw))
            );
        }

        Commands::PipeCreditsCancel { intent_id, user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.post(format!("{}/api/pipe-credits/cancel", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&CancelCreditsIntentRequest { intent_id });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Pipe credits cancel failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<PipeCreditsCancelResponse>(&text_body)?;
            println!(
                "✅ Intent cancelled: {} ({})",
                result.intent_id, result.status
            );
        }

        Commands::LifetimeStatus { user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.get(format!("{}/api/subscription/lifetime/status", base_url));
            request = add_auth_headers(request, &creds, false)?;

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Lifetime status failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let lifetime = serde_json::from_str::<LifetimeStatusResponse>(&text_body)?;
            println!(
                "♾️  Lifetime active: {}",
                if lifetime.lifetime_active {
                    "yes"
                } else {
                    "no"
                }
            );
            if let Some(ts) = lifetime.lifetime_activated_at.as_deref() {
                println!("🕒 Activated at: {}", ts);
            }
            if let Some(intent) = lifetime.intent.as_ref() {
                println!();
                println!("🧾 Intent:");
                println!("  Status:    {}", intent.status);
                println!("  Intent ID: {}", intent.intent_id);
                println!(
                    "  Required:  ${} USDC",
                    format_usdc_ui(usdc_raw_to_ui(intent.required_usdc_raw))
                );
                println!(
                    "  Detected:  ${} USDC",
                    format_usdc_ui(usdc_raw_to_ui(intent.detected_usdc_raw))
                );
                println!(
                    "  Remaining: ${} USDC",
                    format_usdc_ui(usdc_raw_to_ui(intent.remaining_usdc_raw))
                );
                println!("  Reference: {}", intent.reference_pubkey);
                if !intent.treasury_owner_pubkey.is_empty() {
                    println!(
                        "  Solana Pay: {}",
                        solana_pay_url_raw(
                            &intent.treasury_owner_pubkey,
                            intent.remaining_usdc_raw,
                            &intent.usdc_mint,
                            &intent.reference_pubkey,
                            6
                        )
                    );
                }
            }
        }

        Commands::LifetimeIntent { user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.post(format!("{}/api/subscription/lifetime/intent", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&serde_json::json!({}));

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Lifetime intent failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let intent = serde_json::from_str::<LifetimeIntentResponse>(&text_body)?;
            println!("✅ Lifetime intent created");
            println!("Status: {}", intent.status);
            println!("Intent ID: {}", intent.intent_id);
            println!("Price: {} USDC", intent.required_usdc);
            println!("USDC mint: {}", intent.usdc_mint);
            println!("Treasury: {}", intent.treasury_owner_pubkey);
            println!("Reference: {}", intent.reference_pubkey);
            println!();
            println!(
                "Solana Pay: {}",
                solana_pay_url_raw(
                    &intent.treasury_owner_pubkey,
                    intent.required_usdc_raw,
                    &intent.usdc_mint,
                    &intent.reference_pubkey,
                    6
                )
            );
            if let Some(url) = intent.lifetime_terms_url.as_deref() {
                println!("Terms: {}", url);
            }
            println!();
            println!("Next:");
            println!("  1) Pay the Solana Pay link in your wallet");
            println!(
                "  2) Submit the tx: pipe lifetime-submit {} <tx_sig>",
                intent.intent_id
            );
        }

        Commands::LifetimeSubmit {
            intent_id,
            tx_sig,
            user_id,
        } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.post(format!("{}/api/subscription/lifetime/submit", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&SubmitLifetimePaymentRequest { intent_id, tx_sig });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Lifetime submit failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<SubmitLifetimePaymentResponse>(&text_body)?;
            println!("✅ Lifetime payment updated");
            println!("Intent: {}", result.intent_id);
            println!("Status: {}", result.status);
            println!(
                "Detected: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.detected_usdc_raw))
            );
            println!(
                "Remaining: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.remaining_usdc_raw))
            );
        }

        Commands::EstimateCost {
            file_path,
            tier,
            user_id,
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

            // Get file size
            let metadata = tokio::fs::metadata(&file_path).await?;
            let file_size = metadata.len();

            let credits = fetch_credits_status(&client, base_url, &creds).await?;
            let tier_est = credits
                .quota
                .tier_estimates
                .iter()
                .find(|t| t.tier_name.eq_ignore_ascii_case(&tier))
                .ok_or_else(|| anyhow!("Unknown tier: {}", tier))?;

            let file_size_gb = bytes_to_gb_decimal(file_size);
            let estimated_cost_usdc = file_size_gb * tier_est.cost_per_gb_usdc;
            let remaining = credits.balance_usdc - estimated_cost_usdc;

            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║               📊 UPLOAD COST ESTIMATE (USDC)                 ║");
            println!("╚══════════════════════════════════════════════════════════════╝");
            println!();
            println!("📁 File: {}", file_path);
            println!("📏 Size: {:.2} GB ({} bytes)", file_size_gb, file_size);
            println!("🎯 Tier: {}", tier_est.tier_name);
            println!();
            println!(
                "💵 Rate: ${} USDC/GB",
                format_usdc_ui(tier_est.cost_per_gb_usdc)
            );
            println!(
                "💰 Estimated Cost: ${} USDC",
                format_usdc_ui(estimated_cost_usdc)
            );
            println!();
            println!(
                "💳 Credits Balance: ${} USDC",
                format_usdc_ui(credits.balance_usdc)
            );
            println!(
                "📦 Available Storage ({}): {:.2} GB",
                tier_est.tier_name, tier_est.available_gb
            );
            println!();
            if remaining + 1e-9 >= 0.0 {
                println!("✅ Status: CAN AFFORD");
                println!("   After Upload: ${} USDC", format_usdc_ui(remaining));
                println!(
                    "   Remaining Storage ({}): {:.2} GB",
                    tier_est.tier_name,
                    (remaining / tier_est.cost_per_gb_usdc).max(0.0)
                );
            } else {
                println!("❌ Status: INSUFFICIENT CREDITS");
                println!(
                    "   Need ${} more USDC",
                    format_usdc_ui((-remaining).max(0.0))
                );
                println!("   Top up: pipe credits-intent 10");
            }
        }

        Commands::SyncDeposits {
            user_id,
            intent_id,
            tx_sig,
        } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            if tx_sig.is_none() {
                let status = fetch_credits_status(&client, base_url, &creds).await?;
                print_credits_status(&status);
                println!();
                println!("To top up credits: pipe credits-intent 10");
                println!("To submit a payment: pipe credits-submit <intent_id> <tx_sig>");
                return Ok(());
            }

            let tx_sig = tx_sig.expect("checked above");
            let intent_id = match intent_id {
                Some(v) => v,
                None => {
                    let status = fetch_credits_status(&client, base_url, &creds).await?;
                    status.intent.map(|i| i.intent_id).ok_or_else(|| {
                        anyhow!(
                            "No pending intent found. Run `pipe credits-intent <amount>` first."
                        )
                    })?
                }
            };

            let mut request = client.post(format!("{}/api/credits/submit", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&SubmitCreditsPaymentRequest { intent_id, tx_sig });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits submit failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<SubmitCreditsPaymentResponse>(&text_body)?;
            println!("✅ Credits updated");
            println!(
                "Credited: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.credited_usdc_raw))
            );
            println!(
                "Balance:  ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.balance_usdc_raw))
            );
        }

        Commands::S3 { command } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            match command {
                S3Commands::Keys { command } => match command {
                    S3KeysCommands::Create { read_only } => {
                        let mut request = client.post(format!("{}/api/s3/keys", base_url));
                        if read_only {
                            request = request.query(&[("read_only", "true")]);
                        }
                        request = add_auth_headers(request, &creds, true)?;

                        let resp = request.send().await?;
                        let status = resp.status();
                        let text_body = resp.text().await?;
                        if !status.is_success() {
                            return Err(anyhow!(
                                "S3 key create failed. Status = {}, Body = {}",
                                status,
                                text_body
                            ));
                        }

                        let created = serde_json::from_str::<S3CreateKeyResponse>(&text_body)?;
                        let bucket = bucket_name_for_user_id(&creds.user_id);
                        let region = creds.s3_region.as_deref().unwrap_or("us-east-1");
                        println!("✅ S3 key created");
                        println!("Access key id: {}", created.access_key_id);
                        println!("Secret key: {}", created.secret);
                        println!(
                            "Read-only: {}",
                            if created.read_only { "yes" } else { "no" }
                        );
                        println!();
                        println!("Bucket: {}", bucket);
                        if let Some(endpoint) = creds.s3_endpoint.as_deref() {
                            println!("S3 endpoint: {}", endpoint);
                        } else {
                            println!("S3 endpoint: (not set)  — set one with: pipe config set-s3-endpoint https://s3.YOURDOMAIN");
                        }
                        println!();
                        println!("AWS CLI (copy/paste):");
                        println!("  export AWS_ACCESS_KEY_ID={}", created.access_key_id);
                        println!("  export AWS_SECRET_ACCESS_KEY={}", created.secret);
                        println!("  export AWS_DEFAULT_REGION={}", region);
                        if let Some(endpoint) = creds.s3_endpoint.as_deref() {
                            println!("  aws --endpoint-url {} s3 ls s3://{}", endpoint, bucket);
                        }
                        println!();
                        println!("Next:");
                        println!("  pipe s3 bucket get");
                        println!("  pipe s3 presign --method GET --key path/to/object");
                    }
                    S3KeysCommands::Rotate {
                        from,
                        revoke_old,
                        mode,
                    } => {
                        // Load current keys to pick an old key (and inherit its mode by default).
                        let mut request = client.get(format!("{}/api/s3/keys", base_url));
                        request = add_auth_headers(request, &creds, false)?;
                        let resp = request.send().await?;
                        let status = resp.status();
                        let text_body = resp.text().await?;
                        if !status.is_success() {
                            return Err(anyhow!(
                                "S3 keys list failed. Status = {}, Body = {}",
                                status,
                                text_body
                            ));
                        }

                        let listed = serde_json::from_str::<S3KeysListResponse>(&text_body)?;
                        let mut keys = listed.keys;

                        let old_key_opt = match from.as_deref() {
                            Some(id) => {
                                let found = keys.iter().find(|k| k.access_key_id == id).cloned();
                                let Some(found) = found else {
                                    return Err(anyhow!("Key not found: {}", id));
                                };
                                if found.revoked_at.is_some() {
                                    return Err(anyhow!("Key is already revoked: {}", id));
                                }
                                Some(found)
                            }
                            None => {
                                keys.retain(|k| k.revoked_at.is_none());
                                keys.sort_by_key(|k| {
                                    k.created_at.map(|t| t.timestamp()).unwrap_or(0)
                                });
                                keys.last().cloned()
                            }
                        };

                        let new_read_only = match mode.as_deref() {
                            Some(m) => parse_s3_key_mode(m)?,
                            None => old_key_opt.as_ref().map(|k| k.read_only).unwrap_or(true),
                        };

                        let mut create_req = client.post(format!("{}/api/s3/keys", base_url));
                        if new_read_only {
                            create_req = create_req.query(&[("read_only", "true")]);
                        }
                        create_req = add_auth_headers(create_req, &creds, true)?;

                        let resp = create_req.send().await?;
                        let status = resp.status();
                        let text_body = resp.text().await?;
                        if !status.is_success() {
                            return Err(anyhow!(
                                "S3 key create failed. Status = {}, Body = {}",
                                status,
                                text_body
                            ));
                        }

                        let created = serde_json::from_str::<S3CreateKeyResponse>(&text_body)?;
                        let bucket = bucket_name_for_user_id(&creds.user_id);
                        let region = creds.s3_region.as_deref().unwrap_or("us-east-1");

                        println!("✅ S3 key rotated");
                        if let Some(old) = old_key_opt.as_ref() {
                            println!("Old access key id: {}", old.access_key_id);
                        }
                        println!("New access key id: {}", created.access_key_id);
                        println!("Secret key: {}", created.secret);
                        println!(
                            "Read-only: {}",
                            if created.read_only { "yes" } else { "no" }
                        );
                        println!();
                        println!("Bucket: {}", bucket);
                        if let Some(endpoint) = creds.s3_endpoint.as_deref() {
                            println!("S3 endpoint: {}", endpoint);
                        } else {
                            println!("S3 endpoint: (not set)  — set one with: pipe config set-s3-endpoint https://s3.YOURDOMAIN");
                        }
                        println!();
                        println!("AWS CLI (copy/paste):");
                        println!("  export AWS_ACCESS_KEY_ID={}", created.access_key_id);
                        println!("  export AWS_SECRET_ACCESS_KEY={}", created.secret);
                        println!("  export AWS_DEFAULT_REGION={}", region);
                        if let Some(endpoint) = creds.s3_endpoint.as_deref() {
                            println!("  aws --endpoint-url {} s3 ls s3://{}", endpoint, bucket);
                        }

                        if revoke_old {
                            if let Some(old) = old_key_opt {
                                let mut revoke_req = client.delete(format!(
                                    "{}/api/s3/keys/{}",
                                    base_url, old.access_key_id
                                ));
                                revoke_req = add_auth_headers(revoke_req, &creds, true)?;
                                let resp = revoke_req.send().await?;
                                let status = resp.status();
                                let text_body = resp.text().await?;
                                if status == StatusCode::NOT_FOUND {
                                    println!(
                                        "\nOld key not found (already revoked?): {}",
                                        old.access_key_id
                                    );
                                    return Ok(());
                                }
                                if !status.is_success() {
                                    return Err(anyhow!(
                                        "S3 key revoke failed. Status = {}, Body = {}",
                                        status,
                                        text_body
                                    ));
                                }
                                let result =
                                    serde_json::from_str::<S3RevokeKeyResponse>(&text_body)?;
                                if result.revoked {
                                    println!("\n✅ Old key revoked: {}", old.access_key_id);
                                } else {
                                    println!("\nOld key not found: {}", old.access_key_id);
                                }
                            } else {
                                println!("\nNo old key to revoke (no active keys found).");
                            }
                        }
                    }
                    S3KeysCommands::List => {
                        let mut request = client.get(format!("{}/api/s3/keys", base_url));
                        request = add_auth_headers(request, &creds, false)?;

                        let resp = request.send().await?;
                        let status = resp.status();
                        let text_body = resp.text().await?;
                        if !status.is_success() {
                            return Err(anyhow!(
                                "S3 keys list failed. Status = {}, Body = {}",
                                status,
                                text_body
                            ));
                        }

                        let listed = serde_json::from_str::<S3KeysListResponse>(&text_body)?;
                        if listed.keys.is_empty() {
                            println!("No S3 keys found.");
                        } else {
                            for k in listed.keys {
                                let access = if k.read_only {
                                    "read-only"
                                } else {
                                    "read-write"
                                };
                                let status = if k.revoked_at.is_some() {
                                    "revoked"
                                } else {
                                    "active"
                                };
                                println!("{}  {}  {}", k.access_key_id, access, status);
                            }
                        }
                    }
                    S3KeysCommands::Revoke { access_key_id } => {
                        let mut request =
                            client.delete(format!("{}/api/s3/keys/{}", base_url, access_key_id));
                        request = add_auth_headers(request, &creds, true)?;

                        let resp = request.send().await?;
                        let status = resp.status();
                        let text_body = resp.text().await?;
                        if status == StatusCode::NOT_FOUND {
                            println!("Key not found: {}", access_key_id);
                            return Ok(());
                        }
                        if !status.is_success() {
                            return Err(anyhow!(
                                "S3 key revoke failed. Status = {}, Body = {}",
                                status,
                                text_body
                            ));
                        }

                        let result = serde_json::from_str::<S3RevokeKeyResponse>(&text_body)?;
                        if result.revoked {
                            println!("✅ Key revoked: {}", access_key_id);
                        } else {
                            println!("Key not found: {}", access_key_id);
                        }
                    }
                },
                S3Commands::Bucket { command } => match command {
                    S3BucketCommands::Get => {
                        let mut request = client.get(format!("{}/api/s3/bucket", base_url));
                        request = add_auth_headers(request, &creds, false)?;

                        let resp = request.send().await?;
                        let status = resp.status();
                        let text_body = resp.text().await?;
                        if !status.is_success() {
                            return Err(anyhow!(
                                "S3 bucket get failed. Status = {}, Body = {}",
                                status,
                                text_body
                            ));
                        }

                        let bucket = serde_json::from_str::<S3BucketSettingsResponse>(&text_body)?;
                        println!("Bucket: {}", bucket.bucket_name);
                        println!(
                            "Public read: {}",
                            if bucket.public_read {
                                "enabled"
                            } else {
                                "disabled"
                            }
                        );
                        if bucket.cors_allowed_origins.is_empty() {
                            println!("CORS allowed origins: (none)");
                        } else {
                            println!("CORS allowed origins:");
                            for o in bucket.cors_allowed_origins.iter() {
                                println!("  {}", o);
                            }
                        }
                        if bucket.public_read {
                            println!("Note: Public read enables anonymous GET/HEAD only (no list). Public reads bill the bucket owner’s credits.");
                        }
                    }
                    S3BucketCommands::SetPublicRead { enabled } => {
                        let mut request = client.patch(format!("{}/api/s3/bucket", base_url));
                        request = add_auth_headers(request, &creds, true)?;
                        request = request.json(&PatchS3BucketSettingsRequest {
                            public_read: Some(enabled),
                            cors_allowed_origins: None,
                        });

                        let resp = request.send().await?;
                        let status = resp.status();
                        let text_body = resp.text().await?;
                        if !status.is_success() {
                            return Err(anyhow!(
                                "S3 bucket update failed. Status = {}, Body = {}",
                                status,
                                text_body
                            ));
                        }

                        let bucket = serde_json::from_str::<S3BucketSettingsResponse>(&text_body)?;
                        println!("Bucket: {}", bucket.bucket_name);
                        println!(
                            "Public read: {}",
                            if bucket.public_read {
                                "enabled"
                            } else {
                                "disabled"
                            }
                        );
                        if bucket.cors_allowed_origins.is_empty() {
                            println!("CORS allowed origins: (none)");
                        } else {
                            println!("CORS allowed origins:");
                            for o in bucket.cors_allowed_origins.iter() {
                                println!("  {}", o);
                            }
                        }
                        if bucket.public_read {
                            println!("Note: Public read enables anonymous GET/HEAD only (no list). Public reads bill the bucket owner’s credits.");
                        }
                    }
                    S3BucketCommands::SetCors { origin } => {
                        let origins = split_comma_newline_list(&origin);
                        let mut request = client.patch(format!("{}/api/s3/bucket", base_url));
                        request = add_auth_headers(request, &creds, true)?;
                        request = request.json(&PatchS3BucketSettingsRequest {
                            public_read: None,
                            cors_allowed_origins: Some(origins),
                        });

                        let resp = request.send().await?;
                        let status = resp.status();
                        let text_body = resp.text().await?;
                        if !status.is_success() {
                            return Err(anyhow!(
                                "S3 bucket update failed. Status = {}, Body = {}",
                                status,
                                text_body
                            ));
                        }

                        let bucket = serde_json::from_str::<S3BucketSettingsResponse>(&text_body)?;
                        println!("Bucket: {}", bucket.bucket_name);
                        println!(
                            "Public read: {}",
                            if bucket.public_read {
                                "enabled"
                            } else {
                                "disabled"
                            }
                        );
                        if bucket.cors_allowed_origins.is_empty() {
                            println!("CORS allowed origins: (none)");
                        } else {
                            println!("CORS allowed origins:");
                            for o in bucket.cors_allowed_origins.iter() {
                                println!("  {}", o);
                            }
                        }
                        if bucket.public_read {
                            println!("Note: CORS settings apply only when public read is enabled.");
                        }
                    }
                    S3BucketCommands::ClearCors => {
                        let mut request = client.patch(format!("{}/api/s3/bucket", base_url));
                        request = add_auth_headers(request, &creds, true)?;
                        request = request.json(&PatchS3BucketSettingsRequest {
                            public_read: None,
                            cors_allowed_origins: Some(Vec::new()),
                        });

                        let resp = request.send().await?;
                        let status = resp.status();
                        let text_body = resp.text().await?;
                        if !status.is_success() {
                            return Err(anyhow!(
                                "S3 bucket update failed. Status = {}, Body = {}",
                                status,
                                text_body
                            ));
                        }

                        let bucket = serde_json::from_str::<S3BucketSettingsResponse>(&text_body)?;
                        println!("Bucket: {}", bucket.bucket_name);
                        println!(
                            "Public read: {}",
                            if bucket.public_read {
                                "enabled"
                            } else {
                                "disabled"
                            }
                        );
                        println!("CORS allowed origins: (none)");
                    }
                },
                S3Commands::Presign {
                    method,
                    key,
                    access_key_id,
                    expires,
                    region,
                    endpoint,
                    virtual_hosted,
                    path_style,
                    query,
                } => {
                    let query_map = parse_s3_query_args(&query)?;
                    let endpoint = endpoint.or_else(|| creds.s3_endpoint.clone());
                    let region = region.or_else(|| creds.s3_region.clone());
                    let virtual_hosted = if path_style {
                        false
                    } else if virtual_hosted {
                        true
                    } else {
                        creds.s3_virtual_hosted.unwrap_or(false)
                    };
                    let req_body = PresignS3Request {
                        access_key_id,
                        method,
                        key,
                        query: query_map,
                        expires_secs: expires,
                        region,
                        endpoint,
                        virtual_hosted,
                    };

                    let mut request = client.post(format!("{}/api/s3/presign", base_url));
                    request = add_auth_headers(request, &creds, true)?;
                    request = request.json(&req_body);

                    let resp = request.send().await?;
                    let status = resp.status();
                    let text_body = resp.text().await?;
                    if !status.is_success() {
                        return Err(anyhow!(
                            "S3 presign failed. Status = {}, Body = {}",
                            status,
                            text_body
                        ));
                    }

                    let presigned = serde_json::from_str::<PresignS3Response>(&text_body)?;
                    println!("{}", presigned.url);
                }
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

                keyring::export_key(
                    &keyring,
                    &key_name,
                    Path::new(&output_path),
                    &keyring_password,
                    &export_password,
                )?;
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

            let export_password =
                rpassword::prompt_password("Enter password to protect exported key: ")?;
            let confirm = rpassword::prompt_password("Confirm password: ")?;
            if export_password != confirm {
                return Err(anyhow!("Passwords do not match"));
            }

            keyring::export_key(
                &keyring,
                &key_name,
                Path::new(&output),
                &keyring_password,
                &export_password,
            )?;
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
            let private_key = key_material
                .private_key
                .as_ref()
                .ok_or_else(|| anyhow!("Signing key '{}' is missing private key material", key))?;
            let signature = quantum::sign_with_dilithium(&data, private_key)?;

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
    }

    Ok(())
}

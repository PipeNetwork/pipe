use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::time::{SystemTime, Duration, Instant};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use reqwest::Client;
use chrono::{DateTime, Utc};
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, Mutex, Semaphore};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use blake3;

use crate::{SavedCredentials, upload_file_with_auth, improved_download_file_with_auth};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

// Same encoding set as in lib.rs
const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')     // Space
    .add(b'"')     // Quote
    .add(b'#')     // Hash (fragment identifier)
    .add(b'<')     // Less than
    .add(b'>')     // Greater than
    .add(b'?')     // Question mark (query separator)
    .add(b'`')     // Backtick
    .add(b'{')     // Left brace
    .add(b'}')     // Right brace
    .add(b'|')     // Pipe
    .add(b'\\')    // Backslash
    .add(b'^')     // Caret
    .add(b'[')     // Left bracket
    .add(b']')     // Right bracket
    .add(b'%');    // Percent (to avoid double encoding)

/// File queued for processing
#[derive(Debug, Clone)]
struct FileToProcess {
    path: PathBuf,
    relative_path: String,
    size: u64,
    modified: DateTime<Utc>,
}

/// File ready for upload
#[derive(Debug, Clone)]
struct FileToUpload {
    local_path: PathBuf,
    relative_path: String,
    size: u64,
    _hash: String,
    _modified: DateTime<Utc>,
}

/// Progress tracking for streaming sync
struct StreamingProgress {
    // Counters
    files_discovered: AtomicU64,
    files_hashed: AtomicU64,
    files_uploaded: AtomicU64,
    bytes_discovered: AtomicU64,
    bytes_hashed: AtomicU64,
    bytes_uploaded: AtomicU64,
    
    // Progress bars
    progress_bar: ProgressBar,
    
    // State management
    partial_state: Arc<Mutex<HashMap<String, FileState>>>,
    state_path: PathBuf,
    last_save: Arc<Mutex<Instant>>,
}

/// Represents a file's sync state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileState {
    pub path: String,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub hash: Option<String>, // Blake3 hash
    pub last_synced: Option<DateTime<Utc>>, // When this file was last synced
    pub sync_version: u32, // Version number for tracking changes
    pub remote_modified: Option<DateTime<Utc>>, // Remote file modification time
}

impl FileState {
    /// Check if the file has changed since last sync
    pub fn has_changed(&self, other: &FileState) -> bool {
        self.size != other.size || 
        self.modified != other.modified ||
        self.hash != other.hash
    }
}

/// Conflict resolution strategy
#[derive(Debug, Clone, Copy)]
pub enum ConflictStrategy {
    Newer,     // Keep newer file (default)
    Larger,    // Keep larger file
    Local,     // Always keep local
    Remote,    // Always keep remote
    Ask,       // Interactive prompt
}

impl ConflictStrategy {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "newer" => Some(Self::Newer),
            "larger" => Some(Self::Larger),
            "local" => Some(Self::Local),
            "remote" => Some(Self::Remote),
            "ask" => Some(Self::Ask),
            _ => None,
        }
    }
}

/// Sync operation type
#[derive(Debug)]
pub enum SyncOperation {
    Upload(PathBuf),    // File needs to be uploaded
    Download(String),   // File needs to be downloaded
    Delete(String),     // File needs to be deleted (future)
    Conflict(PathBuf, String), // Local and remote conflict
}

/// Sync state tracking
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncState {
    pub last_sync: Option<DateTime<Utc>>,
    pub files: HashMap<String, FileState>,
}

impl SyncState {
    /// Load sync state from file
    pub async fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        
        let content = fs::read_to_string(path).await?;
        let state = serde_json::from_str(&content)?;
        Ok(state)
    }
    
    /// Save sync state to file
    pub async fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        fs::write(path, content).await?;
        Ok(())
    }
    
    /// Get a summary of the sync state
    pub fn summary(&self) -> String {
        let file_count = self.files.len();
        let total_size: u64 = self.files.values().map(|f| f.size).sum();
        let last_sync_str = self.last_sync
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "never".to_string());
        
        format!(
            "Files tracked: {}, Total size: {}, Last sync: {}",
            file_count,
            format_file_size(total_size),
            last_sync_str
        )
    }
}

/// Format file size in human-readable format
fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_idx = 0;
    
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    
    format!("{:.2} {}", size, UNITS[unit_idx])
}

/// Main sync context
#[derive(Clone)]
pub struct SyncContext {
    pub client: Client,
    pub base_url: String,
    pub creds: SavedCredentials,
    pub local_path: PathBuf,
    pub remote_path: String,
    pub conflict_strategy: ConflictStrategy,
    pub dry_run: bool,
    pub state: SyncState,
}

/// Get file metadata as FileState
async fn get_file_state(path: &Path, relative_path: &str) -> Result<FileState> {
    let metadata = fs::metadata(path).await?;
    let modified = metadata.modified()?
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    
    Ok(FileState {
        path: relative_path.to_string(),
        size: metadata.len(),
        modified: DateTime::from_timestamp(modified as i64, 0)
            .unwrap_or_else(|| Utc::now()),
        hash: calculate_file_hash(path).await.ok(),
        last_synced: None,
        sync_version: 0,
        remote_modified: None,
    })
}

/// List all files in a directory recursively
pub async fn list_local_files(base_path: &Path) -> Result<HashMap<String, FileState>> {
    let mut files = HashMap::new();
    list_local_files_recursive(base_path, base_path, &mut files, None).await?;
    Ok(files)
}

/// List all files in a directory recursively with progress tracking
pub async fn list_local_files_with_progress(
    base_path: &Path, 
    pb: &ProgressBar,
    partial_state_path: &Path,
) -> Result<HashMap<String, FileState>> {
    let mut files = HashMap::new();
    
    // Load any existing partial state
    let partial_state = if partial_state_path.exists() {
        pb.set_message("Loading partial scan state...");
        match SyncState::load(partial_state_path).await {
            Ok(state) => {
                println!("  Found partial scan with {} files already processed", state.files.len());
                state.files
            }
            Err(_) => HashMap::new()
        }
    } else {
        HashMap::new()
    };
    
    // First pass: count files and total size
    pb.set_message("Counting files...");
    let (file_count, total_size) = count_files_recursive(base_path).await?;
    
    // Calculate already processed bytes
    let already_processed: u64 = partial_state.values().map(|f| f.size).sum();
    
    // Set up progress bar to track bytes instead of files
    pb.set_length(total_size);
    pb.set_position(already_processed);
    pb.set_message(format!("Building file state map ({} files, {})...", 
        file_count, format_file_size(total_size)));
    
    // Track bytes processed
    let bytes_processed = Arc::new(AtomicU64::new(already_processed));
    
    // Copy partial state into files
    files.extend(partial_state.clone());
    
    list_local_files_recursive_with_bytes(
        base_path, 
        base_path, 
        &mut files, 
        Some(pb), 
        &bytes_processed,
        &partial_state,
        partial_state_path,
    ).await?;
    
    Ok(files)
}

/// Count files and total size recursively for progress tracking
async fn count_files_recursive(path: &Path) -> Result<(u64, u64)> {
    let mut count = 0;
    let mut total_size = 0;
    let mut entries = fs::read_dir(path).await?;
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = entry.metadata().await?;
        
        if metadata.is_dir() {
            let (sub_count, sub_size) = Box::pin(count_files_recursive(&path)).await?;
            count += sub_count;
            total_size += sub_size;
        } else if metadata.is_file() {
            count += 1;
            total_size += metadata.len();
        }
    }
    
    Ok((count, total_size))
}

async fn list_local_files_recursive(
    base_path: &Path,
    current_path: &Path,
    files: &mut HashMap<String, FileState>,
    pb: Option<&ProgressBar>,
) -> Result<()> {
    let mut entries = fs::read_dir(current_path).await?;
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = entry.metadata().await?;
        
        if metadata.is_dir() {
            // Recurse into subdirectory
            Box::pin(list_local_files_recursive(base_path, &path, files, pb)).await?;
        } else if metadata.is_file() {
            // Get relative path from base
            let relative_path = path.strip_prefix(base_path)?
                .to_string_lossy()
                .replace('\\', "/"); // Normalize path separators
            
            // Update progress bar with current file
            if let Some(pb) = pb {
                let size_str = format_file_size(metadata.len());
                pb.set_message(format!("Hashing: {} ({})", relative_path, size_str));
            }
            
            let file_state = get_file_state(&path, &relative_path).await?;
            files.insert(relative_path, file_state);
            
            // Increment progress
            if let Some(pb) = pb {
                pb.inc(1);
            }
        }
    }
    
    Ok(())
}

async fn list_local_files_recursive_with_bytes(
    base_path: &Path,
    current_path: &Path,
    files: &mut HashMap<String, FileState>,
    pb: Option<&ProgressBar>,
    bytes_processed: &Arc<AtomicU64>,
    partial_state: &HashMap<String, FileState>,
    partial_state_path: &Path,
) -> Result<()> {
    let mut entries = fs::read_dir(current_path).await?;
    let mut files_since_save = 0;
    let mut bytes_since_save = 0u64;
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = entry.metadata().await?;
        
        if metadata.is_dir() {
            // Recurse into subdirectory
            Box::pin(list_local_files_recursive_with_bytes(
                base_path, &path, files, pb, bytes_processed, partial_state, partial_state_path
            )).await?;
        } else if metadata.is_file() {
            let file_size = metadata.len();
            
            // Get relative path from base
            let relative_path = path.strip_prefix(base_path)?
                .to_string_lossy()
                .replace('\\', "/"); // Normalize path separators
            
            // Check if file already processed in partial state
            if let Some(existing_state) = partial_state.get(&relative_path) {
                // Check if file hasn't changed since partial scan
                let modified = metadata.modified()?
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs();
                let current_modified = DateTime::from_timestamp(modified as i64, 0)
                    .unwrap_or_else(|| Utc::now());
                
                if existing_state.size == file_size && existing_state.modified == current_modified {
                    // File unchanged, skip hashing
                    continue;
                }
            }
            
            // Update progress bar with current file
            if let Some(pb) = pb {
                let size_str = format_file_size(file_size);
                let processed = bytes_processed.load(Ordering::Relaxed);
                let throughput = if pb.elapsed().as_secs() > 0 {
                    processed / pb.elapsed().as_secs()
                } else {
                    0
                };
                
                pb.set_message(format!("Hashing: {} ({}) | Disk read: {}/s", 
                    relative_path, 
                    size_str,
                    format_file_size(throughput)
                ));
            }
            
            let file_state = get_file_state(&path, &relative_path).await?;
            files.insert(relative_path, file_state);
            
            // Update bytes processed
            bytes_processed.fetch_add(file_size, Ordering::Relaxed);
            
            // Update progress bar with bytes
            if let Some(pb) = pb {
                pb.set_position(bytes_processed.load(Ordering::Relaxed));
            }
            
            // Track for periodic save
            files_since_save += 1;
            bytes_since_save += file_size;
            
            // Save partial state every 100 files or 1GB
            if files_since_save >= 100 || bytes_since_save >= 1_073_741_824 {
                if let Some(pb) = pb {
                    pb.set_message("Saving partial state...");
                }
                
                let partial_sync_state = SyncState {
                    last_sync: None,
                    files: files.clone(),
                };
                
                if let Err(e) = partial_sync_state.save(partial_state_path).await {
                    eprintln!("Warning: Failed to save partial state: {}", e);
                }
                
                files_since_save = 0;
                bytes_since_save = 0;
            }
        }
    }
    
    Ok(())
}

/// Calculate Blake3 hash of a file
async fn calculate_file_hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0; 64 * 1024]; // 64KB buffer for better performance
    
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    
    Ok(hasher.finalize().to_hex().to_string())
}

/// File scanner that discovers files and sends them for processing
async fn scan_files_streaming(
    base_path: &Path,
    file_tx: mpsc::Sender<FileToProcess>,
    existing_state: &HashMap<String, FileState>,
    progress: Arc<StreamingProgress>,
) -> Result<()> {
    scan_files_recursive(base_path, base_path, &file_tx, existing_state, &progress).await?;
    Ok(())
}

async fn scan_files_recursive(
    base_path: &Path,
    current_path: &Path,
    file_tx: &mpsc::Sender<FileToProcess>,
    existing_state: &HashMap<String, FileState>,
    progress: &Arc<StreamingProgress>,
) -> Result<()> {
    let mut entries = fs::read_dir(current_path).await?;
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = entry.metadata().await?;
        
        if metadata.is_dir() {
            // Recurse into subdirectory
            Box::pin(scan_files_recursive(base_path, &path, file_tx, existing_state, progress)).await?;
        } else if metadata.is_file() {
            // Skip .pipe-sync files
            if path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(".pipe-sync"))
                .unwrap_or(false) 
            {
                continue;
            }
            
            let file_size = metadata.len();
            let modified = metadata.modified()?
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs();
            let modified_dt = DateTime::from_timestamp(modified as i64, 0)
                .unwrap_or_else(|| Utc::now());
            
            // Get relative path
            let relative_path = path.strip_prefix(base_path)?
                .to_string_lossy()
                .replace('\\', "/");
            
            // Check if file needs processing
            let needs_processing = if let Some(existing) = existing_state.get(&relative_path) {
                // Check if file has changed
                existing.size != file_size || existing.modified != modified_dt
            } else {
                // New file
                true
            };
            
            if needs_processing {
                // Send file for processing
                let file = FileToProcess {
                    path: path.clone(),
                    relative_path,
                    size: file_size,
                    modified: modified_dt,
                };
                
                if file_tx.send(file).await.is_err() {
                    // Channel closed, stop scanning
                    break;
                }
                
                // Update progress
                progress.files_discovered.fetch_add(1, Ordering::Relaxed);
                progress.bytes_discovered.fetch_add(file_size, Ordering::Relaxed);
            }
        }
    }
    
    Ok(())
}

/// Hash pipeline that calculates hashes and determines which files need upload
async fn hash_pipeline(
    mut file_rx: mpsc::Receiver<FileToProcess>,
    upload_tx: mpsc::Sender<FileToUpload>,
    progress: Arc<StreamingProgress>,
    existing_state: &HashMap<String, FileState>,
) -> Result<()> {
    while let Some(file) = file_rx.recv().await {
        // Update progress bar with current file being hashed
        let _current_msg = format!("Hashing: {} ({})", 
            file.relative_path, 
            format_file_size(file.size)
        );
        
        // Calculate hash
        let hash = match calculate_file_hash(&file.path).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Failed to hash {}: {}", file.relative_path, e);
                continue;
            }
        };
        
        // Check if file needs upload
        let needs_upload = if let Some(existing) = existing_state.get(&file.relative_path) {
            // File exists in state - check if it changed
            existing.size != file.size || 
            existing.modified != file.modified ||
            existing.hash.as_ref() != Some(&hash)
        } else {
            // New file - always upload
            true
        };
        
        // Update partial state
        {
            let mut state = progress.partial_state.lock().await;
            state.insert(file.relative_path.clone(), FileState {
                path: file.relative_path.clone(),
                size: file.size,
                modified: file.modified,
                hash: Some(hash.clone()),
                last_synced: None,
                sync_version: 0,
                remote_modified: None,
            });
        }
        
        // Update progress
        progress.files_hashed.fetch_add(1, Ordering::Relaxed);
        progress.bytes_hashed.fetch_add(file.size, Ordering::Relaxed);
        
        if needs_upload {
            let upload_file = FileToUpload {
                local_path: file.path,
                relative_path: file.relative_path,
                size: file.size,
                _hash: hash,
                _modified: file.modified,
            };
            
            if upload_tx.send(upload_file).await.is_err() {
                // Upload channel closed
                break;
            }
        }
        
        // Save state periodically
        let should_save = {
            let last_save = progress.last_save.lock().await;
            last_save.elapsed() > Duration::from_secs(30)
        };
        
        if should_save {
            save_partial_state(&progress).await?;
        }
    }
    
    Ok(())
}

/// Save partial state to disk
async fn save_partial_state(progress: &Arc<StreamingProgress>) -> Result<()> {
    let state = progress.partial_state.lock().await;
    let sync_state = SyncState {
        last_sync: None,
        files: state.clone(),
    };
    
    // Save to partial state file
    let partial_path = progress.state_path.with_extension("partial");
    sync_state.save(&partial_path).await?;
    
    // Update last save time
    *progress.last_save.lock().await = Instant::now();
    
    Ok(())
}

/// Upload pipeline with concurrent workers
async fn upload_pipeline(
    upload_rx: mpsc::Receiver<FileToUpload>,
    ctx: &SyncContext,
    progress: Arc<StreamingProgress>,
    workers: usize,
) -> Result<()> {
    let semaphore = Arc::new(Semaphore::new(workers));
    let upload_rx = Arc::new(Mutex::new(upload_rx));
    
    // Spawn upload workers
    let mut handles = vec![];
    
    for _worker_id in 0..workers {
        let rx = upload_rx.clone();
        let sem = semaphore.clone();
        let progress = progress.clone();
        let client = ctx.client.clone();
        let base_url = ctx.base_url.clone();
        let creds = ctx.creds.clone();
        let remote_path = ctx.remote_path.clone();
        
        let handle = tokio::spawn(async move {
            loop {
                // Get next file to upload
                let file = {
                    let mut rx_guard = rx.lock().await;
                    rx_guard.recv().await
                };
                
                let Some(file) = file else {
                    // Channel closed, worker done
                    break;
                };
                
                // Acquire semaphore permit
                let _permit = sem.acquire().await.unwrap();
                
                // Update progress - for now just use the main progress display
                
                // Build remote path
                let remote_file_path = if remote_path.is_empty() {
                    file.relative_path.clone()
                } else {
                    format!("{}/{}", remote_path, file.relative_path)
                };
                
                // Upload file - use priorityUpload endpoint for sync
                let full_url = format!("{}/priorityUpload?file_name={}&tier=enterprise", 
                    base_url,
                    utf8_percent_encode(&remote_file_path, QUERY_ENCODE_SET)
                );
                match upload_file_with_auth(
                    &client,
                    &file.local_path,
                    &full_url,
                    &remote_file_path,
                    &creds,
                ).await {
                    Ok(_) => {
                        // Update progress
                        progress.files_uploaded.fetch_add(1, Ordering::Relaxed);
                        progress.bytes_uploaded.fetch_add(file.size, Ordering::Relaxed);
                        
                        // Update partial state with upload success
                        {
                            let mut state = progress.partial_state.lock().await;
                            if let Some(file_state) = state.get_mut(&file.relative_path) {
                                file_state.last_synced = Some(Utc::now());
                                file_state.sync_version += 1;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to upload {}: {}", file.relative_path, e);
                    }
                }
            }
            
            Ok::<(), anyhow::Error>(())
        });
        
        handles.push(handle);
    }
    
    // Wait for all workers to complete
    for handle in handles {
        handle.await??;
    }
    
    Ok(())
}

/// Create streaming progress tracker
fn create_streaming_progress(
    state_path: PathBuf,
    existing_state: HashMap<String, FileState>,
) -> Arc<StreamingProgress> {
    // Create a single progress bar
    let progress_bar = ProgressBar::new_spinner();
    progress_bar.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
    );
    progress_bar.enable_steady_tick(Duration::from_millis(100));
    
    Arc::new(StreamingProgress {
        files_discovered: AtomicU64::new(0),
        files_hashed: AtomicU64::new(0),
        files_uploaded: AtomicU64::new(0),
        bytes_discovered: AtomicU64::new(0),
        bytes_hashed: AtomicU64::new(0),
        bytes_uploaded: AtomicU64::new(0),
        progress_bar,
        partial_state: Arc::new(Mutex::new(existing_state)),
        state_path,
        last_save: Arc::new(Mutex::new(Instant::now())),
    })
}

/// Update overall progress display
async fn update_progress_display(progress: &Arc<StreamingProgress>) {
    let files_discovered = progress.files_discovered.load(Ordering::Relaxed);
    let files_hashed = progress.files_hashed.load(Ordering::Relaxed);
    let files_uploaded = progress.files_uploaded.load(Ordering::Relaxed);
    
    let bytes_discovered = progress.bytes_discovered.load(Ordering::Relaxed);
    let bytes_hashed = progress.bytes_hashed.load(Ordering::Relaxed);
    let bytes_uploaded = progress.bytes_uploaded.load(Ordering::Relaxed);
    
    let msg = format!(
        "Files: {}/{} discovered, {}/{} hashed, {} uploaded | Data: {}/{} discovered, {}/{} hashed, {} uploaded",
        files_hashed, files_discovered,
        files_hashed, files_discovered,
        files_uploaded,
        format_file_size(bytes_hashed), format_file_size(bytes_discovered),
        format_file_size(bytes_hashed), format_file_size(bytes_discovered),
        format_file_size(bytes_uploaded)
    );
    
    progress.progress_bar.set_message(msg);
}

/// Execute sync operations using streaming pipeline
async fn execute_streaming_sync(
    ctx: &SyncContext,
    _local_files: HashMap<String, FileState>,
) -> Result<()> {
    println!("\n🚀 Starting streaming sync...");
    
    // Create channels for the pipeline
    let (file_tx, file_rx) = mpsc::channel::<FileToProcess>(1000);
    let (upload_tx, upload_rx) = mpsc::channel::<FileToUpload>(100);
    
    // Create progress tracking
    let progress = create_streaming_progress(
        ctx.state.files.is_empty().then(|| ctx.local_path.join(".pipe-sync.partial"))
            .unwrap_or_else(|| ctx.local_path.join(".pipe-sync")),
        ctx.state.files.clone(),
    );
    
    // Spawn progress updater
    let progress_updater = {
        let progress = progress.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                update_progress_display(&progress).await;
            }
        })
    };
    
    // Spawn file scanner
    let scanner = {
        let base_path = ctx.local_path.clone();
        let existing_state = ctx.state.files.clone();
        let progress = progress.clone();
        
        tokio::spawn(async move {
            scan_files_streaming(&base_path, file_tx, &existing_state, progress).await
        })
    };
    
    // Spawn hash pipeline
    let hasher = {
        let existing_state = ctx.state.files.clone();
        let progress = progress.clone();
        
        tokio::spawn(async move {
            hash_pipeline(file_rx, upload_tx, progress, &existing_state).await
        })
    };
    
    // Spawn upload pipeline
    let uploader = {
        let ctx_clone = ctx.clone();
        let progress = progress.clone();
        
        tokio::spawn(async move {
            upload_pipeline(upload_rx, &ctx_clone, progress, 3).await
        })
    };
    
    // Wait for scanner to complete
    scanner.await??;
    
    // Wait for hasher to complete
    hasher.await??;
    
    // Wait for uploader to complete
    uploader.await??;
    
    // Stop progress updater
    progress_updater.abort();
    
    // Clear progress bar
    progress.progress_bar.finish_and_clear();
    
    // Final save of state
    save_partial_state(&progress).await?;
    
    // Show final stats
    let files_uploaded = progress.files_uploaded.load(Ordering::Relaxed);
    let bytes_uploaded = progress.bytes_uploaded.load(Ordering::Relaxed);
    
    println!("\n✅ Streaming sync complete!");
    println!("   Uploaded {} files ({})", files_uploaded, format_file_size(bytes_uploaded));
    
    Ok(())
}

/// List remote files for a user
pub async fn list_remote_files(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    prefix: Option<&str>,
) -> Result<HashMap<String, FileState>> {
    use crate::add_auth_headers;
    
    let mut files = HashMap::new();
    
    // Build list files request
    let url = format!("{}/listFiles", base_url);
    let mut request = client.get(&url);
    request = add_auth_headers(request, creds, true);
    
    let response = request.send().await?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Failed to list files: {}", response.status()));
    }
    
    // Parse response
    let json_response: serde_json::Value = response.json().await?;
    
    if let Some(files_array) = json_response.as_array() {
        for file_json in files_array {
            let path = file_json["file_name"].as_str().unwrap_or_default().to_string();
            
            // Filter by prefix if provided
            if let Some(prefix) = prefix {
                if !path.starts_with(prefix) {
                    continue;
                }
            }
            
            // Extract file info
            let size = file_json["size"].as_u64().unwrap_or(0);
            let uploaded_at = file_json["uploaded_at"].as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|| Utc::now());
            
            let file_state = FileState {
                path: path.clone(),
                size,
                modified: uploaded_at,
                hash: None,
                last_synced: None,
                sync_version: 0,
                remote_modified: None,
            };
            
            files.insert(path, file_state);
        }
    }
    
    Ok(files)
}

/// Compare local and remote files to determine sync operations
pub fn compare_files(
    local_files: &HashMap<String, FileState>,
    remote_files: &HashMap<String, FileState>,
    conflict_strategy: ConflictStrategy,
) -> Vec<SyncOperation> {
    let mut operations = Vec::new();
    
    // Check local files
    for (path, local_state) in local_files {
        match remote_files.get(path) {
            None => {
                // File only exists locally - upload
                operations.push(SyncOperation::Upload(PathBuf::from(path)));
            }
            Some(remote_state) => {
                // File exists both locally and remotely
                if local_state.has_changed(remote_state) {
                    match resolve_conflict(local_state, remote_state, conflict_strategy) {
                        ConflictResolution::UseLocal => {
                            operations.push(SyncOperation::Upload(PathBuf::from(path)));
                        }
                        ConflictResolution::UseRemote => {
                            operations.push(SyncOperation::Download(path.clone()));
                        }
                        ConflictResolution::Conflict => {
                            operations.push(SyncOperation::Conflict(
                                PathBuf::from(path),
                                path.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }
    
    // Check remote files not in local
    for (path, _remote_state) in remote_files {
        if !local_files.contains_key(path) {
            // File only exists remotely - download
            operations.push(SyncOperation::Download(path.clone()));
        }
    }
    
    operations
}

/// Compare files using sync state for incremental sync
pub fn compare_files_with_state(
    local_files: &HashMap<String, FileState>,
    remote_files: &HashMap<String, FileState>,
    last_sync_state: &SyncState,
    conflict_strategy: ConflictStrategy,
) -> Vec<SyncOperation> {
    let mut operations = Vec::new();
    
    // Check local files
    for (path, local_state) in local_files {
        let last_state = last_sync_state.files.get(path);
        
        match (remote_files.get(path), last_state) {
            (None, None) => {
                // New local file - upload
                operations.push(SyncOperation::Upload(PathBuf::from(path)));
            }
            (None, Some(last)) => {
                // File was synced before but now missing from remote
                // Could have been deleted remotely
                if local_state.has_changed(last) {
                    // Local file changed since last sync - conflict
                    operations.push(SyncOperation::Conflict(
                        PathBuf::from(path),
                        path.clone(),
                    ));
                } else {
                    // Local file unchanged - safe to delete
                    // For now, we don't delete, just warn
                    eprintln!("⚠️  File {} was deleted remotely", path);
                }
            }
            (Some(remote_state), None) => {
                // File exists both places but wasn't tracked before
                if local_state.has_changed(remote_state) {
                    match resolve_conflict(local_state, remote_state, conflict_strategy) {
                        ConflictResolution::UseLocal => {
                            operations.push(SyncOperation::Upload(PathBuf::from(path)));
                        }
                        ConflictResolution::UseRemote => {
                            operations.push(SyncOperation::Download(path.clone()));
                        }
                        ConflictResolution::Conflict => {
                            operations.push(SyncOperation::Conflict(
                                PathBuf::from(path),
                                path.clone(),
                            ));
                        }
                    }
                }
            }
            (Some(remote_state), Some(last)) => {
                // File tracked in all three states
                let local_changed = local_state.has_changed(last);
                let remote_changed = remote_state.has_changed(last);
                
                if local_changed && remote_changed {
                    // Both changed - conflict
                    match resolve_conflict(local_state, remote_state, conflict_strategy) {
                        ConflictResolution::UseLocal => {
                            operations.push(SyncOperation::Upload(PathBuf::from(path)));
                        }
                        ConflictResolution::UseRemote => {
                            operations.push(SyncOperation::Download(path.clone()));
                        }
                        ConflictResolution::Conflict => {
                            operations.push(SyncOperation::Conflict(
                                PathBuf::from(path),
                                path.clone(),
                            ));
                        }
                    }
                } else if local_changed {
                    // Only local changed - upload
                    operations.push(SyncOperation::Upload(PathBuf::from(path)));
                } else if remote_changed {
                    // Only remote changed - download
                    operations.push(SyncOperation::Download(path.clone()));
                }
                // If neither changed, nothing to do
            }
        }
    }
    
    // Check remote files not in local
    for (path, remote_state) in remote_files {
        if !local_files.contains_key(path) {
            if let Some(last) = last_sync_state.files.get(path) {
                // File was synced before but now missing locally
                if remote_state.has_changed(last) {
                    // Remote changed since last sync - download
                    operations.push(SyncOperation::Download(path.clone()));
                } else {
                    // Remote unchanged - was deleted locally
                    eprintln!("⚠️  File {} was deleted locally", path);
                }
            } else {
                // New remote file - download
                operations.push(SyncOperation::Download(path.clone()));
            }
        }
    }
    
    operations
}



#[derive(Debug)]
enum ConflictResolution {
    UseLocal,
    UseRemote,
    Conflict,
}

/// Resolve conflicts based on strategy
fn resolve_conflict(
    local: &FileState,
    remote: &FileState,
    strategy: ConflictStrategy,
) -> ConflictResolution {
    match strategy {
        ConflictStrategy::Newer => {
            if local.modified > remote.modified {
                ConflictResolution::UseLocal
            } else {
                ConflictResolution::UseRemote
            }
        }
        ConflictStrategy::Larger => {
            if local.size > remote.size {
                ConflictResolution::UseLocal
            } else {
                ConflictResolution::UseRemote
            }
        }
        ConflictStrategy::Local => ConflictResolution::UseLocal,
        ConflictStrategy::Remote => ConflictResolution::UseRemote,
        ConflictStrategy::Ask => ConflictResolution::Conflict,
    }
}

/// Print sync summary
pub fn print_sync_summary(operations: &[SyncOperation]) {
    let uploads = operations.iter().filter(|op| matches!(op, SyncOperation::Upload(_))).count();
    let downloads = operations.iter().filter(|op| matches!(op, SyncOperation::Download(_))).count();
    let conflicts = operations.iter().filter(|op| matches!(op, SyncOperation::Conflict(_, _))).count();
    
    println!("\n📊 Sync Summary:");
    if uploads > 0 {
        println!("  ⬆️  {} files to upload", uploads);
    }
    if downloads > 0 {
        println!("  ⬇️  {} files to download", downloads);
    }
    if conflicts > 0 {
        println!("  ⚠️  {} conflicts to resolve", conflicts);
    }
    
    if uploads == 0 && downloads == 0 && conflicts == 0 {
        println!("  ✅ Everything is in sync!");
    }
}

/// Execute sync operations
pub async fn execute_sync(
    ctx: &SyncContext,
    operations: Vec<SyncOperation>,
) -> Result<()> {
    use futures_util::stream::{self, StreamExt};
    use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
    use std::sync::Arc;
    
    if operations.is_empty() {
        return Ok(());
    }
    
    // Create progress bars
    let multi_progress = Arc::new(MultiProgress::new());
    let overall_pb = multi_progress.add(ProgressBar::new(operations.len() as u64));
    overall_pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );
    overall_pb.set_message("Syncing files...");
    
    // Process operations in parallel
    let semaphore = Arc::new(tokio::sync::Semaphore::new(ctx.state.files.len().min(10)));
    let results = stream::iter(operations)
        .map(|op| {
            let ctx = ctx;
            let semaphore = semaphore.clone();
            let multi_progress = multi_progress.clone();
            let overall_pb = overall_pb.clone();
            
            async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                let result = match op {
                    SyncOperation::Upload(local_path) => {
                        execute_upload(ctx, &local_path, &multi_progress).await
                    }
                    SyncOperation::Download(remote_path) => {
                        execute_download(ctx, &remote_path, &multi_progress).await
                    }
                    SyncOperation::Conflict(local_path, _remote_path) => {
                        // For now, skip conflicts in non-interactive mode
                        eprintln!("⚠️  Conflict: {} - skipping", local_path.display());
                        Ok(())
                    }
                    SyncOperation::Delete(_) => {
                        // Not implemented yet
                        Ok(())
                    }
                };
                
                overall_pb.inc(1);
                result
            }
        })
        .buffer_unordered(ctx.state.files.len().min(10))
        .collect::<Vec<_>>()
        .await;
    
    overall_pb.finish_with_message("Sync complete!");
    
    // Check for errors
    let errors: Vec<_> = results.into_iter().filter_map(|r| r.err()).collect();
    if !errors.is_empty() {
        eprintln!("\n❌ {} sync operations failed:", errors.len());
        for (i, e) in errors.iter().enumerate() {
            eprintln!("  {}. {}", i + 1, e);
        }
        return Err(anyhow::anyhow!("Sync completed with errors"));
    }
    
    Ok(())
}

/// Execute a single upload
async fn execute_upload(
    ctx: &SyncContext,
    local_path: &Path,
    multi_progress: &MultiProgress,
) -> Result<()> {
    let full_path = ctx.local_path.join(local_path);
    let remote_path = format!("{}/{}", ctx.remote_path.trim_end_matches('/'), local_path.display());
    
    if ctx.dry_run {
        println!("Would upload: {} → {}", full_path.display(), remote_path);
        return Ok(());
    }
    
    // Create progress bar for this file
    let file_size = fs::metadata(&full_path).await?.len();
    let pb = multi_progress.add(ProgressBar::new(file_size));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:30.cyan/blue}] {bytes}/{total_bytes} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );
    pb.set_message(format!("⬆️  {}", local_path.display()));
    
    // Upload the file - use priorityUpload endpoint
    let full_url = format!("{}/priorityUpload?file_name={}&tier=enterprise", 
        ctx.base_url,
        utf8_percent_encode(&remote_path, QUERY_ENCODE_SET)
    );
    let result = upload_file_with_auth(
        &ctx.client,
        &full_path,
        &full_url,
        &remote_path,
        &ctx.creds,
    ).await;
    
    pb.finish_and_clear();
    multi_progress.remove(&pb);
    
    match result {
        Ok(_) => {
            println!("✅ Uploaded: {}", local_path.display());
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ Failed to upload {}: {}", local_path.display(), e);
            Err(e)
        }
    }
}

/// Execute a single download  
async fn execute_download(
    ctx: &SyncContext,
    remote_path: &str,
    multi_progress: &MultiProgress,
) -> Result<()> {
    let local_path = ctx.local_path.join(remote_path);
    
    if ctx.dry_run {
        println!("Would download: {} → {}", remote_path, local_path.display());
        return Ok(());
    }
    
    // Ensure parent directory exists
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent).await?;
    }
    
    // Create progress bar
    let pb = multi_progress.add(ProgressBar::new_spinner());
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(format!("⬇️  {}", remote_path));
    
    // Download the file
    let result = improved_download_file_with_auth(
        &ctx.client,
        &ctx.base_url,
        &ctx.creds,
        remote_path,
        local_path.to_string_lossy().as_ref(),
    ).await;
    
    pb.finish_and_clear();
    multi_progress.remove(&pb);
    
    match result {
        Ok(_) => {
            println!("✅ Downloaded: {}", remote_path);
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ Failed to download {}: {}", remote_path, e);
            Err(e)
        }
    }
}

/// Main sync entry point
pub async fn sync_command(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
    path: &str,
    destination: Option<&str>,
    conflict_strategy: ConflictStrategy,
    dry_run: bool,
    _parallel: usize,
) -> Result<()> {
    println!("🔄 Starting sync...");
    
    // Determine sync direction and paths
    let (local_path, remote_path, is_upload) = if let Some(dest) = destination {
        // Explicit source and destination
        if dest.starts_with("./") || dest.starts_with("/") || !path.contains('/') {
            // path is remote, dest is local (download)
            (PathBuf::from(dest), path.to_string(), false)
        } else {
            // path is local, dest is remote (upload)
            (PathBuf::from(path), dest.to_string(), true)
        }
    } else {
        // Single path - determine direction by checking if it exists locally
        let local = PathBuf::from(path);
        if local.exists() {
            // Local path exists - upload
            (local, path.to_string(), true)
        } else {
            // Assume remote path - download to current directory
            (PathBuf::from("."), path.to_string(), false)
        }
    };
    
    // Load sync state
    let state_path = local_path.join(".pipe-sync");
    let mut state = SyncState::load(&state_path).await?;
    
    // Show sync state info if exists
    if state.files.len() > 0 || state.last_sync.is_some() {
        println!("📊 Sync state: {}", state.summary());
    }
    
    // Create sync context
    let ctx = SyncContext {
        client: client.clone(),
        base_url: base_url.to_string(),
        creds: creds.clone(),
        local_path: local_path.clone(),
        remote_path: remote_path.clone(),
        conflict_strategy,
        dry_run,
        state: state.clone(),
    };
    
    if is_upload {
        println!("📤 Upload sync: {} → {}", local_path.display(), remote_path);
    } else {
        println!("📥 Download sync: {} → {}", remote_path, local_path.display());
    }
    
    // List files
    println!("📋 Building file state map for comparison...");
    
    // For downloads, create the directory if it doesn't exist
    if !is_upload && !local_path.exists() {
        fs::create_dir_all(&local_path).await?;
    }
    
    // Check if local path exists for upload sync
    if is_upload && !local_path.exists() {
        return Err(anyhow::anyhow!("Local path does not exist: {}", local_path.display()));
    }
    
    // For now, we only support upload sync
    if !is_upload {
        return Err(anyhow::anyhow!("Download sync not yet implemented"));
    }
    
    // Execute streaming sync
    if !dry_run {
        // Use streaming sync for upload
        execute_streaming_sync(&ctx, HashMap::new()).await?;
        
        // Load the final state from partial state
        let partial_state_path = local_path.join(".pipe-sync.partial");
        if partial_state_path.exists() {
            // Move partial state to final state
            let final_state = SyncState::load(&partial_state_path).await?;
            state.files = final_state.files;
            state.last_sync = Some(Utc::now());
            state.save(&state_path).await?;
            
            // Clean up partial state
            let _ = fs::remove_file(&partial_state_path).await;
        }
        
        println!("\n✅ Sync completed successfully!");
        println!("📝 Sync state saved to: {}", state_path.display());
    } else {
        println!("Dry run mode not yet implemented for streaming sync");
    }
    
    Ok(())
} 
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use reqwest::Client;
use chrono::{DateTime, Utc};
use tokio::fs;
use tokio::io::AsyncReadExt;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use blake3;

use crate::{SavedCredentials, upload_file_with_auth, improved_download_file_with_auth};

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
    list_local_files_recursive(base_path, base_path, &mut files).await?;
    Ok(files)
}

async fn list_local_files_recursive(
    base_path: &Path,
    current_path: &Path,
    files: &mut HashMap<String, FileState>,
) -> Result<()> {
    let mut entries = fs::read_dir(current_path).await?;
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = entry.metadata().await?;
        
        if metadata.is_dir() {
            // Recurse into subdirectory
            Box::pin(list_local_files_recursive(base_path, &path, files)).await?;
        } else if metadata.is_file() {
            // Get relative path from base
            let relative_path = path.strip_prefix(base_path)?
                .to_string_lossy()
                .replace('\\', "/"); // Normalize path separators
            
            let file_state = get_file_state(&path, &relative_path).await?;
            files.insert(relative_path, file_state);
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
    
    // Upload the file
    let full_url = format!("{}/uploadFile", ctx.base_url);
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
    println!("📋 Scanning files...");
    
    // For downloads, create the directory if it doesn't exist
    if !is_upload && !local_path.exists() {
        fs::create_dir_all(&local_path).await?;
    }
    
    let local_files = if local_path.exists() {
        list_local_files(&local_path).await?
    } else {
        HashMap::new()
    };
    println!("  Found {} local files", local_files.len());
    
    // For now, assume no remote files until we have a proper list API
    let remote_files = HashMap::new();
    println!("  Remote file listing not yet implemented - will upload all files");
    
    // Compare and determine operations
    let operations = if state.files.is_empty() {
        // First sync - use simple comparison
        println!("  First sync detected - using simple comparison");
        compare_files(&local_files, &remote_files, conflict_strategy)
    } else {
        // Incremental sync - use state-aware comparison
        println!("  Using incremental sync (last sync: {})", 
            state.last_sync
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "never".to_string())
        );
        compare_files_with_state(&local_files, &remote_files, &state, conflict_strategy)
    };
    
    // Print summary
    print_sync_summary(&operations);
    
    if operations.is_empty() {
        return Ok(());
    }
    
    // Ask for confirmation if not dry run
    if !dry_run {
        print!("\nProceed with sync? [y/N] ");
        std::io::Write::flush(&mut std::io::stdout())?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Sync cancelled.");
            return Ok(());
        }
    }
    
    // Execute operations
    if !dry_run {
        execute_sync(&ctx, operations).await?;
        
        // Update sync state with current file states
        state.last_sync = Some(Utc::now());
        
        // Build new state from successfully synced files
        let mut new_files = HashMap::new();
        
        // Add all files that were successfully synced
        for (path, local_state) in &local_files {
            // Update with current state including sync time
            let mut updated_state = local_state.clone();
            updated_state.last_synced = Some(Utc::now());
            updated_state.sync_version += 1;
            new_files.insert(path.clone(), updated_state);
        }
        
        // For downloads, update with remote file states
        for (path, remote_state) in &remote_files {
            if local_files.contains_key(path) {
                // Already handled above
                continue;
            }
            let mut updated_state = remote_state.clone();
            updated_state.last_synced = Some(Utc::now());
            updated_state.sync_version += 1;
            new_files.insert(path.clone(), updated_state);
        }
        
        state.files = new_files;
        state.save(&state_path).await?;
        
        println!("\n✅ Sync completed successfully!");
        println!("📝 Sync state saved to: {}", state_path.display());
    }
    
    Ok(())
} 
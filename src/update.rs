use anyhow::{Result, anyhow};
use std::process::Command;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn update_command() -> Result<()> {
    println!("\n Updating Pipe-CLI...");

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let update_dir = format!("pipe-update-{}", timestamp);

    if Path::new(&update_dir).exists() {
        fs::remove_dir_all(&update_dir)?;
    }

    // Clone repo
    let status = Command::new("git")
        .args(&["clone", "https://github.com/PipeNetwork/pipe.git", &update_dir])
        .status()?;
    if !status.success() {
        let _ = fs::remove_dir_all(&update_dir);
        return Err(anyhow!("Failed to clone repository"));
    }

    // Re-build
    let status = Command::new("cargo")
        .args(&["install", "--path", &update_dir])
        .status()?;
    if !status.success() {
        let _ = fs::remove_dir_all(&update_dir);
        return Err(anyhow!("Failed to install new version"));
    }

    // Remove cloned repo
    if Path::new(&update_dir).exists() {
        fs::remove_dir_all(&update_dir)?;
    }

    println!("\n ✅ Pipe CLI updated successfully!");
    Ok(())
}

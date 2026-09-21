use crate::error::ensure_https;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_PROFILE: &str = "default";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Profile {
    pub control_api_url: String,
    #[serde(default)]
    pub s3_endpoint: Option<String>,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
}

fn default_region() -> String {
    "us-east-1".into()
}

impl Profile {
    pub fn new(control_api_url: impl Into<String>) -> Self {
        Self {
            control_api_url: control_api_url.into(),
            region: default_region(),
            ..Self::default()
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure_https(&self.control_api_url, "control_api_url")?;
        if let Some(url) = &self.s3_endpoint {
            ensure_https(url, "s3_endpoint")?;
            if reqwest::Url::parse(url)?.path() != "/" {
                return Err(anyhow!(
                    "s3_endpoint must be an origin without a path prefix"
                ));
            }
        }
        if self.region.is_empty()
            || self.region.len() > 64
            || !self
                .region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(anyhow!(
                "region must contain only ASCII letters, digits, and hyphens"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(default = "legacy_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub active_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

fn legacy_version() -> u32 {
    1
}
impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            schema_version: 2,
            active_profile: None,
            profiles: BTreeMap::new(),
        }
    }
}

pub struct ConfigStore {
    pub path: PathBuf,
    pub file: ConfigFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigBackup {
    format: String,
    version: u32,
    config: ConfigFile,
    config_sha256: String,
}

impl ConfigStore {
    pub fn path(explicit: Option<&str>) -> PathBuf {
        let path = explicit.map(PathBuf::from).unwrap_or_else(|| {
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("pipe")
                .join("config.json")
        });
        if path.is_absolute() {
            path
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        }
    }
    pub fn load(explicit: Option<&str>) -> Result<Self> {
        let path = Self::path(explicit);
        if !path.exists() {
            let mut file = ConfigFile::default();
            file.profiles
                .insert(DEFAULT_PROFILE.into(), Profile::new(default_api_url()));
            file.active_profile = Some(DEFAULT_PROFILE.into());
            return Ok(Self { path, file });
        }
        let data = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let file: ConfigFile = serde_json::from_str(&data).context("parse Pipe configuration")?;
        anyhow::ensure!(
            file.schema_version <= 2 && file.schema_version > 0,
            "unsupported configuration version; original file was preserved"
        );
        Ok(Self { path, file })
    }
    pub fn active_name(&self, requested: Option<&str>) -> String {
        requested
            .map(str::to_owned)
            .or_else(|| self.file.active_profile.clone())
            .unwrap_or_else(|| DEFAULT_PROFILE.into())
    }
    pub fn profile(&self, requested: Option<&str>) -> Result<(String, Profile)> {
        let name = self.active_name(requested);
        let profile = self
            .file
            .profiles
            .get(&name)
            .cloned()
            .ok_or_else(|| anyhow!("profile '{name}' does not exist"))?;
        profile.validate()?;
        Ok((name, profile))
    }
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = self.file.clone();
        file.schema_version = 2;
        if self.path.exists() && self.file.schema_version < 2 {
            let backup = self
                .path
                .with_extension(format!("backup-{}", uuid::Uuid::new_v4()));
            crate::keyring::atomic_private_write(&backup, &fs::read(&self.path)?)?;
        }
        let data = serde_json::to_vec_pretty(&file)?;
        crate::keyring::atomic_private_write(&self.path, &data)
    }
    /// Back up configuration only. Payment/transfer journals and secret stores
    /// are intentionally never restored to an earlier revision by rollback.
    pub fn backup(&self, destination: &Path) -> Result<()> {
        anyhow::ensure!(!destination.exists(), "backup destination already exists");
        for profile in self.file.profiles.values() {
            profile.validate()?;
        }
        let data = serde_json::to_vec(&self.file)?;
        let backup = ConfigBackup {
            format: "pipe-config-backup".into(),
            version: 1,
            config: self.file.clone(),
            config_sha256: crate::sigv4::sha256_hex(&data),
        };
        crate::keyring::atomic_private_write(destination, &serde_json::to_vec_pretty(&backup)?)
    }
    pub fn rollback(&mut self, backup: &Path) -> Result<PathBuf> {
        use std::io::Read;
        let mut bytes = Vec::new();
        fs::File::open(backup)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= 1024 * 1024,
            "configuration backup exceeds the size limit"
        );
        let restored: ConfigBackup = serde_json::from_slice(&bytes)
            .context("invalid configuration backup; current state preserved")?;
        anyhow::ensure!(
            restored.format == "pipe-config-backup"
                && restored.version == 1
                && (1..=2).contains(&restored.config.schema_version),
            "unsupported configuration backup; current state preserved"
        );
        anyhow::ensure!(
            crate::sigv4::sha256_hex(&serde_json::to_vec(&restored.config)?)
                == restored.config_sha256,
            "configuration backup checksum mismatch; current state preserved"
        );
        for profile in restored.config.profiles.values() {
            profile.validate()?;
        }
        anyhow::ensure!(
            restored
                .config
                .active_profile
                .as_ref()
                .is_none_or(|p| restored.config.profiles.contains_key(p)),
            "backup selects a missing profile"
        );
        let previous = self
            .path
            .with_extension(format!("before-rollback-{}.json", uuid::Uuid::new_v4()));
        self.backup(&previous)?;
        crate::keyring::atomic_private_write(
            &self.path,
            &serde_json::to_vec_pretty(&restored.config)?,
        )?;
        self.file = restored.config;
        Ok(previous)
    }
    pub fn migrate_legacy(&mut self, legacy: &Path) -> Result<PathBuf> {
        if !legacy.exists() {
            return Err(anyhow!(
                "legacy configuration {} was not found",
                legacy.display()
            ));
        }
        let backup = legacy.with_extension(format!(
            "backup-{}-{}",
            chrono::Utc::now().format("%Y%m%d%H%M%S"),
            uuid::Uuid::new_v4()
        ));
        let original = fs::read(legacy)?;
        let value: serde_json::Value = serde_json::from_slice(&original)?;
        crate::keyring::atomic_private_write(&backup, &original)?;
        let api = value
            .get("control_api_url")
            .and_then(|v| v.as_str())
            .unwrap_or(default_api_url());
        let mut profile = Profile::new(api);
        profile.s3_endpoint = value
            .get("s3_endpoint")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        profile.bucket = value
            .get("bucket")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        profile.prefix = value
            .get("prefix")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        profile.validate()?;
        let name = self.active_name(None);
        self.file.profiles.insert(name, profile);
        self.save()?;
        Ok(backup)
    }
}

pub fn default_api_url() -> &'static str {
    "https://api.pipedev.network/control-api"
}

#[cfg(test)]
mod rollback_tests {
    use super::*;
    #[test]
    fn rollback_restores_explicit_endpoints_and_preserves_new_recovery_state() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let mut store = ConfigStore::load(path.to_str()).unwrap();
        store
            .file
            .profiles
            .get_mut("default")
            .unwrap()
            .control_api_url = "https://compat.example/control-api".into();
        store.save().unwrap();
        let backup = root.path().join("saved.json");
        store.backup(&backup).unwrap();
        let journals = root.path().join("customer-state-v1.enc");
        let recovery = b"newer unresolved request must survive rollback";
        fs::write(&journals, recovery).unwrap();
        store
            .file
            .profiles
            .get_mut("default")
            .unwrap()
            .control_api_url = "https://new.example/control-api".into();
        store.save().unwrap();
        let previous = store.rollback(&backup).unwrap();
        assert_eq!(
            store.file.profiles["default"].control_api_url,
            "https://compat.example/control-api"
        );
        assert_eq!(fs::read(&journals).unwrap(), recovery);
        store.rollback(&previous).unwrap();
        assert_eq!(
            store.file.profiles["default"].control_api_url,
            "https://new.example/control-api"
        );
        let before = fs::read(&path).unwrap();
        let mut corrupt: serde_json::Value =
            serde_json::from_slice(&fs::read(&backup).unwrap()).unwrap();
        corrupt["config"]["profiles"]["default"]["control_api_url"] =
            serde_json::json!("https://different.example");
        fs::write(&backup, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(store.rollback(&backup).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::read(&journals).unwrap(), recovery);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(previous).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

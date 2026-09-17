use anyhow::{anyhow, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SERVICE: &str = "pipe-cli-v2";

#[derive(Default, Serialize, Deserialize)]
struct FallbackFile {
    secrets: BTreeMap<String, String>,
}

#[derive(Clone)]
enum CachedSecret {
    Value(Option<String>),
    Error(String),
}

pub struct SecretStore {
    profile: String,
    fallback: PathBuf,
    directory: PathBuf,
    native: bool,
    cache: Mutex<BTreeMap<String, CachedSecret>>,
    native_error: Mutex<Option<String>>,
}

impl SecretStore {
    pub fn new(profile: impl Into<String>) -> Self {
        let profile = profile.into();
        let root = std::env::var_os("PIPE_CLI_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("pipe")
            });
        Self::at(
            root,
            profile,
            std::env::var_os("PIPE_DISABLE_KEYRING").is_none(),
        )
    }
    pub fn at(root: PathBuf, profile: String, native: bool) -> Self {
        let namespace = crate::sigv4::sha256_hex(profile.as_bytes());
        Self {
            profile,
            fallback: root.join("secrets.json"),
            directory: root.join("state").join(namespace),
            native,
            cache: Mutex::new(BTreeMap::new()),
            native_error: Mutex::new(None),
        }
    }
    pub fn state_directory(&self) -> &Path {
        &self.directory
    }
    pub fn command_lock(&self) -> Result<File> {
        fs::create_dir_all(&self.directory)?;
        let file = private_open(&self.directory.join("command.lock"))?;
        file.try_lock_exclusive()
            .context("another command is using this profile; retry when it finishes")?;
        Ok(file)
    }
    fn name(&self, key: &str) -> String {
        format!("{}:{key}", self.profile)
    }
    fn entry(&self, key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, &self.name(key)).map_err(|_| anyhow!("OS keyring unavailable"))
    }

    fn cached(&self, key: &str) -> Result<Option<CachedSecret>> {
        self.cache
            .lock()
            .map_err(|_| anyhow!("secret cache unavailable"))
            .map(|cache| cache.get(key).cloned())
    }

    fn cache_value(&self, key: &str, value: Option<String>) -> Result<()> {
        self.cache
            .lock()
            .map_err(|_| anyhow!("secret cache unavailable"))?
            .insert(key.to_owned(), CachedSecret::Value(value));
        Ok(())
    }

    fn cache_error(&self, key: &str, message: String) -> Result<()> {
        self.cache
            .lock()
            .map_err(|_| anyhow!("secret cache unavailable"))?
            .insert(key.to_owned(), CachedSecret::Error(message));
        Ok(())
    }

    fn native_failure(&self, operation: &str, error: &keyring::Error) -> String {
        let message = format!(
            "OS keychain access failed while {operation} Pipe CLI credentials ({error}); unlock the keychain item once and retry, or explicitly select encrypted fallback with PIPE_DISABLE_KEYRING=1 and PIPE_CLI_SECRET_PASSWORD"
        );
        if let Ok(mut failure) = self.native_error.lock() {
            if failure.is_none() {
                *failure = Some(message.clone());
            }
            return failure.clone().unwrap_or(message);
        }
        message
    }

    fn native_failure_message(&self) -> Option<String> {
        self.native_error
            .lock()
            .ok()
            .and_then(|failure| failure.clone())
    }

    pub fn get(&self, key: &str) -> Result<Option<String>> {
        if let Some(cached) = self.cached(key)? {
            return match cached {
                CachedSecret::Value(value) => Ok(value),
                CachedSecret::Error(message) => Err(anyhow!(message)),
            };
        }
        // A fallback record may be newer than a keyring entry whose update failed.
        if let Some(value) = self.load_fallback()?.secrets.get(&self.name(key)).cloned() {
            self.cache_value(key, Some(value.clone()))?;
            return Ok(Some(value));
        }
        if self.native {
            if let Some(message) = self.native_failure_message() {
                self.cache_error(key, message.clone())?;
                return Err(anyhow!(message));
            }
            let entry = match self.entry(key) {
                Ok(entry) => entry,
                Err(error) => {
                    let message = error.to_string();
                    self.cache_error(key, message.clone())?;
                    return Err(anyhow!(message));
                }
            };
            match entry.get_password() {
                Ok(value) => {
                    self.cache_value(key, Some(value.clone()))?;
                    return Ok(Some(value));
                }
                Err(keyring::Error::NoEntry) => {
                    self.cache_value(key, None)?;
                    return Ok(None);
                }
                Err(error) => {
                    let message = self.native_failure("reading", &error);
                    self.cache_error(key, message.clone())?;
                    return Err(anyhow!(message));
                }
            }
        }
        self.cache_value(key, None)?;
        Ok(None)
    }
    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        if let Some(cached) = self.cached(key)? {
            match cached {
                CachedSecret::Value(Some(existing)) if existing == value => return Ok(()),
                CachedSecret::Error(message) => {
                    if self.password().is_none() {
                        return Err(anyhow!(message));
                    }
                }
                CachedSecret::Value(_) => {}
            }
        }
        if self.native && self.native_failure_message().is_none() {
            let entry = match self.entry(key) {
                Ok(entry) => entry,
                Err(error) => {
                    let message = error.to_string();
                    self.cache_error(key, message.clone())?;
                    return if self.password().is_none() {
                        Err(anyhow!(message))
                    } else {
                        self.update_fallback(key, Some(value))?;
                        self.cache_value(key, Some(value.to_owned()))
                    };
                }
            };
            match entry.set_password(value) {
                Ok(()) => {
                    if self.fallback.exists() {
                        self.update_fallback(key, None)?;
                    }
                    self.cache_value(key, Some(value.to_owned()))?;
                    return Ok(());
                }
                Err(error) => {
                    let message = self.native_failure("saving", &error);
                    self.cache_error(key, message.clone())?;
                    if self.password().is_none() {
                        return Err(anyhow!(message));
                    }
                }
            }
        }
        if self.password().is_none() {
            if let Some(message) = self.native_failure_message() {
                return Err(anyhow!(message));
            }
            return Err(anyhow!("OS keyring unavailable; explicitly select encrypted fallback with PIPE_CLI_SECRET_PASSWORD before saving credentials"));
        }
        self.update_fallback(key, Some(value))?;
        self.cache_value(key, Some(value.to_owned()))
    }
    pub fn delete(&self, key: &str) -> Result<()> {
        let already_missing = matches!(self.cached(key)?, Some(CachedSecret::Value(None)));
        if self.native && !already_missing {
            if let Some(message) = self.native_failure_message() {
                if !self.fallback.exists() {
                    return Err(anyhow!(message));
                }
            } else {
                let entry = self
                    .entry(key)
                    .map_err(|error| anyhow!(error.to_string()))?;
                match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => {}
                    Err(error) => {
                        let message = self.native_failure("removing", &error);
                        if !self.fallback.exists() {
                            return Err(anyhow!(message));
                        }
                    }
                }
            }
        }
        if self.fallback.exists() {
            self.update_fallback(key, None)?;
        }
        self.cache_value(key, None)?;
        Ok(())
    }
    fn password(&self) -> Option<zeroize::Zeroizing<String>> {
        std::env::var("PIPE_CLI_SECRET_PASSWORD")
            .ok()
            .filter(|s| s.len() >= 12)
            .map(zeroize::Zeroizing::new)
            .or_else(|| {
                #[cfg(test)]
                {
                    Some(zeroize::Zeroizing::new(
                        "unit-test-only-fallback-password".into(),
                    ))
                }
                #[cfg(not(test))]
                {
                    None
                }
            })
    }
    fn warn() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            eprintln!("warning: OS keyring unavailable; reading a legacy secret file; select encrypted fallback to migrate it")
        });
    }
    fn load_fallback(&self) -> Result<FallbackFile> {
        if !self.fallback.exists() {
            return Ok(FallbackFile::default());
        }
        let metadata = fs::symlink_metadata(&self.fallback)?;
        if !metadata.is_file() {
            return Err(anyhow!("secret file must be a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(anyhow!("secret file permissions must be 0600"));
            }
        }
        let bytes = zeroize::Zeroizing::new(fs::read(&self.fallback)?);
        let clear = if bytes.starts_with(b"PIPESEC3") {
            crate::secretbox::open(
                &bytes,
                &self.password().ok_or_else(|| {
                    anyhow!("PIPE_CLI_SECRET_PASSWORD is required for encrypted secret storage")
                })?,
            )?
        } else {
            Self::warn();
            bytes.to_vec()
        };
        let clear = zeroize::Zeroizing::new(clear);
        serde_json::from_slice(&clear).context("invalid secret file")
    }
    fn update_fallback(&self, key: &str, value: Option<&str>) -> Result<()> {
        let parent = self.fallback.parent().context("missing secret directory")?;
        fs::create_dir_all(parent)?;
        let lock = private_open(&parent.join("secrets.lock"))?;
        lock.lock_exclusive()?;
        let mut file = self.load_fallback()?;
        match value {
            Some(value) => {
                file.secrets.insert(self.name(key), value.to_owned());
            }
            None => {
                file.secrets.remove(&self.name(key));
            }
        }
        let data = zeroize::Zeroizing::new(serde_json::to_vec(&file)?);
        let password = self
            .password()
            .ok_or_else(|| anyhow!("explicit encrypted fallback password required"))?;
        let sealed = crate::secretbox::seal(&data, &password)?;
        if self.fallback.exists() && !fs::read(&self.fallback)?.starts_with(b"PIPESEC3") {
            let backup = self
                .fallback
                .with_extension(format!("backup-{}", uuid::Uuid::new_v4()));
            atomic_private_write(&backup, &fs::read(&self.fallback)?)?;
        }
        atomic_private_write(&self.fallback, &sealed)
    }
}

fn private_open(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

pub fn atomic_private_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(data)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fallback_roundtrip_is_private_and_isolates_profiles() {
        let root = tempfile::tempdir().unwrap();
        let a = SecretStore::at(root.path().into(), "a".into(), false);
        let b = SecretStore::at(root.path().into(), "b".into(), false);
        a.set("token", "test-token").unwrap();
        assert_eq!(a.get("token").unwrap().as_deref(), Some("test-token"));
        assert!(b.get("token").unwrap().is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&a.fallback).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        a.delete("token").unwrap();
        assert!(a.get("token").unwrap().is_none());
    }

    #[test]
    fn cached_values_survive_backing_file_changes_until_deleted() {
        let root = tempfile::tempdir().unwrap();
        let store = SecretStore::at(root.path().into(), "cache".into(), false);
        store.set("token", "cached-token").unwrap();
        assert_eq!(store.get("token").unwrap().as_deref(), Some("cached-token"));

        fs::remove_file(&store.fallback).unwrap();
        assert_eq!(store.get("token").unwrap().as_deref(), Some("cached-token"));

        store.delete("token").unwrap();
        assert!(store.get("token").unwrap().is_none());
    }
}

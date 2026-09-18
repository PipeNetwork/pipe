use crate::s3::{ObjectInfo, S3Client, S3Error};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use walkdir::WalkDir;

#[derive(Serialize, Deserialize)]
struct Observation {
    digest: String,
    etag: String,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    scope: String,
    files: BTreeMap<String, Observation>,
}

struct State {
    path: PathBuf,
    manifest: Manifest,
}

impl State {
    fn open(
        state_dir: &Path,
        root: &Path,
        bucket: &str,
        prefix: &str,
        endpoint: &str,
    ) -> Result<Self> {
        // Reject non-Unicode roots rather than creating a lossy identity.
        let scope = blake3::hash(&serde_json::to_vec(&(root, bucket, prefix, endpoint))?)
            .to_hex()
            .to_string();
        let path = checked_directory(state_dir, true)?.join(format!("sync-{scope}.json"));
        let manifest = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    bail!("sync manifest must be a regular file");
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o077 != 0 {
                        bail!("sync manifest must be private (0600)");
                    }
                }
                let manifest: Manifest =
                    serde_json::from_slice(&fs::read(&path)?).context("invalid sync manifest")?;
                if manifest.version != 1 || manifest.scope != scope {
                    bail!("sync manifest version or scope mismatch");
                }
                manifest
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Manifest {
                version: 1,
                scope,
                files: BTreeMap::new(),
            },
            Err(error) => return Err(error.into()),
        };
        Ok(Self { path, manifest })
    }

    fn unchanged(&self, key: &str, digest: Option<&str>, remote: Option<&ObjectInfo>) -> bool {
        let Some(previous) = self.manifest.files.get(key) else {
            return false;
        };
        digest == Some(previous.digest.as_str())
            && remote.and_then(|object| object.etag.as_deref()) == Some(previous.etag.as_str())
    }

    fn observe(&mut self, key: &str, digest: String, etag: Option<String>) -> Result<()> {
        // No ETag means no safe skip. Never infer one from content or LIST.
        if let Some(etag) = etag.filter(|etag| !etag.is_empty()) {
            self.manifest
                .files
                .insert(key.into(), Observation { digest, etag });
        } else {
            self.manifest.files.remove(key);
        }
        crate::keyring::atomic_private_write(&self.path, &serde_json::to_vec(&self.manifest)?)
    }
}

/// Copy every regular file; retained for the directory-upload aliases.
pub async fn upload_directory(
    client: &S3Client,
    local: &Path,
    bucket: &str,
    prefix: &str,
) -> Result<u64> {
    upload(client, local, bucket, prefix, None).await
}

/// Return the number of files transferred, excluding unchanged files.
pub async fn sync_upload(
    client: &S3Client,
    local: &Path,
    bucket: &str,
    prefix: &str,
    state_dir: &Path,
) -> Result<u64> {
    upload(client, local, bucket, prefix, Some(state_dir)).await
}

async fn upload(
    client: &S3Client,
    local: &Path,
    bucket: &str,
    prefix: &str,
    state_dir: Option<&Path>,
) -> Result<u64> {
    let root = checked_directory(local, false)?;
    let prefix = normalized_prefix(prefix)?;
    let show_progress = client.progress_enabled();
    // Directory sync follows the AWS CLI's per-object output. The S3 client's
    // byte progress bar is useful for a single copy, but becomes a giant line
    // of blocks when it is recreated for every object in a sync.
    let transfer_client = client.clone().with_progress(false);
    let mut state = state_dir
        .map(|dir| State::open(dir, &root, bucket, prefix, &client.endpoint_identity()))
        .transpose()?;
    let observer = client.clone().with_conditions(None, None)?;
    let mut count = 0;
    let excluded_state = state_dir
        .map(|dir| checked_directory(dir, true))
        .transpose()?;
    if excluded_state
        .as_ref()
        .is_some_and(|dir| root.starts_with(dir))
    {
        bail!("upload source must not be inside the sync state directory");
    }
    for entry in WalkDir::new(&root)
        .follow_links(false)
        .follow_root_links(false)
        .into_iter()
        .filter_entry(|entry| {
            !excluded_state
                .as_ref()
                .is_some_and(|dir| entry.path().starts_with(dir))
                && !entry.file_name().to_str().is_some_and(|name| {
                    name.starts_with(".pipe-upload-") && name.ends_with(".json")
                })
        })
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(&root)?;
        let relative = relative
            .iter()
            .map(|part| part.to_str().context("non-Unicode upload filename"))
            .collect::<Result<Vec<_>>>()?
            .join("/");
        validate_relative(&relative)?;
        let key = join_key(prefix, &relative);
        let path = safe_join(&root, &relative)?;
        let parent = checked_directory(path.parent().context("missing file parent")?, false)?;
        let source = Destination::open(&parent, path.file_name().context("missing filename")?)?;
        let path = source.path.as_path();
        regular_file(path)?;
        if let Some(state) = state.as_ref() {
            let digest = digest_file(path).await?;
            let remote = head_if_present(&observer, bucket, &key).await?;
            if state.unchanged(&key, Some(&digest), remote.as_ref()) {
                continue;
            }
        }
        // Hash exactly the bytes handed to put_file even if the source changes.
        let (snapshot, digest) = snapshot_file(path).await?;
        if let Some(state) = state.as_mut() {
            // Only the actual write/completion response binds this snapshot
            // to an ETag. A later HEAD could observe a concurrent writer.
            let etag = transfer_client
                .put_file_observed(bucket, &key, snapshot.path(), None)
                .await?;
            state.observe(&key, digest, etag)?;
        } else {
            transfer_client
                .put_file(bucket, &key, snapshot.path(), None)
                .await?;
        }
        if show_progress {
            eprintln!("upload: ./{} to s3://{}/{}", relative, bucket, key);
        }
        count += 1;
    }
    Ok(count)
}

/// Copy every listed file; retained for the directory-download aliases.
pub async fn download_directory(
    client: &S3Client,
    bucket: &str,
    prefix: &str,
    local: &Path,
) -> Result<u64> {
    download(client, bucket, prefix, local, None).await
}

/// Return the number of files transferred. Neither direction deletes data.
pub async fn sync_download(
    client: &S3Client,
    bucket: &str,
    prefix: &str,
    local: &Path,
    state_dir: &Path,
) -> Result<u64> {
    download(client, bucket, prefix, local, Some(state_dir)).await
}

async fn download(
    client: &S3Client,
    bucket: &str,
    prefix: &str,
    local: &Path,
    state_dir: Option<&Path>,
) -> Result<u64> {
    let prefix = normalized_prefix(prefix)?;
    let root = checked_directory(local, true)?;
    let show_progress = client.progress_enabled();
    // Keep sync output to one AWS-style line per completed object instead of
    // rendering a separate byte bar for every download.
    let transfer_client = client.clone().with_progress(false);
    let mut state = state_dir
        .map(|dir| State::open(dir, &root, bucket, prefix, &client.endpoint_identity()))
        .transpose()?;
    let listing_prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}/")
    };
    let mut token = None;
    let mut seen_tokens = HashSet::new();
    let mut count = 0;
    loop {
        let (items, next) = client
            .list_objects(bucket, Some(&listing_prefix), token.as_deref())
            .await?;
        if let Some(next) = next.as_ref() {
            if next.is_empty() || !seen_tokens.insert(next.clone()) {
                bail!("object listing repeated a continuation token");
            }
        }
        for item in items {
            let Some(relative) = relative_key(prefix, &item.key)? else {
                continue;
            };
            let path = safe_join(&root, relative)?;
            let parent =
                checked_directory(path.parent().context("missing destination parent")?, true)?;
            let destination =
                Destination::open(&parent, path.file_name().context("missing filename")?)?;
            let exists = regular_file(&destination.path)?;
            let before = if let Some(state) = state.as_ref() {
                let digest = if exists {
                    Some(digest_file(&destination.path).await?)
                } else {
                    None
                };
                let Some(remote) = head_if_present(client, bucket, &item.key).await? else {
                    // The object disappeared after listing. Preserve local data.
                    continue;
                };
                if state.unchanged(&item.key, digest.as_deref(), Some(&remote)) {
                    continue;
                }
                Some(remote)
            } else {
                None
            };
            // The nested downloader atomically replaces this pathname. Keep
            // its cleanup guard, but close the placeholder handle so Windows
            // can replace the file.
            let staging = tempfile::NamedTempFile::new_in(&destination.parent)?.into_temp_path();
            let reader = download_client(
                &transfer_client,
                before.as_ref().and_then(|object| object.etag.as_deref()),
            )?;
            reader
                .get_to_file(bucket, &item.key, &staging, None)
                .await?;
            let digest = if state.is_some() {
                Some(digest_file(&staging).await?)
            } else {
                None
            };
            let after = if state.is_some() {
                let remote = client.head_object(bucket, &item.key).await?;
                if before.as_ref().and_then(|object| object.etag.as_ref()) != remote.etag.as_ref() {
                    bail!("remote object changed during download: {}", item.key);
                }
                Some(remote)
            } else {
                None
            };
            // Failed/interrupted downloads preserve the destination. Recheck
            // paths after the await before atomically committing the result.
            checked_directory(&parent, false)?;
            regular_file(&destination.path)?;
            // Flush the downloaded file now occupying the staging pathname.
            fs::OpenOptions::new()
                .write(true)
                .open(&staging)?
                .sync_all()?;
            staging
                .persist(&destination.path)
                .context("commit directory download")?;
            #[cfg(unix)]
            File::open(&destination.parent)?.sync_all()?;
            if let Some(state) = state.as_mut() {
                state.observe(
                    &item.key,
                    digest.context("missing download digest")?,
                    after.and_then(|object| object.etag),
                )?;
            }
            if show_progress {
                eprintln!("download: s3://{}/{} to ./{}", bucket, item.key, relative);
            }
            count += 1;
        }
        token = next;
        if token.is_none() {
            break;
        }
    }
    Ok(count)
}

async fn head_if_present(client: &S3Client, bucket: &str, key: &str) -> Result<Option<ObjectInfo>> {
    match client.head_object(bucket, key).await {
        Ok(object) => Ok(Some(object)),
        Err(error)
            if error
                .downcast_ref::<S3Error>()
                .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn download_client(client: &S3Client, etag: Option<&str>) -> Result<S3Client> {
    let Some(etag) = etag.filter(|etag| !etag.is_empty()) else {
        return Ok(client.clone());
    };
    if client
        .if_match
        .as_deref()
        .is_some_and(|condition| condition != "*" && condition != etag)
        || client
            .if_none_match
            .as_deref()
            .is_some_and(|condition| condition == "*" || condition == etag)
    {
        bail!("download conditions do not match the observed remote ETag");
    }
    client.clone().with_conditions(Some(etag.to_owned()), None)
}

async fn digest_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::from_std(open_regular_file(path)?);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let size = file.read(&mut buffer).await?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

async fn snapshot_file(path: &Path) -> Result<(tempfile::NamedTempFile, String)> {
    regular_file(path)?;
    let snapshot = tempfile::NamedTempFile::new()?;
    let mut source = tokio::fs::File::from_std(open_regular_file(path)?);
    let mut target = tokio::fs::File::from_std(snapshot.reopen()?);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let size = source.read(&mut buffer).await?;
        if size == 0 {
            break;
        }
        target.write_all(&buffer[..size]).await?;
        hasher.update(&buffer[..size]);
    }
    target.flush().await?;
    Ok((snapshot, hasher.finalize().to_hex().to_string()))
}

pub fn join_key(prefix: &str, key: &str) -> String {
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        key.into()
    } else {
        format!("{prefix}/{key}")
    }
}

fn normalized_prefix(prefix: &str) -> Result<&str> {
    let prefix = prefix.trim_matches('/');
    if !prefix.is_empty() {
        validate_relative(prefix)?;
    }
    Ok(prefix)
}

fn relative_key<'a>(prefix: &str, key: &'a str) -> Result<Option<&'a str>> {
    let relative = if prefix.is_empty() {
        key
    } else if key == prefix {
        return Ok(None);
    } else if let Some(relative) = key
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.strip_prefix('/'))
    {
        relative
    } else {
        return Ok(None);
    };
    if relative.is_empty() {
        return Ok(None);
    }
    // Validate markers too, but don't create files for directory markers.
    validate_relative(relative.strip_suffix('/').unwrap_or(relative))?;
    if relative.ends_with('/') {
        return Ok(None);
    }
    Ok(Some(relative))
}

fn validate_relative(relative: &str) -> Result<()> {
    if relative.is_empty()
        || relative.contains(['\\', ':', '\0', '<', '>', '"', '|', '?', '*'])
        || relative.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || part.ends_with(['.', ' '])
                || windows_device_name(part)
        })
        || Path::new(relative)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("unsafe remote key or relative filename: {relative:?}");
    }
    Ok(())
}

fn windows_device_name(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative(relative)?;
    Ok(root.join(relative))
}

/// Check each component before creating the next, including the user's root.
fn checked_directory(path: &Path, create: bool) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let directory = pinned_directory(&absolute, create)?;
        Ok(fs::canonicalize(format!(
            "/proc/self/fd/{}",
            directory.as_raw_fd()
        ))?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut checked = PathBuf::new();
        for component in absolute.components() {
            match component {
                Component::CurDir => continue,
                Component::Prefix(prefix) => {
                    // A Windows volume prefix is not a directory until its
                    // following root separator has been appended.
                    checked.push(prefix.as_os_str());
                    continue;
                }
                Component::ParentDir => bail!("directory must not contain '..'"),
                _ => checked.push(component.as_os_str()),
            }
            match fs::symlink_metadata(&checked) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => bail!(
                    "directory component is a symlink or not a directory: {}",
                    checked.display()
                ),
                Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                    match fs::create_dir(&checked) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error.into()),
                    }
                    let metadata = fs::symlink_metadata(&checked)?;
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        bail!("unsafe directory component: {}", checked.display());
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(fs::canonicalize(&checked)?)
    }
}

fn regular_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(anyhow!(
            "file is a symlink or not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn open_regular_file(path: &Path) -> Result<File> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() {
        bail!("source is not a regular file: {}", path.display());
    }
    let file = File::open(path)?;
    let after = file.metadata()?;
    if !after.is_file() {
        bail!("source changed while opening: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            bail!("source changed while opening: {}", path.display());
        }
    }
    Ok(file)
}

struct Destination {
    path: PathBuf,
    parent: PathBuf,
    #[cfg(target_os = "linux")]
    _directory: File,
}

impl Destination {
    fn open(parent: &Path, name: &std::ffi::OsStr) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let directory = pinned_directory(parent, false)?;
            let parent = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
            Ok(Self {
                path: parent.join(name),
                parent,
                _directory: directory,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let parent = checked_directory(parent, false)?;
            Ok(Self {
                path: parent.join(name),
                parent,
            })
        }
    }
}

#[cfg(target_os = "linux")]
fn pinned_directory(path: &Path, create: bool) -> Result<File> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    if !path.is_absolute() {
        bail!("directory must be absolute");
    }
    let mut directory = File::open("/")?;
    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => bail!("directory must not contain '..'"),
        };
        let next = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
        let metadata = match fs::symlink_metadata(&next) {
            Ok(metadata) => metadata,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&next) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
                fs::symlink_metadata(&next)?
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!(
                "directory component is a symlink or not a directory: {}",
                path.display()
            );
        }
        let opened = File::open(&next)?;
        let actual = opened.metadata()?;
        // Compare inode identity as well as type, so a symlink substituted
        // between lstat and open cannot redirect later creates or downloads.
        if !actual.is_dir() || (metadata.dev(), metadata.ino()) != (actual.dev(), actual.ino()) {
            bail!(
                "directory component changed while opening: {}",
                path.display()
            );
        }
        directory = opened;
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;
    use std::sync::{Arc, Mutex};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    #[derive(Default)]
    struct Remote {
        files: BTreeMap<String, (Vec<u8>, String)>,
        puts: usize,
        gets: usize,
        heads: usize,
        head_status: Option<u16>,
        fail_get: bool,
        overwrite_after_put: bool,
        omit_put_etag: bool,
    }

    impl Remote {
        fn set(&mut self, key: &str, bytes: &[u8], etag: &str) {
            self.files.insert(key.into(), (bytes.into(), etag.into()));
        }
    }

    fn client(server: &MockServer) -> S3Client {
        S3Client::new(
            &Profile {
                control_api_url: "https://api.example.test".into(),
                s3_endpoint: Some(server.uri()),
                region: "us-east-1".into(),
                ..Profile::default()
            },
            "test-access".into(),
            "test-secret".into(),
        )
        .unwrap()
    }

    // Decode the signed aws-chunked body to verify bytes received by the service.
    fn uploaded_bytes(mut bytes: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        loop {
            let end = bytes.windows(2).position(|part| part == b"\r\n").unwrap();
            let header = std::str::from_utf8(&bytes[..end]).unwrap();
            let size = usize::from_str_radix(header.split(';').next().unwrap(), 16).unwrap();
            if size == 0 {
                return result;
            }
            bytes = &bytes[end + 2..];
            result.extend_from_slice(&bytes[..size]);
            bytes = &bytes[size + 2..];
        }
    }

    async fn service() -> (MockServer, S3Client, Arc<Mutex<Remote>>) {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(Remote::default()));
        let remote = state.clone();
        Mock::given(|_: &Request| true)
            .respond_with(move |request: &Request| {
                let mut remote = remote.lock().unwrap();
                let method = request.method.as_str();
                let key = request.url.path().strip_prefix("/bucket/").unwrap_or("");
                if method == "GET" && request.url.path() == "/bucket" {
                    let items = remote
                        .files
                        .keys()
                        .map(|key| {
                            format!(
                                "<Contents><Key>{key}</Key><ETag>stale-list-etag</ETag></Contents>"
                            )
                        })
                        .collect::<String>();
                    return ResponseTemplate::new(200).set_body_string(
                        format!(
                    "<ListBucketResult>{items}<IsTruncated>false</IsTruncated></ListBucketResult>"),
                    );
                }
                if method == "HEAD" {
                    remote.heads += 1;
                    if let Some(status) = remote.head_status {
                        return ResponseTemplate::new(status);
                    }
                }
                if method == "PUT" {
                    remote.puts += 1;
                    let etag = format!("\"opaque-{}-multipart\"", remote.puts);
                    if remote.overwrite_after_put {
                        remote.set(key, b"another writer", "\"concurrent-writer\"");
                    } else {
                        remote.set(key, &uploaded_bytes(&request.body), &etag);
                    }
                    return if remote.omit_put_etag {
                        ResponseTemplate::new(200)
                    } else {
                        ResponseTemplate::new(200).insert_header("etag", etag)
                    };
                }
                if method == "GET" {
                    remote.gets += 1;
                    if remote.fail_get {
                        return ResponseTemplate::new(403);
                    }
                }
                let Some((bytes, etag)) = remote.files.get(key) else {
                    return ResponseTemplate::new(404);
                };
                if request
                    .headers
                    .get("if-match")
                    .is_some_and(|value| value.to_str().unwrap() != etag)
                {
                    return ResponseTemplate::new(412);
                }
                let response = ResponseTemplate::new(200).insert_header("etag", etag.as_str());
                if method == "HEAD" {
                    response.insert_header("content-length", bytes.len().to_string())
                } else {
                    response.set_body_bytes(bytes.clone())
                }
            })
            .mount(&server)
            .await;
        let client = client(&server);
        (server, client, state)
    }

    // Create even the TempDir's stored path beneath the canonical system temp
    // directory, avoiding macOS's /var -> /private/var alias in all test uses.
    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
    }

    fn root(temp: &tempfile::TempDir) -> PathBuf {
        fs::canonicalize(temp.path()).unwrap()
    }

    #[tokio::test]
    async fn upload_incremental_opaque_etags_local_remote_changes_and_empty_404() {
        let (_server, client, remote) = service().await;
        let local = tempdir();
        let state = tempdir();
        let local = root(&local);
        let state = root(&state);
        fs::write(local.join("file"), b"first").unwrap();
        assert_eq!(
            sync_upload(&client, &local, "bucket", "prefix", &state)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sync_upload(&client, &local, "bucket", "prefix/", &state)
                .await
                .unwrap(),
            0
        );
        fs::write(local.join("file"), b"other").unwrap(); // same size, new digest
        assert_eq!(
            sync_upload(&client, &local, "bucket", "prefix", &state)
                .await
                .unwrap(),
            1
        );
        remote
            .lock()
            .unwrap()
            .set("prefix/file", b"remote edit", "\"unrelated-version\"");
        assert_eq!(
            sync_upload(&client, &local, "bucket", "prefix", &state)
                .await
                .unwrap(),
            1
        );
        remote.lock().unwrap().files.remove("prefix/file");
        assert_eq!(
            sync_upload(&client, &local, "bucket", "prefix", &state)
                .await
                .unwrap(),
            1
        );
        assert_eq!(remote.lock().unwrap().puts, 4);
        assert_eq!(remote.lock().unwrap().gets, 0);
        assert_eq!(remote.lock().unwrap().heads, 5);
        assert_eq!(remote.lock().unwrap().files["prefix/file"].0, b"other");
        let manifest = State::open(
            &state,
            &local,
            "bucket",
            "prefix",
            &client.endpoint_identity(),
        )
        .unwrap();
        assert_ne!(
            manifest.manifest.files["prefix/file"].digest,
            manifest.manifest.files["prefix/file"].etag
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(manifest.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn upload_does_not_associate_a_concurrent_writers_etag() {
        let (_server, client, remote) = service().await;
        let local = tempdir();
        let state = tempdir();
        let local = root(&local);
        let state = root(&state);
        fs::write(local.join("file"), b"our bytes").unwrap();
        remote.lock().unwrap().overwrite_after_put = true;
        assert_eq!(
            sync_upload(&client, &local, "bucket", "", &state)
                .await
                .unwrap(),
            1
        );
        let manifest =
            State::open(&state, &local, "bucket", "", &client.endpoint_identity()).unwrap();
        assert_eq!(
            manifest.manifest.files["file"].etag,
            "\"opaque-1-multipart\""
        );
        assert_eq!(
            manifest.manifest.files["file"].digest,
            blake3::hash(b"our bytes").to_hex().to_string()
        );
        assert_eq!(
            remote.lock().unwrap().files["file"].1,
            "\"concurrent-writer\""
        );
        remote.lock().unwrap().overwrite_after_put = false;
        assert_eq!(
            sync_upload(&client, &local, "bucket", "", &state)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sync_upload(&client, &local, "bucket", "", &state)
                .await
                .unwrap(),
            0
        );
        assert_eq!(remote.lock().unwrap().gets, 0);
        assert_eq!(remote.lock().unwrap().heads, 3);
    }

    #[tokio::test]
    async fn missing_write_etag_never_skips_or_reads_back() {
        let (_server, client, remote) = service().await;
        let local = tempdir();
        let state = tempdir();
        let local = root(&local);
        let state = root(&state);
        fs::write(local.join("file"), b"bytes").unwrap();
        remote.lock().unwrap().omit_put_etag = true;
        for _ in 0..2 {
            assert_eq!(
                sync_upload(&client, &local, "bucket", "", &state)
                    .await
                    .unwrap(),
                1
            );
        }
        let manifest =
            State::open(&state, &local, "bucket", "", &client.endpoint_identity()).unwrap();
        assert!(manifest.manifest.files.is_empty());
        let remote = remote.lock().unwrap();
        assert_eq!(remote.puts, 2);
        assert_eq!(remote.heads, 2);
        assert_eq!(remote.gets, 0);
    }

    #[tokio::test]
    async fn switching_endpoints_with_matching_etags_does_not_skip_transfers() {
        let (_first_server, first, _) = service().await;
        let (_second_server, second, remote) = service().await;
        let local = tempdir();
        let downloads = tempdir();
        let state = tempdir();
        let local = root(&local);
        let downloads = root(&downloads);
        let state = root(&state);
        fs::write(local.join("file"), b"ours").unwrap();
        assert_eq!(
            sync_upload(&first, &local, "bucket", "", &state)
                .await
                .unwrap(),
            1
        );
        remote.lock().unwrap().set(
            "file",
            b"different endpoint bytes",
            "\"opaque-1-multipart\"",
        );
        assert_eq!(
            sync_upload(&second, &local, "bucket", "", &state)
                .await
                .unwrap(),
            1
        );
        assert_eq!(remote.lock().unwrap().gets, 0);
        assert_eq!(
            sync_download(&first, "bucket", "", &downloads, &state)
                .await
                .unwrap(),
            1
        );
        remote
            .lock()
            .unwrap()
            .set("file", b"second endpoint", "\"opaque-1-multipart\"");
        assert_eq!(
            sync_download(&second, "bucket", "", &downloads, &state)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            fs::read(downloads.join("file")).unwrap(),
            b"second endpoint"
        );
    }

    #[tokio::test]
    async fn head_permission_errors_abort_without_uploading() {
        let (_server, client, remote) = service().await;
        let local = tempdir();
        let state = tempdir();
        fs::write(local.path().join("file"), b"bytes").unwrap();
        remote.lock().unwrap().head_status = Some(403);
        let error = sync_upload(&client, &root(&local), "bucket", "", &root(&state))
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<S3Error>().unwrap().status.as_u16(),
            403
        );
        assert_eq!(remote.lock().unwrap().puts, 0);
    }

    #[tokio::test]
    async fn download_incremental_and_alias_preserve_unrelated_files() {
        let (_server, client, remote) = service().await;
        let local = tempdir();
        let state = tempdir();
        let local = root(&local);
        let state = root(&state);
        remote
            .lock()
            .unwrap()
            .set("prefix/sub/file", b"first", "\"opaque-v1\"");
        remote
            .lock()
            .unwrap()
            .set("prefix-other/escape", b"unrelated", "\"other\"");
        fs::write(local.join("keep"), b"keep me").unwrap();
        assert_eq!(
            sync_download(&client, "bucket", "prefix", &local, &state)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sync_download(&client, "bucket", "prefix/", &local, &state)
                .await
                .unwrap(),
            0
        );
        fs::write(local.join("sub/file"), b"other").unwrap();
        assert_eq!(
            sync_download(&client, "bucket", "prefix", &local, &state)
                .await
                .unwrap(),
            1
        );
        remote
            .lock()
            .unwrap()
            .set("prefix/sub/file", b"new remote", "\"opaque-v2\"");
        assert_eq!(
            sync_download(&client, "bucket", "prefix", &local, &state)
                .await
                .unwrap(),
            1
        );
        assert_eq!(remote.lock().unwrap().gets, 3);
        assert_eq!(
            download_directory(&client, "bucket", "prefix", &local)
                .await
                .unwrap(),
            1
        );
        assert_eq!(fs::read(local.join("sub/file")).unwrap(), b"new remote");
        assert_eq!(fs::read(local.join("keep")).unwrap(), b"keep me");
        assert!(!local.join("escape").exists());
        remote.lock().unwrap().files.remove("prefix/sub/file");
        assert_eq!(
            sync_download(&client, "bucket", "prefix", &local, &state)
                .await
                .unwrap(),
            0
        );
        assert!(local.join("sub/file").exists());
    }

    #[tokio::test]
    async fn failed_download_preserves_existing_file_and_observation() {
        let (_server, client, remote) = service().await;
        let local = tempdir();
        let state = tempdir();
        let local = root(&local);
        let state = root(&state);
        remote.lock().unwrap().set("file", b"old", "\"v1\"");
        sync_download(&client, "bucket", "", &local, &state)
            .await
            .unwrap();
        remote.lock().unwrap().set("file", b"new", "\"v2\"");
        remote.lock().unwrap().fail_get = true;
        assert!(sync_download(&client, "bucket", "", &local, &state)
            .await
            .is_err());
        assert_eq!(fs::read(local.join("file")).unwrap(), b"old");
        let manifest =
            State::open(&state, &local, "bucket", "", &client.endpoint_identity()).unwrap();
        assert_eq!(manifest.manifest.files["file"].etag, "\"v1\"");
        assert_eq!(fs::read_dir(&local).unwrap().count(), 1);
    }

    #[test]
    fn rejects_unsafe_paths_and_enforces_prefix_boundary() {
        for key in [
            "../escape",
            "/escape",
            "a/../escape",
            "a/./b",
            "a//b",
            "a\\b",
            "C:escape",
            "C:/escape",
            "\\\\server\\share",
            "\\?\\C:\\escape",
            "a\0b",
            "",
        ] {
            assert!(safe_join(Path::new("root"), key).is_err(), "{key:?}");
        }
        assert_eq!(relative_key("foo", "foobar/file").unwrap(), None);
        assert_eq!(relative_key("foo", "foo/file").unwrap(), Some("file"));
        assert_eq!(relative_key("foo", "foo/directory/").unwrap(), None);
        assert!(relative_key("foo", "foo//escape").is_err());
        assert!(relative_key("foo", "foo/../escape/").is_err());
    }

    #[test]
    fn manifest_scope_isolates_roots_buckets_prefixes_endpoints_and_checks_corruption() {
        let local = tempdir();
        let other = tempdir();
        let state = tempdir();
        let local = root(&local);
        let state = root(&state);
        let first = State::open(&state, &local, "bucket", "prefix", "endpoint-one").unwrap();
        assert_ne!(
            first.path,
            State::open(&state, &root(&other), "bucket", "prefix", "endpoint-one")
                .unwrap()
                .path
        );
        assert_ne!(
            first.path,
            State::open(&state, &local, "other", "prefix", "endpoint-one")
                .unwrap()
                .path
        );
        assert_ne!(
            first.path,
            State::open(&state, &local, "bucket", "other", "endpoint-one")
                .unwrap()
                .path
        );
        assert_ne!(
            first.path,
            State::open(&state, &local, "bucket", "prefix", "endpoint-two")
                .unwrap()
                .path
        );
        crate::keyring::atomic_private_write(&first.path, b"not json").unwrap();
        assert!(State::open(&state, &local, "bucket", "prefix", "endpoint-one").is_err());
    }

    #[tokio::test]
    async fn repeated_pagination_tokens_are_rejected() {
        let server = MockServer::start().await;
        for (token, next) in [(None, "a"), (Some("a"), "b"), (Some("b"), "a")] {
            Mock::given(move |request: &Request| {
                request.url.query_pairs().find(|(key, _)| key == "continuation-token")
                    .map(|(_, value)| value.into_owned()).as_deref() == token
            }).respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>{next}</NextContinuationToken></ListBucketResult>"
            ))).expect(1).mount(&server).await;
        }
        let local = tempdir();
        let error = download_directory(&client(&server), "bucket", "", &root(&local))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("continuation token"));
    }

    #[tokio::test]
    async fn upload_ignores_legacy_manifests_and_nested_state() {
        let (_server, client, remote) = service().await;
        let local = tempdir();
        let local = root(&local);
        fs::write(local.join("file"), b"bytes").unwrap();
        fs::write(local.join(".pipe-upload-old.json"), b"private state").unwrap();
        let state = local.join("state");
        assert_eq!(
            sync_upload(&client, &local, "bucket", "", &state)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sync_upload(&client, &local, "bucket", "", &state)
                .await
                .unwrap(),
            0
        );
        assert_eq!(remote.lock().unwrap().files.len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn transfers_reject_symlink_destinations_and_skip_upload_links() {
        use std::os::unix::fs::symlink;
        let (_server, client, remote) = service().await;
        let local = tempdir();
        let outside = tempdir();
        let local = root(&local);
        let outside = root(&outside);
        fs::write(outside.join("file"), b"outside").unwrap();
        symlink(&outside, local.join("linked")).unwrap();
        symlink(outside.join("file"), local.join("leaf")).unwrap();
        fs::write(local.join("regular"), b"inside").unwrap();
        assert_eq!(
            upload_directory(&client, &local, "bucket", "upload")
                .await
                .unwrap(),
            1
        );
        remote
            .lock()
            .unwrap()
            .set("download/linked/file", b"overwrite", "\"v1\"");
        assert!(download_directory(&client, "bucket", "download", &local)
            .await
            .is_err());
        remote.lock().unwrap().files.remove("download/linked/file");
        remote
            .lock()
            .unwrap()
            .set("download/leaf", b"overwrite", "\"v1\"");
        assert!(download_directory(&client, "bucket", "download", &local)
            .await
            .is_err());
        assert!(
            download_directory(&client, "bucket", "download", &local.join("linked/new"))
                .await
                .is_err()
        );
        assert!(!outside.join("new").exists());
        assert_eq!(fs::read(outside.join("file")).unwrap(), b"outside");
        symlink(outside.join("missing"), local.join("dangling")).unwrap();
        assert!(regular_file(&local.join("dangling")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_parent_does_not_follow_a_replaced_directory() {
        use std::os::unix::fs::symlink;
        let local = tempdir();
        let outside = tempdir();
        let parent = root(&local).join("directory");
        fs::create_dir(&parent).unwrap();
        let destination = Destination::open(&parent, std::ffi::OsStr::new("file")).unwrap();
        fs::rename(&parent, root(&local).join("moved")).unwrap();
        symlink(root(&outside), &parent).unwrap();
        fs::write(&destination.path, b"pinned").unwrap();
        assert!(!outside.path().join("file").exists());
        assert_eq!(
            fs::read(local.path().join("moved/file")).unwrap(),
            b"pinned"
        );
    }
}

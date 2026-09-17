//! Versioned, private recovery records. No network request precedes durable intent.
use crate::{auth::ControlClient, keyring::atomic_private_write};
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use pipe_api::compute::Request;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    path::PathBuf,
};
use uuid::Uuid;

const LIMIT: u64 = 16 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextBinding {
    pub endpoint: String,
    pub owner_wallet: String,
    pub account_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub context: ContextBinding,
    pub request: Request,
    pub state: String,
    pub created_at: i64,
    pub response: Option<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    schema_version: u32,
    entries: BTreeMap<Uuid, Entry>,
}
pub struct Journal {
    path: PathBuf,
    _lock: File,
    data: Data,
}
impl Journal {
    pub fn open(client: &ControlClient) -> Result<Self> {
        let path = client
            .secrets
            .state_directory()
            .join("compute-journal-v1.json");
        std::fs::create_dir_all(path.parent().unwrap())?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.with_extension("lock"))?;
        lock.try_lock_exclusive()
            .context("compute journal is in use")?;
        let data = match File::open(&path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(LIMIT + 1).read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() as u64 <= LIMIT,
                    "compute journal too large; preserve it for recovery"
                );
                let data: Data = serde_json::from_slice(&bytes)
                    .context("invalid compute journal; original file preserved")?;
                ensure!(
                    data.schema_version == 1,
                    "unsupported compute journal version; original file preserved"
                );
                data
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Data {
                schema_version: 1,
                entries: BTreeMap::new(),
            },
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            _lock: lock,
            data,
        })
    }
    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.data)?;
        ensure!(
            bytes.len() as u64 <= LIMIT,
            "compute journal is full; preserve it for recovery"
        );
        atomic_private_write(&self.path, &bytes).context("persist compute recovery journal")
    }
    pub fn list(&self) -> &BTreeMap<Uuid, Entry> {
        &self.data.entries
    }
    pub fn get(&self, id: Uuid) -> Result<&Entry> {
        self.data
            .entries
            .get(&id)
            .context("request is absent from this profile's compute journal")
    }
    pub fn prepare(
        &mut self,
        context: ContextBinding,
        request: Request,
        supplied: Option<Uuid>,
    ) -> Result<Uuid> {
        let id = supplied.unwrap_or_else(Uuid::new_v4);
        if let Some(old) = self.data.entries.get(&id) {
            ensure!(
                old.context == context && old.request == request,
                "request ID is bound to another context or payload"
            );
            return Ok(id);
        }
        for (pending, old) in &self.data.entries {
            ensure!(
                !(old.context == context && old.request == request && old.state == "unknown"),
                "an unresolved request already exists; run pipe compute resume {pending}"
            );
        }
        ensure!(
            self.data.entries.len() < 4096,
            "compute journal entry limit reached; preserve it for recovery"
        );
        self.data.entries.insert(
            id,
            Entry {
                context,
                request,
                state: "unknown".into(),
                created_at: chrono::Utc::now().timestamp(),
                response: None,
            },
        );
        self.save()?;
        Ok(id)
    }
    pub fn accepted(&mut self, id: Uuid, response: Value) -> Result<()> {
        let entry = self
            .data
            .entries
            .get_mut(&id)
            .context("missing prepared request")?;
        if let Some(prior) = &entry.response {
            ensure!(
                prior == &response,
                "accepted response changed; original receipt preserved"
            );
        }
        entry.response = Some(response);
        entry.state = "accepted".into();
        self.save()
    }
    pub fn rejected(&mut self, id: Uuid) -> Result<()> {
        let entry = self
            .data
            .entries
            .get_mut(&id)
            .context("missing prepared request")?;
        ensure!(
            entry.response.is_none(),
            "cannot reject an accepted request"
        );
        entry.state = "rejected".into();
        self.save()
    }
}

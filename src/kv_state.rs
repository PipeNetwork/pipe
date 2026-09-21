//! KV secrets and recovery intents are stored together in the selected secure
//! store before activation/forwarding. Payload values never enter the journal.
use crate::{auth::ControlClient, compute_journal::ContextBinding};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub id: Uuid,
    pub secret: String,
    pub endpoint: String,
    pub instance: Option<Uuid>,
    pub permissions: Option<u8>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Intent {
    CreateInstance {
        wallet: String,
        id: Uuid,
    },
    DeleteInstance {
        id: Uuid,
    },
    CreateCredential {
        instance: Uuid,
        id: Uuid,
        label: String,
        permissions: u8,
    },
    RevokeCredential {
        id: Uuid,
    },
    Data {
        endpoint: String,
        credential: Uuid,
        command: String,
        sha256: String,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub context: Option<ContextBinding>,
    pub intent: Intent,
    pub state: String,
    pub created_at: i64,
    pub response: Option<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u32,
    pub credentials: BTreeMap<Uuid, Credential>,
    pub requests: BTreeMap<Uuid, Record>,
}
impl State {
    pub fn load(c: &ControlClient) -> Result<Self> {
        let clear = match crate::secure_state::read(c, &SPEC)? {
            Some(value) => Some(value),
            None => c
                .secrets
                .get("kv-state-v1")?
                .map(|v| zeroize::Zeroizing::new(v.into_bytes())),
        };
        let Some(clear) = clear else {
            return Ok(Self {
                schema_version: 1,
                credentials: BTreeMap::new(),
                requests: BTreeMap::new(),
            });
        };
        ensure!(
            clear.len() <= SPEC.limit,
            "KV state exceeds limit; preserve for recovery"
        );
        let value: Self =
            serde_json::from_slice(&clear).context("invalid KV state; original preserved")?;
        ensure!(
            value.schema_version == 1,
            "unsupported KV state; preserve for recovery"
        );
        Ok(value)
    }
    pub fn save(&self, c: &ControlClient) -> Result<()> {
        crate::secure_state::write(
            c,
            &SPEC,
            &zeroize::Zeroizing::new(serde_json::to_vec(self)?),
        )
    }
    pub fn prepare(
        &mut self,
        c: &ControlClient,
        context: Option<ContextBinding>,
        intent: Intent,
        id: Uuid,
    ) -> Result<()> {
        if let Some(old) = self.requests.get(&id) {
            ensure!(
                old.context == context && old.intent == intent,
                "request ID belongs to another context or intent"
            );
            return Ok(());
        }
        for (id, old) in &self.requests {
            ensure!(
                !(old.context == context
                    && same_intent(&old.intent, &intent)
                    && old.state == "unknown"),
                "unresolved KV request {id} exists; inspect pipe kv requests before continuing"
            );
        }
        ensure!(
            self.requests.len() < 4096,
            "KV request limit reached; preserve recovery state"
        );
        self.requests.insert(
            id,
            Record {
                context,
                intent,
                state: "unknown".into(),
                created_at: chrono::Utc::now().timestamp(),
                response: None,
            },
        );
        self.save(c)
    }
    pub fn finish(
        &mut self,
        c: &ControlClient,
        id: Uuid,
        state: &str,
        response: Option<Value>,
    ) -> Result<()> {
        let r = self.requests.get_mut(&id).context("missing KV request")?;
        ensure!(r.state == "unknown", "KV request already resolved");
        r.state = state.into();
        r.response = response;
        self.save(c)
    }
}

fn same_intent(a: &Intent, b: &Intent) -> bool {
    match (a, b) {
        (Intent::CreateInstance { wallet: a, .. }, Intent::CreateInstance { wallet: b, .. }) => {
            a == b
        }
        (
            Intent::CreateCredential {
                instance: a,
                label: al,
                permissions: ap,
                ..
            },
            Intent::CreateCredential {
                instance: b,
                label: bl,
                permissions: bp,
                ..
            },
        ) => a == b && al == bl && ap == bp,
        _ => a == b,
    }
}

const SPEC: crate::secure_state::Spec = crate::secure_state::Spec {
    file: "kv-state-v1.enc",
    key: "kv-state-key-v1",
    magic: b"PIPEKVS1",
    limit: 2 * 1024 * 1024,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_intents_and_secrets_survive_restart_and_reject_replacements() {
        let dir = tempfile::tempdir().unwrap();
        let c = ControlClient::for_test(
            crate::config::Profile::new("https://example.invalid"),
            dir.path(),
        )
        .unwrap();
        let binding = Some(ContextBinding {
            endpoint: c.url(""),
            owner_wallet: "owner".into(),
            account_id: Some("account".into()),
        });
        let id = Uuid::new_v4();
        let instance = Uuid::new_v4();
        let secret = "ab".repeat(32);
        let mut s = State::load(&c).unwrap();
        s.credentials.insert(
            id,
            Credential {
                id,
                secret: secret.clone(),
                endpoint: "rediss://kv.pipe.network:6380".into(),
                instance: Some(instance),
                permissions: Some(3),
            },
        );
        let intent = Intent::CreateCredential {
            instance,
            id,
            label: "test".into(),
            permissions: 3,
        };
        s.prepare(&c, binding.clone(), intent.clone(), id).unwrap();
        let mut s = State::load(&c).unwrap();
        assert_eq!(s.credentials[&id].secret, secret);
        assert_eq!(s.requests[&id].state, "unknown");
        let replacement = Uuid::new_v4();
        assert!(s
            .prepare(
                &c,
                binding.clone(),
                Intent::CreateCredential {
                    instance,
                    id: replacement,
                    label: "test".into(),
                    permissions: 3
                },
                replacement
            )
            .is_err());
        assert!(s.prepare(&c, None, intent, id).is_err());
        s.finish(
            &c,
            id,
            "accepted",
            Some(serde_json::json!({"credential_id":id})),
        )
        .unwrap();
        assert!(s.finish(&c, id, "rejected", None).is_err());
        let bytes = std::fs::read(dir.path().join("secrets.json")).unwrap();
        assert!(bytes.starts_with(b"PIPESEC3"));
        assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
        let path = c.secrets.state_directory().join("kv-state-v1.enc");
        let mut bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"PIPEKVS1"));
        assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(State::load(&c).is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}

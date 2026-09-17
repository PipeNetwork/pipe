use crate::{auth::ControlClient, compute_journal::ContextBinding, secure_state};
use anyhow::{ensure, Context, Result};
use pipe_api::hosting::Request;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;
const SPEC: secure_state::Spec = secure_state::Spec {
    file: "hosting-state-v1.enc",
    key: "hosting-state-key-v1",
    magic: b"PIPEHOS1",
    limit: 16 * 1024 * 1024,
};
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Binding {
    Customer {
        context: ContextBinding,
    },
    Product {
        endpoint: String,
        credential: Uuid,
        account: Uuid,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub secret: String,
    pub endpoint: String,
    pub account: Uuid,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub binding: Binding,
    pub request: Request,
    pub state: String,
    pub response: Option<Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub binding: Binding,
    pub site: Uuid,
    pub sha256: String,
    pub bytes: u64,
    pub expected_active: Option<String>,
    pub migrate: bool,
    pub steps: [Uuid; 3],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    version: u32,
    pub credentials: BTreeMap<Uuid, Credential>,
    pub requests: BTreeMap<Uuid, Entry>,
    pub deployments: BTreeMap<Uuid, Deployment>,
}
impl State {
    pub fn load(c: &ControlClient) -> Result<Self> {
        let Some(clear) = secure_state::read(c, &SPEC)? else {
            return Ok(Self {
                version: 1,
                credentials: BTreeMap::new(),
                requests: BTreeMap::new(),
                deployments: BTreeMap::new(),
            });
        };
        let s: Self =
            serde_json::from_slice(&clear).context("invalid hosting state; original preserved")?;
        ensure!(
            s.version == 1,
            "unsupported hosting state; original preserved"
        );
        Ok(s)
    }
    pub fn save(&self, c: &ControlClient) -> Result<()> {
        secure_state::write(
            c,
            &SPEC,
            &zeroize::Zeroizing::new(serde_json::to_vec(self)?),
        )
    }
    pub fn prepare(&mut self, c: &ControlClient, id: Uuid, b: Binding, r: Request) -> Result<bool> {
        if let Some(e) = self.requests.get(&id) {
            ensure!(
                e.binding == b && e.request == r,
                "hosting request belongs to another context or payload"
            );
            return Ok(false);
        }
        for (old, e) in &self.requests {
            let same = match (&e.request, &r) {
                (
                    Request::CreateKey {
                        label: a,
                        can_write: aw,
                        ..
                    },
                    Request::CreateKey {
                        label: b,
                        can_write: bw,
                        ..
                    },
                ) => a == b && aw == bw,
                _ => e.request == r,
            };
            ensure!(
                !(same && e.binding == b && (e.state == "unknown" || e.state == "pending")),
                "unresolved hosting request {old}; resume it before a replacement"
            );
        }
        ensure!(
            self.requests.len() < 4096,
            "hosting journal limit reached; preserve for recovery"
        );
        self.requests.insert(
            id,
            Entry {
                binding: b,
                request: r,
                state: "unknown".into(),
                response: None,
            },
        );
        self.save(c)?;
        Ok(true)
    }
    pub fn finish(
        &mut self,
        c: &ControlClient,
        id: Uuid,
        state: &str,
        v: Option<Value>,
    ) -> Result<()> {
        let e = self
            .requests
            .get_mut(&id)
            .context("missing hosting request")?;
        ensure!(
            matches!(e.state.as_str(), "unknown" | "pending"),
            "hosting request already resolved"
        );
        e.state = state.into();
        e.response = v;
        self.save(c)
    }
    pub fn metadata(&self) -> Value {
        json!({"requests":self.requests.iter().map(|(id,e)|json!({"request_id":id,"binding":e.binding,"operation":e.request.operation().0,"state":e.state,"payload_sha256":crate::sigv4::sha256_hex(&serde_json::to_vec(&e.request).unwrap())})).collect::<Vec<_>>(),"deployments":self.deployments.keys().collect::<Vec<_>>()})
    }
}
pub fn bundle(
    c: &ControlClient,
    hash: &str,
    write: Option<&[u8]>,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid bundle digest"
    );
    let file = format!("hosting-bundles/{hash}.enc");
    let spec = secure_state::Spec {
        file: &file,
        key: SPEC.key,
        magic: b"PIPEHOB1",
        limit: 32 * 1024 * 1024,
    };
    if let Some(data) = write {
        ensure!(
            crate::sigv4::sha256_hex(data) == hash,
            "bundle digest differs"
        );
        if !c.secrets.state_directory().join(&file).exists() {
            let dir = c.secrets.state_directory().join("hosting-bundles");
            let count = if dir.exists() {
                std::fs::read_dir(dir)?.count()
            } else {
                0
            };
            ensure!(
                count < 128,
                "hosting snapshot limit reached; preserve for recovery"
            );
            secure_state::write(c, &spec, data)?;
        }
    }
    let data = secure_state::read(c, &spec)?
        .context("saved deployment bundle missing; preserve recovery state")?;
    ensure!(
        crate::sigv4::sha256_hex(&data) == hash,
        "saved bundle digest differs"
    );
    Ok(data)
}

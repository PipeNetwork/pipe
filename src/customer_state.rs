//! Encrypted original customer mutations and invitation material; never a browser session.
use crate::{auth::ControlClient, compute_journal::ContextBinding, secure_state};
use anyhow::{ensure, Context, Result};
use pipe_api::account::Request;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;
const SPEC: secure_state::Spec = secure_state::Spec {
    file: "customer-state-v1.enc",
    key: "customer-state-key-v1",
    magic: b"PIPECUS1",
    limit: 16 * 1024 * 1024,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub binding: ContextBinding,
    pub request: Request,
    pub state: String,
    pub response: Option<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    version: u32,
    pub requests: BTreeMap<Uuid, Entry>,
}
impl State {
    pub fn load(c: &ControlClient) -> Result<Self> {
        let Some(clear) = secure_state::read(c, &SPEC)? else {
            return Ok(Self {
                version: 1,
                requests: BTreeMap::new(),
            });
        };
        let s: Self = serde_json::from_slice(&clear)
            .context("invalid customer journal; original preserved")?;
        ensure!(
            s.version == 1,
            "unsupported customer journal; original preserved"
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
    pub fn prepare(
        &mut self,
        c: &ControlClient,
        id: Uuid,
        b: ContextBinding,
        r: Request,
    ) -> Result<()> {
        ensure!(
            !self.requests.contains_key(&id),
            "request already exists; use account resume"
        );
        for (old, e) in &self.requests {
            // Any unknown organization/account mutation blocks replacement, including
            // newly generated IDs, role changes and invitation material.
            ensure!(e.binding!=b || e.state!="unknown","unresolved customer request {old}; inspect and resume or acknowledge before another mutation");
        }
        ensure!(
            self.requests.len() < 4096,
            "customer journal limit reached; preserve recovery records"
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
        self.save(c)
    }
    pub fn finish(
        &mut self,
        c: &ControlClient,
        id: Uuid,
        state: &str,
        value: Option<Value>,
    ) -> Result<()> {
        let e = self
            .requests
            .get_mut(&id)
            .context("missing customer request")?;
        ensure!(e.state == "unknown", "request already resolved");
        e.state = state.into();
        e.response = value;
        self.save(c)
    }
    pub fn metadata(&self) -> Value {
        json!({"requests":self.requests.iter().map(|(id,e)|json!({"request_id":id,"context":e.binding,"operation":e.request.operation().0,"state":e.state,"payload_sha256":crate::sigv4::sha256_hex(&serde_json::to_vec(&e.request).unwrap())})).collect::<Vec<_>>()})
    }
}

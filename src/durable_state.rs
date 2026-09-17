use crate::{auth::ControlClient, compute_journal::ContextBinding};
use anyhow::{ensure, Context, Result};
use pipe_api::durable::Request;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;
const SPEC: crate::secure_state::Spec = crate::secure_state::Spec {
    file: "durable-state-v1.enc",
    key: "durable-state-key-v1",
    magic: b"PIPEDOS1",
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
        namespace: Uuid,
        credential: Uuid,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub namespace: Uuid,
    pub endpoint: String,
    pub secret: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub binding: Binding,
    pub request: Request,
    pub state: String,
    pub created_at: i64,
    pub response: Option<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u32,
    pub credentials: BTreeMap<Uuid, Credential>,
    pub requests: BTreeMap<Uuid, Entry>,
}
impl State {
    pub fn load(c: &ControlClient) -> Result<Self> {
        let Some(clear) = crate::secure_state::read(c, &SPEC)? else {
            return Ok(Self {
                schema_version: 1,
                credentials: BTreeMap::new(),
                requests: BTreeMap::new(),
            });
        };
        let s: Self = serde_json::from_slice(&clear)
            .context("invalid Durable recovery state; original preserved")?;
        ensure!(
            s.schema_version == 1,
            "unsupported Durable state; original preserved"
        );
        Ok(s)
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
        id: Uuid,
        binding: Binding,
        request: Request,
    ) -> Result<bool> {
        if let Some(e) = self.requests.get(&id) {
            ensure!(
                e.binding == binding && e.request == request,
                "request ID belongs to another context or payload"
            );
            return Ok(false);
        }
        for (id, e) in &self.requests {
            ensure!(
                !(e.binding == binding
                    && same_request(&e.request, &request)
                    && e.state == "unknown"),
                "unresolved request {id} already exists; run pipe durable resume {id}"
            );
        }
        ensure!(
            self.requests.len() < 4096,
            "Durable journal entry limit reached; preserve for recovery"
        );
        self.requests.insert(
            id,
            Entry {
                binding,
                request,
                state: "unknown".into(),
                created_at: chrono::Utc::now().timestamp(),
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
        response: Option<Value>,
    ) -> Result<()> {
        let e = self
            .requests
            .get_mut(&id)
            .context("missing Durable request")?;
        ensure!(
            e.state == "unknown" || (e.state == "accepted" && state == "accepted"),
            "request already resolved"
        );
        e.state = state.into();
        if response.is_some() {
            e.response = response;
        }
        self.save(c)
    }
    pub fn metadata(&self) -> Value {
        serde_json::json!({"requests":self.requests.iter().map(|(id,e)|serde_json::json!({"request_id":id,"binding":e.binding,"operation":e.request.operation(matches!(e.binding,Binding::Product{..})).0,"state":e.state,"created_at":e.created_at,"operation_id":e.response.as_ref().and_then(|v|v.get("operation_id")),"payload_sha256":crate::sigv4::sha256_hex(&serde_json::to_vec(&e.request).unwrap())})).collect::<Vec<_>>()})
    }
}
fn same_request(a: &Request, b: &Request) -> bool {
    match (a, b) {
        (
            Request::CreateKey {
                namespace: a,
                label: al,
                can_write: aw,
                ..
            },
            Request::CreateKey {
                namespace: b,
                label: bl,
                can_write: bw,
                ..
            },
        ) => a == b && al == bl && aw == bw,
        _ => a == b,
    }
}

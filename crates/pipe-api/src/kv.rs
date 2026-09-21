//! Reviewed KV management models. Optional request fields preserve old clients.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CreateInstance {
    pub wallet: String,
    pub id: Uuid,
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CreateCredential {
    pub instance: Uuid,
    pub label: String,
    pub permissions: u8,
    pub credential_id: Uuid,
    pub secret: String,
}
#[derive(Deserialize)]
pub struct InstanceReceipt {
    pub id: Uuid,
    pub namespace: Uuid,
    pub wallet: String,
    pub memory_limit_bytes: u64,
}
#[derive(Deserialize)]
pub struct CredentialReceipt {
    pub credential_id: Uuid,
    pub instance: Uuid,
    pub permissions: u8,
    pub secret: String,
}
#[derive(Deserialize)]
pub struct Pricing {
    pub available: bool,
    pub endpoint: Option<String>,
}

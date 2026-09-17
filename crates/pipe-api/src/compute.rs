use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVm {
    pub project_id: Uuid,
    pub name: String,
    pub image_id: String,
    pub flavor_id: String,
    pub ssh_public_keys: Vec<String>,
    pub inference_budget_usd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_renew: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Billing {
    pub auto_renew: bool,
    pub renew: bool,
    pub price_version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Start,
    Stop,
    Reboot,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub body: Value,
}
impl Request {
    pub fn create(body: CreateVm) -> Self {
        Self {
            operation_id: "createComputeVm".into(),
            method: "POST".into(),
            path: "/v1/compute/vms".into(),
            body: json!(body),
        }
    }
    pub fn action(id: Uuid, action: Action, force: bool) -> Self {
        let (operation, suffix) = match action {
            Action::Start => ("startComputeVm", "/start"),
            Action::Stop => ("stopComputeVm", "/stop"),
            Action::Reboot => ("rebootComputeVm", "/reboot"),
            Action::Delete => ("deleteComputeVm", ""),
        };
        Self {
            operation_id: operation.into(),
            method: if matches!(action, Action::Delete) {
                "DELETE"
            } else {
                "POST"
            }
            .into(),
            path: format!("/v1/compute/vms/{id}{suffix}"),
            body: if matches!(action, Action::Start | Action::Delete) {
                json!({})
            } else {
                json!({"force":force})
            },
        }
    }
    pub fn billing(id: Uuid, body: Billing) -> Self {
        Self {
            operation_id: "updateComputeBilling".into(),
            method: "POST".into(),
            path: format!("/v1/compute/vms/{id}/billing"),
            body: json!(body),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Mutation {
    pub vm_id: Uuid,
    pub operation_id: Uuid,
    pub generation: i64,
}

#[derive(Debug, Deserialize)]
pub struct Operation {
    pub operation_id: Uuid,
    pub vm_id: Uuid,
    pub generation: i64,
    pub action: String,
    pub status: String,
    pub phase: String,
    pub error_code: Option<String>,
    pub created_at: i64,
    pub completed_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct Ssh {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub host_key_fingerprint: Option<String>,
}

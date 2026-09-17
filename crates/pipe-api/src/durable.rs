//! Reviewed models for the original paid Durable Objects OpenAPI 3.1 union.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub sql: String,
    #[serde(default)]
    pub params: Vec<Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    PutState {
        key: String,
        value: Value,
    },
    GetState {
        key: String,
    },
    DeleteState {
        key: String,
    },
    ListState {
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        after: String,
    },
    Sql {
        statements: Vec<Statement>,
    },
    Migrate {
        version: u64,
        statements: Vec<String>,
    },
    PutBlob {
        key: String,
        data_base64: String,
    },
    GetBlob {
        key: String,
    },
    DeleteBlob {
        key: String,
    },
    ListBlobs {
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        after: String,
    },
    DeleteObject,
}
impl Action {
    pub fn write(&self) -> bool {
        !matches!(
            self,
            Self::GetState { .. }
                | Self::ListState { .. }
                | Self::GetBlob { .. }
                | Self::ListBlobs { .. }
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Execute {
    pub object: String,
    pub action: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub wallet: String,
    pub name: String,
    pub price_version: String,
    pub spending_limit_atoms: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum Request {
    Create(Create),
    Revoke {
        namespace: Uuid,
    },
    Limit {
        namespace: Uuid,
        spending_limit_atoms: String,
    },
    CreateKey {
        namespace: Uuid,
        id: Uuid,
        label: String,
        can_write: bool,
    },
    RevokeKey {
        id: Uuid,
    },
    Execute {
        namespace: Uuid,
        body: Execute,
    },
}
impl Request {
    pub fn operation(&self, product: bool) -> (&'static str, &'static str, String) {
        match self {
            Self::Create(_) => (
                "createDurableNamespace",
                "POST",
                "/v1/customer/durable/namespaces".into(),
            ),
            Self::Revoke { namespace } => (
                "revokeDurableNamespace",
                "DELETE",
                format!("/v1/customer/durable/namespaces/{namespace}"),
            ),
            Self::Limit { namespace, .. } => (
                "updateDurableLimit",
                "POST",
                format!("/v1/customer/durable/namespaces/{namespace}/limit"),
            ),
            Self::CreateKey { namespace, .. } => (
                "createDurableCredential",
                "POST",
                format!("/v1/customer/durable/namespaces/{namespace}/credentials"),
            ),
            Self::RevokeKey { id } => (
                "revokeDurableCredential",
                "DELETE",
                format!("/v1/customer/durable/credentials/{id}"),
            ),
            Self::Execute { namespace, .. } => {
                if product {
                    (
                        "executeDurableAction",
                        "POST",
                        format!("/v1/durable/namespaces/{namespace}/execute"),
                    )
                } else {
                    (
                        "executeCustomerDurableAction",
                        "POST",
                        format!("/v1/customer/durable/namespaces/{namespace}/execute"),
                    )
                }
            }
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Operation {
    pub operation_id: Uuid,
    pub status: String,
    pub charge_atoms: String,
    pub response: Option<Response>,
    pub response_expired: bool,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Response {
    pub sequence: i64,
    pub status: u16,
    pub result: Value,
    pub checkpoint_bytes: i64,
}

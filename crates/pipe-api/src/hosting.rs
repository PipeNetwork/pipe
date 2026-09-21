//! Reviewed hosting requests. Customer CLI never assigns owners or infrastructure bindings.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Request {
    Register {
        wallet: String,
    },
    Purchase {
        plan: String,
        price_version: String,
    },
    CreateKey {
        id: Uuid,
        label: String,
        can_write: bool,
    },
    RevokeKey {
        id: Uuid,
    },
    CreateSite {
        slug: String,
    },
    DeleteSite {
        site: Uuid,
    },
    Upload {
        site: Uuid,
        sha256: String,
        bytes: u64,
    },
    Migrate {
        site: Uuid,
        release_id: String,
        expected_active: Option<String>,
    },
    Activate {
        site: Uuid,
        release_id: String,
        expected_active: Option<String>,
    },
    Deactivate {
        site: Uuid,
        expected_active: Option<String>,
    },
    Allocate {
        site: Uuid,
        bytes: u64,
    },
    DeleteRelease {
        site: Uuid,
        release: String,
    },
    CreateDomain {
        site: Uuid,
        hostname: String,
    },
    DeleteDomain {
        site: Uuid,
        domain: Uuid,
    },
    VerifyDomain {
        site: Uuid,
        domain: Uuid,
    },
}
impl Request {
    pub fn operation(&self) -> (&'static str, &'static str, String) {
        match self {
            Self::Register { .. } => (
                "registerHostingAccount",
                "POST",
                "/v1/customer/hosting/account".into(),
            ),
            Self::Purchase { .. } => (
                "purchaseHostingPlan",
                "POST",
                "/v1/customer/hosting/purchases".into(),
            ),
            Self::CreateKey { .. } => (
                "createHostingCredential",
                "POST",
                "/v1/customer/hosting/credentials".into(),
            ),
            Self::RevokeKey { id } => (
                "revokeHostingCredential",
                "DELETE",
                format!("/v1/customer/hosting/credentials/{id}"),
            ),
            Self::CreateSite { .. } => ("createHostingSite", "POST", "/v1/hosting/sites".into()),
            Self::DeleteSite { site } => (
                "deleteHostingSite",
                "DELETE",
                format!("/v1/hosting/sites/{site}"),
            ),
            Self::Upload { site, .. } => (
                "uploadHostingRelease",
                "POST",
                format!("/v1/hosting/sites/{site}/releases"),
            ),
            Self::Migrate { site, .. } => (
                "migrateHostingSite",
                "POST",
                format!("/v1/hosting/sites/{site}/migrations"),
            ),
            Self::Activate { site, .. } => (
                "activateHostingRelease",
                "POST",
                format!("/v1/hosting/sites/{site}/activate"),
            ),
            Self::Deactivate { site, .. } => (
                "deactivateHostingSite",
                "POST",
                format!("/v1/hosting/sites/{site}/deactivate"),
            ),
            Self::Allocate { site, .. } => (
                "allocateHostingStorage",
                "POST",
                format!("/v1/hosting/sites/{site}/storage"),
            ),
            Self::DeleteRelease { site, release } => (
                "deleteHostingRelease",
                "DELETE",
                format!("/v1/hosting/sites/{site}/releases/{release}"),
            ),
            Self::CreateDomain { site, .. } => (
                "createHostingDomain",
                "POST",
                format!("/v1/hosting/sites/{site}/domains"),
            ),
            Self::DeleteDomain { site, domain } => (
                "deleteHostingDomain",
                "DELETE",
                format!("/v1/hosting/sites/{site}/domains/{domain}"),
            ),
            Self::VerifyDomain { site, domain } => (
                "verifyHostingDomain",
                "POST",
                format!("/v1/hosting/sites/{site}/domains/{domain}/verify"),
            ),
        }
    }
    pub fn body(&self) -> Option<Value> {
        Some(match self {
            Self::Register { wallet } => json!({"wallet":wallet}),
            Self::Purchase {
                plan,
                price_version,
            } => json!({"plan":plan,"price_version":price_version}),
            Self::CreateKey {
                id,
                label,
                can_write,
            } => json!({"id":id,"label":label,"can_write":can_write}),
            Self::CreateSite { slug } => json!({"slug":slug}),
            Self::Activate {
                release_id,
                expected_active,
                ..
            }
            | Self::Migrate {
                release_id,
                expected_active,
                ..
            } => json!({"release_id":release_id,"expected_active":expected_active}),
            Self::Deactivate {
                expected_active, ..
            } => json!({"expected_active":expected_active}),
            Self::Allocate { bytes, .. } => json!({"bytes":bytes}),
            Self::CreateDomain { hostname, .. } => json!({"hostname":hostname}),
            _ => return None,
        })
    }
    // Everything else requires observation/manual reconciliation after a lost reply.
    pub fn replay_safe(&self) -> bool {
        matches!(
            self,
            Self::Register { .. }
                | Self::Purchase { .. }
                | Self::CreateKey { .. }
                | Self::RevokeKey { .. }
                | Self::Upload { .. }
                | Self::Migrate { .. }
                | Self::DeleteSite { .. }
        )
    }
}

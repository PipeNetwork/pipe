//! Canonical account/organization requests. Balances stay in their original units.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub limit: u32,
    pub cursor: Option<String>,
    pub created_at_from: Option<String>,
    pub created_at_to: Option<String>,
    pub search: Option<String>,
    pub entry_type: Option<String>,
    pub model: Option<String>,
    pub project_id: Option<String>,
    pub group_by: Option<String>,
}
impl History {
    pub fn pairs(&self) -> Vec<(String, String)> {
        let mut v = vec![("limit".into(), self.limit.to_string())];
        for (k, x) in [
            ("cursor", &self.cursor),
            ("created_at_from", &self.created_at_from),
            ("created_at_to", &self.created_at_to),
            ("search", &self.search),
            ("entry_type", &self.entry_type),
            ("model", &self.model),
            ("project_id", &self.project_id),
            ("group_by", &self.group_by),
        ] {
            if let Some(x) = x {
                v.push((k.into(), x.clone()));
            }
        }
        v
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum Request {
    ApiKeys,
    CreateApiKey {
        id: uuid::Uuid,
        api_key: String,
        settings: crate::keys::Settings,
    },
    UpdateApiKey {
        id: uuid::Uuid,
        settings: crate::keys::Settings,
    },
    RevokeApiKey {
        id: uuid::Uuid,
    },
    Account,
    Identities,
    Wallets,
    Referrals,
    Organizations,
    Members {
        org: String,
    },
    Invites {
        org: String,
    },
    Balance {
        org: Option<String>,
    },
    Ledger {
        org: Option<String>,
        history: History,
    },
    Usage {
        org: Option<String>,
        history: History,
    },
    Billing {
        org: String,
    },
    Invoices {
        org: String,
    },
    Subscriptions {
        org: String,
    },
    Profile {
        display_name: Option<String>,
    },
    RotateReferral,
    CreateOrg {
        id: String,
        name: String,
    },
    UpdateMember {
        org: String,
        account: String,
        role: String,
    },
    RemoveMember {
        org: String,
        account: String,
    },
    CreateInvite {
        org: String,
        id: String,
        email: String,
        role: String,
        accept_token: String,
    },
    RevokeInvite {
        org: String,
        id: String,
    },
    AcceptInvite {
        token: String,
    },
}
impl Request {
    pub fn operation(&self) -> (&'static str, &'static str, String) {
        use Request::*;
        let org_path = |org: &str, end: &str| format!("/v1/platform/organizations/{org}{end}");
        match self {
            ApiKeys => ("platform.api_keys", "GET", "/v1/account/api-keys".into()),
            CreateApiKey { .. } => (
                "platform.create_api_key",
                "POST",
                "/v1/account/api-keys".into(),
            ),
            UpdateApiKey { id, .. } => (
                "platform.update_api_key",
                "PATCH",
                format!("/v1/account/api-keys/{id}"),
            ),
            RevokeApiKey { id } => (
                "platform.revoke_api_key",
                "POST",
                format!("/v1/account/api-keys/{id}/revoke"),
            ),
            Account => ("platformCliAccount", "GET", "/v1/cli/account".into()),
            Identities => (
                "platform.identities",
                "GET",
                "/v1/platform/account/identities".into(),
            ),
            Wallets => (
                "platform.wallet_links",
                "GET",
                "/v1/platform/account/wallet-link".into(),
            ),
            Referrals => (
                "platform.referral_summary",
                "GET",
                "/v1/account/referral".into(),
            ),
            Organizations => (
                "platform.organizations",
                "GET",
                "/v1/platform/organizations".into(),
            ),
            Members { org } => ("platform.memberships", "GET", org_path(org, "/memberships")),
            Invites { org } => ("platform.invites", "GET", org_path(org, "/invites")),
            Balance { org: None } => ("platform.billing.account", "GET", "/v1/account".into()),
            Balance { org: Some(org) } => (
                "platform.billing.org_account",
                "GET",
                org_path(org, "/account"),
            ),
            Ledger { org: None, .. } => (
                "platform.billing.account_ledger",
                "GET",
                "/v1/account/ledger".into(),
            ),
            Ledger { org: Some(org), .. } => (
                "platform.billing.org_ledger",
                "GET",
                org_path(org, "/ledger"),
            ),
            Usage { org: None, .. } => {
                ("platform.billing.account_usage", "GET", "/v1/usage".into())
            }
            Usage { org: Some(org), .. } => {
                ("platform.billing.org_usage", "GET", org_path(org, "/usage"))
            }
            Billing { org } => ("platform.billing.summary", "GET", org_path(org, "/billing")),
            Invoices { org } => (
                "platform.billing.invoices",
                "GET",
                org_path(org, "/billing/invoices"),
            ),
            Subscriptions { org } => (
                "platform.billing.subscriptions",
                "GET",
                org_path(org, "/billing/subscriptions"),
            ),
            Profile { .. } => (
                "platform.profile",
                "PATCH",
                "/v1/platform/auth/profile".into(),
            ),
            RotateReferral => (
                "platform.rotate_referral_code",
                "POST",
                "/v1/account/referral/code".into(),
            ),
            CreateOrg { .. } => (
                "platform.create_organization",
                "POST",
                "/v1/platform/organizations".into(),
            ),
            UpdateMember { org, account, .. } => (
                "platform.update_membership",
                "PATCH",
                org_path(org, &format!("/memberships/{account}")),
            ),
            RemoveMember { org, account } => (
                "platform.remove_membership",
                "DELETE",
                org_path(org, &format!("/memberships/{account}")),
            ),
            CreateInvite { org, .. } => {
                ("platform.create_invite", "POST", org_path(org, "/invites"))
            }
            RevokeInvite { org, id } => (
                "platform.revoke_invite",
                "DELETE",
                org_path(org, &format!("/invites/{id}")),
            ),
            AcceptInvite { token } => (
                "platform.accept_invite",
                "POST",
                format!("/v1/platform/invites/{token}/accept"),
            ),
        }
    }
    pub fn body(&self) -> Option<Value> {
        use Request::*;
        match self {
            CreateApiKey {
                id,
                api_key,
                settings,
            } => {
                let mut v = serde_json::to_value(settings).expect("serializable key settings");
                v["api_key_id"] = serde_json::json!(id);
                v["api_key"] = serde_json::json!(api_key);
                Some(v)
            }
            UpdateApiKey { settings, .. } => {
                Some(serde_json::to_value(settings).expect("serializable key settings"))
            }
            Profile { display_name } => Some(json!({"display_name":display_name})),
            CreateOrg { id, name } => Some(json!({"id":id,"name":name})),
            UpdateMember { role, .. } => Some(json!({"role":role})),
            CreateInvite {
                id,
                email,
                role,
                accept_token,
                ..
            } => Some(json!({"id":id,"email":email,"role":role,"accept_token":accept_token})),
            _ => None,
        }
    }
    pub fn history(&self) -> Option<&History> {
        match self {
            Self::Ledger { history, .. } | Self::Usage { history, .. } => Some(history),
            _ => None,
        }
    }
    pub fn identifiers(&self) -> Vec<&str> {
        use Request::*;
        match self {
            Members { org }
            | Invites { org }
            | Billing { org }
            | Invoices { org }
            | Subscriptions { org } => vec![org],
            Balance { org } | Ledger { org, .. } | Usage { org, .. } => {
                org.iter().map(String::as_str).collect()
            }
            UpdateMember { org, account, .. } | RemoveMember { org, account } => vec![org, account],
            CreateInvite {
                org,
                id,
                accept_token,
                ..
            } => vec![org, id, accept_token],
            RevokeInvite { org, id } => vec![org, id],
            CreateOrg { id, .. } => vec![id],
            AcceptInvite { token } => vec![token],
            _ => vec![],
        }
    }
}

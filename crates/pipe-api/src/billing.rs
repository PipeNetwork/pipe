//! Reviewed billing requests. CLI money is integer USD cents; legacy JSON numbers
//! are produced as exact decimal text only at the contract boundary.
use serde::{Deserialize, Serialize};
use serde_json::{json, Number, Value};
use uuid::Uuid;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum Request {
    CardConfig,
    CardHistory,
    CardCheckout {
        wallet: String,
        amount_cents: i64,
    },
    CardReconcile {
        id: Uuid,
    },
    Checkout {
        org: String,
        amount_cents: i64,
    },
    PlanCheckout {
        org: String,
        plan: String,
    },
    Portal {
        org: String,
    },
    Settings {
        org: String,
        enabled: bool,
        threshold_cents: Option<i64>,
        amount_cents: Option<i64>,
    },
    SolanaCreate {
        org: String,
        id: String,
        reference: String,
        amount_cents: i64,
    },
    SolanaVerify {
        org: String,
        id: String,
        signature: String,
    },
    SolanaSync {
        org: String,
        id: String,
    },
}
pub fn dollars(cents: i64) -> Number {
    let absolute = cents.unsigned_abs();
    format!(
        "{}{}.{:02}",
        if cents < 0 { "-" } else { "" },
        absolute / 100,
        absolute % 100
    )
    .parse()
    .expect("integer cents are an exact JSON decimal")
}

impl Request {
    pub fn operation(&self) -> (&'static str, &'static str, String) {
        use Request::*;
        let org = |org: &str, end: &str| format!("/v1/platform/organizations/{org}/billing/{end}");
        match self {
            CardConfig => (
                "infrastructure.stripe.config",
                "GET",
                "/v1/customer/billing/stripe/config".into(),
            ),
            CardHistory => (
                "infrastructure.stripe.history",
                "GET",
                "/v1/customer/billing/stripe/topups".into(),
            ),
            CardCheckout { .. } => (
                "infrastructure.stripe.checkout",
                "POST",
                "/v1/customer/billing/stripe/topups".into(),
            ),
            CardReconcile { id } => (
                "infrastructure.stripe.reconcile",
                "POST",
                format!("/v1/customer/billing/stripe/topups/{id}/reconcile"),
            ),
            Checkout { org: o, .. } => ("platform.billing.checkout", "POST", org(o, "checkout")),
            PlanCheckout { org: o, .. } => (
                "platform.billing.plan_checkout",
                "POST",
                org(o, "plan-checkout"),
            ),
            Portal { org: o } => ("platform.billing.portal", "POST", org(o, "portal")),
            Settings { org: o, .. } => ("platform.billing.settings", "POST", org(o, "settings")),
            SolanaCreate { org: o, .. } => {
                ("platform.solana.create", "POST", org(o, "solana-usdc"))
            }
            SolanaVerify { org: o, id, .. } => (
                "platform.solana.verify",
                "POST",
                org(o, &format!("solana-usdc/{id}/verify")),
            ),
            SolanaSync { org: o, id } => (
                "platform.solana.sync",
                "POST",
                org(o, &format!("solana-usdc/{id}/sync")),
            ),
        }
    }
    pub fn body(&self) -> Option<Value> {
        use Request::*;
        let success = "https://pipe.network/dashboard/billing?checkout=success";
        let cancel = "https://pipe.network/dashboard/billing?checkout=canceled";
        match self {
            CardCheckout {
                wallet,
                amount_cents,
            } => Some(json!({"wallet":wallet,"amount_cents":amount_cents})),
            Checkout { amount_cents, .. } => Some(
                json!({"amount_usd":dollars(*amount_cents),"success_url":success,"cancel_url":cancel}),
            ),
            PlanCheckout { plan, .. } => {
                Some(json!({"plan_id":plan,"success_url":success,"cancel_url":cancel}))
            }
            Portal { .. } => Some(json!({"return_url":"https://pipe.network/dashboard/billing"})),
            Settings {
                enabled,
                threshold_cents,
                amount_cents,
                ..
            } => Some(
                json!({"auto_recharge_enabled":enabled,"auto_recharge_threshold_usd":threshold_cents.map(dollars),"auto_recharge_amount_usd":amount_cents.map(dollars)}),
            ),
            SolanaCreate {
                id,
                reference,
                amount_cents,
                ..
            } => Some(json!({"id":id,"reference":reference,"amount_usd":dollars(*amount_cents)})),
            SolanaVerify { signature, .. } => Some(json!({"signature":signature})),
            _ => None,
        }
    }
    pub fn org(&self) -> Option<&str> {
        use Request::*;
        match self {
            Checkout { org, .. }
            | PlanCheckout { org, .. }
            | Portal { org }
            | Settings { org, .. }
            | SolanaCreate { org, .. }
            | SolanaVerify { org, .. }
            | SolanaSync { org, .. } => Some(org),
            _ => None,
        }
    }
    pub fn safe_resume(&self) -> bool {
        !matches!(self, Self::Settings { .. })
    }
}

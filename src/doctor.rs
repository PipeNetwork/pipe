//! Explicit diagnostics export. No automatic telemetry, tokens, bodies or key material.
use crate::{auth::ControlClient, output};
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::path::Path;
fn capabilities(v: &Value) -> Value {
    fn flags(v: &Value) -> Value {
        json!({"supported":v["supported"].as_bool(),"enabled":v["enabled"].as_bool(),"authorized":v["authorized"].as_bool()})
    }
    let mut features = serde_json::Map::new();
    for name in [
        "account",
        "storage",
        "compute",
        "hosting",
        "kv",
        "durable",
        "billing",
        "usage",
        "credentials",
        "platform_account",
        "organizations",
        "platform_billing",
        "account_api_keys",
        "infrastructure_card",
        "platform_solana_create",
    ] {
        if v["features"].get(name).is_some() {
            features.insert(name.into(), flags(&v["features"][name]));
        }
    }
    json!({"cli":flags(&v["cli"]),"features":features})
}
pub async fn run(c: &ControlClient, export: Option<&Path>, j: bool) -> Result<()> {
    if export.is_none() {
        return output::print(&c.get("/v1/cli/capabilities").await?, j);
    }
    let destination = export.unwrap();
    ensure!(
        !destination.exists(),
        "diagnostic destination already exists"
    );
    let status = match c.get("/v1/cli/capabilities").await {
        Ok(v) => json!({"capabilities":capabilities(&v)}),
        Err(e) => {
            let (code, exit) = crate::error::classification(&e);
            json!({"error_code":code,"exit_status":exit})
        }
    };
    let mut journals = Vec::new();
    for name in [
        "compute-journal-v1.json",
        "kv-state-v1.enc",
        "durable-state-v1.enc",
        "hosting-state-v1.enc",
        "customer-state-v1.enc",
        "billing-state-v1.enc",
    ] {
        match std::fs::symlink_metadata(c.secrets.state_directory().join(name)) {
            Ok(m) if m.file_type().is_file() => {
                journals.push(json!({"format":name,"bytes":m.len()}))
            }
            Ok(_) => journals.push(json!({"format":name,"unsupported_file_type":true})),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => journals.push(json!({"format":name,"metadata_unavailable":true})),
        }
    }
    let report = json!({"cli_version":env!("CARGO_PKG_VERSION"),"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"control_origin":reqwest::Url::parse(&c.profile.control_api_url)?.origin().ascii_serialization(),"status":status,"journal_metadata":journals,"telemetry_enabled":false});
    crate::keyring::atomic_private_write(
        destination,
        &serde_json::to_vec_pretty(&json!({"schema_version":1,"result":report}))?,
    )?;
    output::print(&json!({"exported":destination,"report":report}), j)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exported_capabilities_discard_all_non_boolean_remote_data() {
        let v = json!({"access_token":"sensitive","cli":{"supported":true,"enabled":false,"authorized":false,"token":"sensitive"},"features":{"storage":{"supported":true,"enabled":false,"authorized":"sensitive","secret":"sensitive"},"sensitive":{"supported":true}},"service_revision":"sensitive"});
        let result = capabilities(&v).to_string();
        assert!(!result.contains("sensitive"));
        assert!(result.contains("storage"));
    }
}

//! Platform credential and product dispatch.
pub use crate::advanced::{api, ApiCommands};
pub(crate) use crate::advanced::{operation, validate, validate_response};
use crate::{auth::ControlClient, output};
use anyhow::{anyhow, ensure, Result};
use clap::Subcommand;
use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
#[error(
    "activation outcome unknown for credential {id}; resume with pipe credentials activate {id}"
)]
pub struct ActivationUnknown {
    pub id: uuid::Uuid,
}

pub use crate::compute::Commands as ComputeCommands;
pub use crate::durable::Commands as DurableCommands;
pub use crate::hosting::Commands as HostingCommands;
pub use crate::kv::Commands as KvCommands;
pub async fn compute(c: &ControlClient, cmd: ComputeCommands, j: bool) -> Result<()> {
    crate::compute::run(c, cmd, j).await
}
pub async fn kv(c: &ControlClient, cmd: KvCommands, j: bool) -> Result<()> {
    crate::kv::run(c, cmd, j).await
}
pub async fn durable(c: &ControlClient, cmd: DurableCommands, j: bool) -> Result<()> {
    crate::durable::run(c, cmd, j).await
}
pub async fn hosting(c: &ControlClient, cmd: HostingCommands, j: bool) -> Result<()> {
    crate::hosting::run(c, cmd, j).await
}

#[derive(Subcommand, Debug)]
pub enum CredentialCommands {
    List,
    Create {
        #[arg(long)]
        label: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        owner_wallet: String,
        /// Exact canonical account from pipe context (omit for infrastructure-only identities).
        #[arg(long)]
        account_context: Option<String>,
        /// Grant all current and future owned resources for the selected product scopes.
        #[arg(long, conflicts_with = "resources")]
        account_access: bool,
        /// Limit organization scopes to this membership (repeatable).
        #[arg(long = "organization")]
        organizations: Vec<String>,
        /// Limit product scopes to KIND:UUID; kinds: compute_vm, kv_instance, durable_namespace, hosting_site.
        #[arg(long = "resource")]
        resources: Vec<String>,
        #[arg(long, default_value_t = 86400)]
        expires_in: u64,
    },
    Revoke {
        id: uuid::Uuid,
    },
    Activate {
        id: uuid::Uuid,
    },
    /// Inspect a securely saved active credential; --show-secret explicitly exports it.
    Export {
        id: uuid::Uuid,
    },
}
pub async fn credentials(client: &ControlClient, cmd: CredentialCommands, j: bool) -> Result<()> {
    match cmd {
        CredentialCommands::List => output::print(&client.get("/v1/cli/credentials").await?, j),
        CredentialCommands::Revoke { id } => output::print(
            &client.delete(&format!("/v1/cli/credentials/{id}")).await?,
            j,
        ),
        CredentialCommands::Create {
            label,
            scope,
            owner_wallet,
            account_context,
            account_access,
            organizations,
            resources,
            expires_in,
        } => {
            ensure!(
                (60..=2592000).contains(&expires_in),
                "credential expiry must be between 60 and 2592000 seconds"
            );
            ensure!(
                organizations.len() <= 32 && resources.len() <= 32,
                "select at most 32 organizations and 32 resources"
            );
            ensure!(
                account_access || !organizations.is_empty() || !resources.is_empty(),
                "select --account-access, --organization or --resource explicitly"
            );
            ensure!(
                !account_access || resources.is_empty(),
                "account-wide access cannot be combined with resource restrictions"
            );
            let resources: Vec<Value> = resources
                .iter()
                .map(|raw| {
                    let (kind, id) = raw
                        .split_once(':')
                        .ok_or_else(|| anyhow!("resource must be KIND:UUID"))?;
                    ensure!(
                        [
                            "compute_vm",
                            "kv_instance",
                            "durable_namespace",
                            "hosting_site"
                        ]
                        .contains(&kind),
                        "unsupported resource kind"
                    );
                    Ok(json!({"kind":kind,"id":id.parse::<uuid::Uuid>()?}))
                })
                .collect::<Result<_>>()?;
            let body = json!({"label":label,"scope":scope,"owner_wallet":owner_wallet,"account_context":account_context,"account_access":account_access,"organizations":organizations,"resources":resources,"expires_in":expires_in});
            let (_, _, op) = operation("platformCliCreateCredential")?;
            validate(
                &op["requestBody"]["content"]["application/json"]["schema"],
                &body,
            )?;
            client.secrets.set("storage-probe", "ready")?;
            client.secrets.delete("storage-probe")?;
            let value = client.post("/v1/cli/credentials", body).await?;
            validate_response("platformCliCreateCredential", "200", &value)?;
            let mut granted: Vec<&str> = value["scopes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            granted.sort_unstable();
            let mut requested: Vec<&str> = scope.split_ascii_whitespace().collect();
            requested.sort_unstable();
            requested.dedup();
            ensure!(value["owner_wallet"]==owner_wallet && value["account_context"]==json!(account_context) && value["account_access"]==account_access && value["resources"]==json!(resources)
                && granted==requested && value["organizations"].as_array().is_some_and(|items|items.len()==organizations.len() && items.iter().all(|o|o["id"].as_str().is_some_and(|id|organizations.iter().any(|v|v==id)))),
                "credential response changed the requested grants; inactive credential was not activated");
            let id = value["id"]
                .as_str()
                .ok_or_else(|| anyhow!("invalid credential response"))?
                .parse::<uuid::Uuid>()?;
            let secret = value["secret"]
                .as_str()
                .ok_or_else(|| anyhow!("missing automation secret"))?;
            ensure!(
                secret.starts_with("pcli_c_")
                    && secret.len() == 71
                    && secret[7..].bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid automation credential"
            );
            client.secrets.set(&format!("automation:{id}"), secret)?;
            let mut saved = value.clone();
            saved.as_object_mut().unwrap().remove("secret");
            client.secrets.set(
                &format!("automation-grant:{id}"),
                &serde_json::to_string(&saved)?,
            )?;
            activate(client, id).await?;
            output::print_automation(&value, j)
        }
        CredentialCommands::Activate { id } => output::print(&activate(client, id).await?, j),
        CredentialCommands::Export { id } => {
            let secret = client
                .secrets
                .get(&format!("automation:{id}"))?
                .ok_or_else(|| anyhow!("automation secret has not been saved locally"))?;
            let response = client
                .http
                .get(client.url("/v1/cli/context"))
                .bearer_auth(&secret)
                .send()
                .await
                .map_err(|e| e.without_url())?;
            if !response.status().is_success() {
                return Err(crate::error::response_error(response).await);
            }
            let context: Value =
                serde_json::from_slice(&crate::error::bounded_body(response, 65536).await?)?;
            validate_response("platformCliContext", "200", &context)?;
            ensure!(
                context["principal"]["credential_id"] == id.to_string()
                    && context["principal"]["credential_kind"] == "automation",
                "saved credential identity changed"
            );
            output::print_automation(
                &json!({"id":id,"secret":secret,"principal":context["principal"]}),
                j,
            )
        }
    }
}
async fn activate(client: &ControlClient, id: uuid::Uuid) -> Result<Value> {
    let secret = client
        .secrets
        .get(&format!("automation:{id}"))?
        .ok_or_else(|| anyhow!("automation secret has not been saved locally"))?;
    let response = client
        .http
        .post(client.url(&format!("/v1/cli/credentials/{id}/activate")))
        .bearer_auth(secret)
        .send()
        .await
        .map_err(|_| ActivationUnknown { id })?;
    if response.status().is_server_error()
        || response.status() == reqwest::StatusCode::REQUEST_TIMEOUT
    {
        return Err(ActivationUnknown { id }.into());
    }
    if !response.status().is_success() {
        return Err(crate::error::response_error(response).await);
    }
    let value: Value = serde_json::from_slice(
        &crate::error::bounded_body(response, 16384)
            .await
            .map_err(|_| ActivationUnknown { id })?,
    )
    .map_err(|_| ActivationUnknown { id })?;
    validate_response("platformCliActivateCredential", "200", &value)
        .map_err(|_| ActivationUnknown { id })?;
    if value["id"] != id.to_string() || value["activated"] != true {
        return Err(ActivationUnknown { id }.into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };
    fn request(resource: uuid::Uuid) -> CredentialCommands {
        CredentialCommands::Create {
            label: "CI".into(),
            scope: "kv.read".into(),
            owner_wallet: "owner".into(),
            account_context: None,
            account_access: false,
            organizations: vec![],
            resources: vec![format!("kv_instance:{resource}")],
            expires_in: 600,
        }
    }
    #[tokio::test]
    async fn credential_activation_preserves_saved_grants_after_lost_response() {
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
        let id = uuid::Uuid::new_v4();
        let resource = uuid::Uuid::new_v4();
        let secret = format!("pcli_c_{}", "a".repeat(64));
        let value = json!({"id":id,"secret":secret,"owner_wallet":"owner","account_context":null,"account_access":false,"organizations":[],"resources":[{"kind":"kv_instance","id":resource}],"scopes":["kv.read"],"expires_at":chrono::Utc::now().timestamp()+600});
        Mock::given(method("POST"))
            .and(path("/v1/cli/credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value))
            .expect(1)
            .mount(&server)
            .await;
        let store = c.secrets.clone();
        let expected = secret.clone();
        Mock::given(method("POST"))
            .and(path(format!("/v1/cli/credentials/{id}/activate")))
            .and(header("authorization", format!("Bearer {secret}")))
            .respond_with(move |_: &wiremock::Request| {
                assert_eq!(
                    store.get(&format!("automation:{id}")).unwrap().as_deref(),
                    Some(expected.as_str())
                );
                let grant: Value = serde_json::from_str(
                    &store
                        .get(&format!("automation-grant:{id}"))
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(grant["account_access"], false);
                assert_eq!(grant["resources"][0]["id"], resource.to_string());
                assert!(grant.get("secret").is_none());
                ResponseTemplate::new(503)
            })
            .expect(1)
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let unknown = credentials(&c, request(resource), true).await.unwrap_err();
        assert_eq!(
            crate::error::classification(&unknown),
            ("unknown_outcome", 8)
        );
        let disk = std::fs::read(root.path().join("secrets.json")).unwrap();
        assert!(!String::from_utf8_lossy(&disk).contains(&secret));
        drop(c);
        let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
        Mock::given(method("POST"))
            .and(path(format!("/v1/cli/credentials/{id}/activate")))
            .and(header("authorization", format!("Bearer {secret}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"id":id,"activated":true})),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(activate(&c, id).await.unwrap()["activated"], true);
        assert_eq!(
            c.secrets
                .get(&format!("automation:{id}"))
                .unwrap()
                .as_deref(),
            Some(secret.as_str())
        );
    }
    #[tokio::test]
    async fn changed_credential_grants_are_never_activated() {
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
        let id = uuid::Uuid::new_v4();
        let resource = uuid::Uuid::new_v4();
        let value = json!({"id":id,"secret":format!("pcli_c_{}","b".repeat(64)),"owner_wallet":"owner","account_context":null,"account_access":true,"organizations":[],"resources":[],"scopes":["kv.read"],"expires_at":chrono::Utc::now().timestamp()+600});
        Mock::given(method("POST"))
            .and(path("/v1/cli/credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value))
            .expect(1)
            .mount(&server)
            .await;
        assert!(credentials(&c, request(resource), true)
            .await
            .unwrap_err()
            .to_string()
            .contains("changed the requested grants"));
        assert!(c
            .secrets
            .get(&format!("automation:{id}"))
            .unwrap()
            .is_none());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    #[tokio::test]
    async fn credential_export_rechecks_identity_and_preserves_expired_material() {
        for status in [200, 401] {
            let server = MockServer::start().await;
            let root = tempfile::tempdir().unwrap();
            let c = ControlClient::for_test(Profile::new(server.uri()), root.path()).unwrap();
            let id = uuid::Uuid::new_v4();
            let secret = format!("pcli_c_{}", "c".repeat(64));
            c.secrets.set(&format!("automation:{id}"), &secret).unwrap();
            let context = json!({"principal":{"account_id":null,"owner_wallet":"owner","credential_id":uuid::Uuid::new_v4(),"credential_kind":"automation","scopes":["kv.read"],"account_access":false,"organizations":[],"resources":[{"kind":"kv_instance","id":uuid::Uuid::new_v4()}]},"contexts":[],"storage":{"endpoint":"https://gw-001.pipedev.network","region":"us-east-1"}});
            Mock::given(method("GET"))
                .and(path("/v1/cli/context"))
                .and(header("authorization", format!("Bearer {secret}")))
                .respond_with(ResponseTemplate::new(status).set_body_json(context))
                .expect(1)
                .mount(&server)
                .await;
            let error = credentials(&c, CredentialCommands::Export { id }, true)
                .await
                .unwrap_err();
            if status == 401 {
                assert_eq!(crate::error::classification(&error).1, 3);
            } else {
                assert!(error.to_string().contains("identity changed"));
            }
            assert_eq!(
                c.secrets
                    .get(&format!("automation:{id}"))
                    .unwrap()
                    .as_deref(),
                Some(secret.as_str())
            );
        }
    }
}

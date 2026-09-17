//! Legacy account keys are managed explicitly, never substituted for CLI tokens.
use crate::{auth::ControlClient, customer, customer_state::State, output};
use anyhow::{ensure, Context, Result};
use clap::{Args, Subcommand};
use pipe_api::{
    account::Request,
    keys::{Field, Settings},
};
use serde_json::json;
use uuid::Uuid;
#[derive(Subcommand, Debug)]
pub enum Commands {
    List,
    Create {
        #[command(flatten)]
        settings: Options,
    },
    Update {
        id: Uuid,
        #[command(flatten)]
        settings: Options,
    },
    Revoke {
        id: Uuid,
    },
    /// Recheck availability and export saved material only with --show-secret.
    Export {
        id: Uuid,
    },
}
#[derive(Args, Debug, Default)]
pub struct Options {
    #[arg(long, conflicts_with = "clear_label")]
    label: Option<String>,
    #[arg(long)]
    clear_label: bool,
    /// Exact JSON decimal USD amount; never converted by the CLI to a float.
    #[arg(long, conflicts_with = "clear_hard_cap")]
    hard_cap_usd: Option<String>,
    #[arg(long)]
    clear_hard_cap: bool,
    #[arg(long, conflicts_with = "clear_daily_cap")]
    daily_cap_usd: Option<String>,
    #[arg(long)]
    clear_daily_cap: bool,
    #[arg(long = "allowed-model", conflicts_with = "clear_models")]
    allowed_models: Vec<String>,
    #[arg(long)]
    clear_models: bool,
    #[arg(long,action=clap::ArgAction::Set)]
    no_retention: Option<bool>,
    #[arg(long,action=clap::ArgAction::Set)]
    disabled: Option<bool>,
}
impl Options {
    fn settings(self) -> Result<Settings> {
        fn amount(v: Option<String>, clear: bool) -> Result<Field<serde_json::Number>> {
            if clear {
                return Ok(Field::Null);
            }
            Ok(match v {
                None => Field::Missing,
                Some(v) => Field::Value(
                    serde_json::from_str::<serde_json::Number>(&v)
                        .context("cap must be a JSON decimal USD amount")?,
                ),
            })
        }
        Ok(Settings {
            label: if self.clear_label {
                Field::Null
            } else {
                self.label.map(Field::Value).unwrap_or_default()
            },
            hard_cap_usd: amount(self.hard_cap_usd, self.clear_hard_cap)?,
            daily_cap_usd: amount(self.daily_cap_usd, self.clear_daily_cap)?,
            allowed_models: if self.clear_models {
                Some(vec![])
            } else if self.allowed_models.is_empty() {
                None
            } else {
                Some(self.allowed_models)
            },
            no_retention: self.no_retention,
            disabled: self.disabled,
        })
    }
}
pub fn confirmation(c: &Commands) -> bool {
    matches!(
        c,
        Commands::Create { .. } | Commands::Update { .. } | Commands::Revoke { .. }
    )
}
pub async fn run(c: &ControlClient, command: Commands, j: bool) -> Result<()> {
    if matches!(command, Commands::List) {
        return output::print(&customer::read(c, &Request::ApiKeys).await?, j);
    }
    let b = customer::binding(c).await?;
    let request = match command {
        Commands::Create { settings } => Request::CreateApiKey {
            id: Uuid::new_v4(),
            api_key: format!("api_{}", Uuid::new_v4().simple()),
            settings: settings.settings()?,
        },
        Commands::Update { id, settings } => {
            let settings = settings.settings()?;
            ensure!(
                settings != Settings::default(),
                "specify the key settings to update"
            );
            Request::UpdateApiKey { id, settings }
        }
        Commands::Revoke { id } => Request::RevokeApiKey { id },
        Commands::Export { id } => {
            let s = State::load(c)?;
            let saved = s
                .requests
                .values()
                .find_map(|e| match &e.request {
                    Request::CreateApiKey {
                        id: expected,
                        api_key,
                        ..
                    } if *expected == id && e.binding == b => Some(api_key),
                    _ => None,
                })
                .context("account API key was not created in this profile/account")?;
            let keys = customer::read(c, &Request::ApiKeys).await?;
            let key = keys
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["id"] == id.to_string())
                .context("account API key no longer exists")?;
            ensure!(
                key["active"] == true
                    && key["revoked_at"].is_null()
                    && saved
                        .get(..12)
                        .is_some_and(|prefix| key["key_prefix"] == prefix),
                "account API key is disabled, revoked or its material changed"
            );
            return output::print_automation(
                &json!({"credential_type":"account_api_key","api_key_id":id,"user_id":key["user_id"],"secret":saved}),
                j,
            );
        }
        Commands::List => unreachable!(),
    };
    output::print(&customer::mutate(c, &b, request).await?, j)
}

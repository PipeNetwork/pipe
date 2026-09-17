//! Pipe platform CLI development client; preserves storage and payment protocols.
mod advanced;
mod doctor;

mod account;
mod account_keys;
mod auth;
mod cli;
mod compute;
mod compute_journal;
pub mod config;
mod crypto;
mod customer;
mod customer_state;
mod device;
mod durable;
mod durable_state;
mod error;
mod hosting;
mod hosting_state;
mod keyring;
mod kv;
mod kv_state;
mod output;
mod payments;
mod platform;
pub mod s3;
mod secretbox;
mod secure_state;
mod sigv4;
mod solana;
mod sync;
mod wallet_auth;

#[cfg(test)]
mod openapi_contract;

use clap::Parser;
pub use cli::Cli;

pub async fn run_cli() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let json = cli.json || matches!(cli.output, Some(output::Mode::Json | output::Mode::Jsonl));
    match cli::run(cli).await {
        Ok(()) => Ok(()),
        Err(error)
            if error.downcast_ref::<durable::ApplicationError>().is_some()
                || error.downcast_ref::<durable::Expired>().is_some() =>
        {
            Err(error)
        }
        Err(error) if json => {
            output::print(&error::document(&error), true)?;
            Err(error.context("command failed; see JSON output"))
        }
        Err(error) => Err(error),
    }
}

pub fn exit_status(error: &anyhow::Error) -> u8 {
    error::classification(error).1
}

pub fn error_message(error: &anyhow::Error) -> String {
    error::message(error)
}

mod billing_workflows;

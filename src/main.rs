use anyhow::Result;
use pipe::run_cli;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    run_cli().await
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::process::ExitCode {
    match pipe::run_cli().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", pipe::error_message(&error));
            std::process::ExitCode::from(pipe::exit_status(&error))
        }
    }
}

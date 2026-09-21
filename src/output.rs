use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Mode {
    Table,
    Json,
    Jsonl,
}
static MODE: AtomicU8 = AtomicU8::new(0);
static NO_INPUT: AtomicBool = AtomicBool::new(false);
static SHOW_SECRET: AtomicBool = AtomicBool::new(false);
pub fn is_jsonl() -> bool {
    MODE.load(Ordering::Relaxed) == 2
}
pub fn no_input() -> bool {
    NO_INPUT.load(Ordering::Relaxed)
}
pub fn configure(mode: Option<Mode>, no_input: bool, show_secret: bool) {
    MODE.store(
        match mode {
            None | Some(Mode::Table) => 0,
            Some(Mode::Json) => 1,
            Some(Mode::Jsonl) => 2,
        },
        Ordering::Relaxed,
    );
    NO_INPUT.store(no_input, Ordering::Relaxed);
    SHOW_SECRET.store(show_secret, Ordering::Relaxed);
}
pub fn require_input() -> anyhow::Result<()> {
    use std::io::IsTerminal;
    anyhow::ensure!(
        !NO_INPUT.load(Ordering::Relaxed) && std::io::stdin().is_terminal(),
        "interactive input unavailable; supply an explicit input file"
    );
    Ok(())
}
use serde::Serialize;
use serde_json::Value;

pub fn print<T: Serialize>(value: &T, json: bool) -> anyhow::Result<()> {
    let mut value = serde_json::to_value(value)?;
    redact(&mut value);
    render(&value, json)
}

pub fn print_credential(value: &Value, json: bool) -> anyhow::Result<()> {
    let mut safe = value.clone();
    let secret = safe.get("secret_access_key").cloned();
    redact(&mut safe);
    if let Some(secret) = secret.filter(|_| SHOW_SECRET.load(Ordering::Relaxed)) {
        safe["secret_access_key"] = secret;
    }
    render(&safe, json)
}

pub fn print_automation(value: &Value, json: bool) -> anyhow::Result<()> {
    let mut safe = value.clone();
    redact(&mut safe);
    if SHOW_SECRET.load(Ordering::Relaxed) {
        if let Some(secret) = value.get("secret") {
            safe["secret"] = secret.clone();
        }
    }
    render(&safe, json)
}

fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| {
                !matches!(
                    key.to_ascii_lowercase().as_str(),
                    "secret_access_key"
                        | "access_token"
                        | "refresh_token"
                        | "session_token"
                        | "private_key"
                        | "wallet_private_key"
                        | "password"
                        | "secret"
                        | "secret_key_hex"
                        | "authorization"
                        | "device_code"
                        | "token"
                        | "api_key"
                        | "accept_token"
                        | "accept_url"
                )
            });
            for value in map.values_mut() {
                redact(value);
            }
        }
        Value::Array(items) => {
            for item in items {
                redact(item);
            }
        }
        _ => {}
    }
}

fn render(value: &Value, json: bool) -> anyhow::Result<()> {
    let versioned = serde_json::json!({"schema_version":1,"result":value});
    match MODE.load(Ordering::Relaxed) {
        1 => {
            println!("{}", serde_json::to_string_pretty(&versioned)?);
            return Ok(());
        }
        2 => {
            println!("{}", serde_json::to_string(&versioned)?);
            return Ok(());
        }
        _ => {}
    }
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        let value = serde_json::to_value(value)?;
        print_human(&value, 0);
    }
    Ok(())
}

fn print_human(value: &Value, indent: usize) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                match value {
                    Value::Object(_) | Value::Array(_) => {
                        println!("{}{key}:", " ".repeat(indent));
                        print_human(value, indent + 2);
                    }
                    _ => println!("{}{key}: {}", " ".repeat(indent), scalar(value)),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                print!("{}- ", " ".repeat(indent));
                match item {
                    Value::Object(_) | Value::Array(_) => {
                        println!();
                        print_human(item, indent + 2);
                    }
                    _ => println!("{}", scalar(item)),
                }
            }
        }
        _ => println!("{}", scalar(value)),
    }
}

fn scalar(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "-".into(),
        _ => value.to_string(),
    }
}

/// Application data has arbitrary field names, including "secret" and "token".
/// Call only for a reviewed data result, never an authentication/credential body.
pub fn print_application(value: &Value, json: bool) -> anyhow::Result<()> {
    render(value, json)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_are_removed_recursively() {
        let mut value = serde_json::json!({"items":[{"secret_access_key":"secret","access_token":"token","name":"safe"}],"refresh_token":"refresh","accept_token":"invitation","accept_url":"https://fixture.test/invite/secret"});
        redact(&mut value);
        assert_eq!(value, serde_json::json!({"items":[{"name":"safe"}]}));
    }
}

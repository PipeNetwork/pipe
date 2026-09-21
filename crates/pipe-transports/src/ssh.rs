use anyhow::{ensure, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use pipe_api::compute::Ssh;
use sha2::{Digest, Sha256};
use std::{net::IpAddr, path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};

pub fn validate(connection: &Ssh) -> Result<&str> {
    let host = &connection.host;
    let dns = host.len() <= 253
        && host.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && s.as_bytes()[0].is_ascii_alphanumeric()
                && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    ensure!(
        host.parse::<IpAddr>().is_ok() || dns,
        "invalid advertised SSH hostname"
    );
    ensure!(
        connection.port > 0
            && !connection.user.is_empty()
            && connection.user.len() <= 64
            && connection
                .user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            && !connection.user.starts_with('-'),
        "invalid advertised SSH port or user"
    );
    let fingerprint = connection
        .host_key_fingerprint
        .as_deref()
        .context("SSH host identity is unavailable; wait for a verified host observation")?;
    let digest = fingerprint
        .strip_prefix("SHA256:")
        .context("unsupported SSH fingerprint format")?;
    ensure!(
        STANDARD_NO_PAD.decode(digest).is_ok_and(|v| v.len() == 32),
        "invalid SSH fingerprint"
    );
    Ok(fingerprint)
}

pub fn matching_key(line: &str, expected: &str) -> Result<(String, String)> {
    let parts: Vec<_> = line.split_ascii_whitespace().collect();
    ensure!(parts.len() == 3, "invalid SSH known-host record");
    ensure!(
        matches!(
            parts[1],
            "ssh-ed25519"
                | "ssh-rsa"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
        ),
        "unsupported SSH host key type"
    );
    ensure!(parts[2].len() <= 16384, "SSH key exceeds bound");
    let blob = STANDARD
        .decode(parts[2])
        .context("invalid SSH public key encoding")?;
    ensure!(blob.len() >= 4, "invalid SSH public key");
    let n = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
    ensure!(
        blob.get(4..4 + n) == Some(parts[1].as_bytes()),
        "SSH public key algorithm mismatch"
    );
    ensure!(
        format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob))) == expected,
        "SSH host key conflicts with advertised fingerprint"
    );
    Ok((parts[1].into(), parts[2].into()))
}

/// keyscan supplies untrusted public keys. Only the API-advertised digest can admit one.
pub async fn scan(connection: &Ssh) -> Result<(String, String)> {
    let fingerprint = validate(connection)?;
    let mut child = Command::new("ssh-keyscan")
        .args([
            "-T",
            "5",
            "-p",
            &connection.port.to_string(),
            &connection.host,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("OpenSSH ssh-keyscan is required")?;
    let mut stdout = child
        .stdout
        .take()
        .context("missing keyscan output")?
        .take(65537);
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stdout.read_to_end(&mut bytes))
        .await
        .context("SSH key discovery deadline reached")??;
    ensure!(
        bytes.len() <= 65536,
        "SSH key discovery response exceeds limit"
    );
    let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .context("SSH key discovery did not finish")??;
    ensure!(status.success(), "SSH key discovery failed");
    for line in std::str::from_utf8(&bytes)?.lines() {
        if let Ok(key) = matching_key(line, fingerprint) {
            return Ok(key);
        }
    }
    anyhow::bail!("SSH host key conflicts with advertised fingerprint")
}

pub fn command(
    connection: &Ssh,
    alias: &str,
    known_hosts: &Path,
    identity: Option<&Path>,
    remote: Option<&str>,
    batch: bool,
) -> Result<Command> {
    validate(connection)?;
    ensure!(
        alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid host alias"
    );
    let path = known_hosts
        .to_str()
        .context("known-host path must be UTF-8")?;
    ensure!(
        !path.chars().any(char::is_control),
        "invalid known-host path"
    );
    // -o values use OpenSSH's config lexer and percent expansion, even with no shell.
    let quoted = path
        .replace('%', "%%")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-F",
        "none",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "GlobalKnownHostsFile=none",
        "-o",
        "CheckHostIP=no",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ConnectTimeout=10",
    ])
    .arg("-o")
    .arg(format!("UserKnownHostsFile=\"{quoted}\""))
    .arg("-o")
    .arg(format!("HostKeyAlias={alias}"));
    if batch {
        cmd.args(["-o", "BatchMode=yes"]);
    }
    if let Some(identity) = identity {
        cmd.arg("-i")
            .arg(identity)
            .args(["-o", "IdentitiesOnly=yes"]);
    }
    cmd.arg("-p")
        .arg(connection.port.to_string())
        .arg("-l")
        .arg(&connection.user)
        .arg("--")
        .arg(&connection.host);
    if let Some(remote) = remote {
        cmd.arg(remote);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connection_metadata_cannot_inject_local_arguments_or_disable_host_identity() {
        let mut c = Ssh {
            host: "127.0.0.1".into(),
            port: 22,
            user: "ubuntu".into(),
            host_key_fingerprint: Some(format!("SHA256:{}", STANDARD_NO_PAD.encode([1; 32]))),
        };
        for bad in [
            "-oProxyCommand=bad",
            "host;bad",
            "$(bad)",
            "a,b",
            "a\nb",
            "[::1]:22",
        ] {
            c.host = bad.into();
            assert!(validate(&c).is_err());
        }
        c.host = "::1".into();
        validate(&c).unwrap();
        let cmd = command(
            &c,
            "pipe-vm",
            Path::new("/private/a b/known_hosts"),
            None,
            Some("echo $(remote-only)"),
            true,
        )
        .unwrap();
        let args: Vec<_> = cmd
            .as_std()
            .get_args()
            .map(|s| s.to_str().unwrap())
            .collect();
        assert!(args.contains(&"StrictHostKeyChecking=yes"));
        assert!(args.contains(&"BatchMode=yes"));
        assert_eq!(args.last(), Some(&"echo $(remote-only)"));
        c.host_key_fingerprint = None;
        assert!(validate(&c).is_err());
    }
}

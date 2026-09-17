//! A real disposable loopback sshd; no external host or existing credentials.
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use pipe_api::compute::Ssh;
use pipe_transports::ssh;
use sha2::{Digest, Sha256};
use std::{process::Stdio, time::Duration};
use tokio::process::Command;

#[tokio::test]
#[ignore = "requires PIPE_TEST_SSHD and installed OpenSSH ssh/keyscan/keygen"]
async fn actual_openssh_verifies_host_identity_and_propagates_remote_exit() {
    let daemon =
        std::env::var("PIPE_TEST_SSHD").expect("explicit disposable sshd executable required");
    let root = tempfile::tempdir().unwrap();
    let host = root.path().join("host");
    let identity = root.path().join("identity");
    for path in [&host, &identity] {
        assert!(Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .status()
            .await
            .unwrap()
            .success());
    }
    let public = std::fs::read_to_string(host.with_extension("pub")).unwrap();
    let mut parts = public.split_whitespace();
    let kind = parts.next().unwrap();
    let key = parts.next().unwrap();
    let fingerprint = format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(STANDARD.decode(key).unwrap()))
    );
    let auth = root.path().join("authorized_keys");
    std::fs::copy(identity.with_extension("pub"), &auth).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let username = Command::new("id").arg("-un").output().await.unwrap();
    let username = String::from_utf8(username.stdout)
        .unwrap()
        .trim()
        .to_owned();
    let config = root.path().join("sshd_config");
    std::fs::write(&config,format!("ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nUsePAM no\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAllowUsers {username}\nLogLevel ERROR\n",host.display(),root.path().join("pid").display(),auth.display())).unwrap();
    let log = std::fs::File::create(root.path().join("sshd.log")).unwrap();
    let mut server = Command::new(daemon)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        assert!(
            server.try_wait().unwrap().is_none(),
            "{}",
            std::fs::read_to_string(root.path().join("sshd.log")).unwrap()
        );
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut connection = Ssh {
        host: "127.0.0.1".into(),
        port,
        user: username,
        host_key_fingerprint: Some(fingerprint),
    };
    let scanned = ssh::scan(&connection).await.unwrap();
    assert_eq!(scanned, (kind.to_owned(), key.to_owned()));
    let known = root.path().join("known hosts with spaces");
    let record = format!("pipe-test {kind} {key}\n");
    std::fs::write(&known, &record).unwrap();
    let mut command = ssh::command(
        &connection,
        "pipe-test",
        &known,
        Some(&identity),
        Some("exit 37"),
        true,
    )
    .unwrap();
    command.stdin(Stdio::null());
    let status = command.status().await.unwrap();
    assert_eq!(
        status.code(),
        Some(37),
        "{}",
        std::fs::read_to_string(root.path().join("sshd.log")).unwrap()
    );
    connection.host_key_fingerprint = Some(format!("SHA256:{}", STANDARD_NO_PAD.encode([1; 32])));
    assert!(ssh::scan(&connection).await.is_err());
    assert!(
        ssh::matching_key(&record, connection.host_key_fingerprint.as_deref().unwrap()).is_err()
    );
    connection.host_key_fingerprint = None;
    assert!(ssh::command(&connection, "pipe-test", &known, None, None, true).is_err());
    server.kill().await.unwrap();
    server.wait().await.unwrap();
}

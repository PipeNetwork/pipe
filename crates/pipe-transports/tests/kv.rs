use pipe_transports::kv::{self, Command, Endpoint, Error, Reply};
use tokio::io::BufReader;

#[tokio::test]
async fn resp_bounds_precision_and_binary_values() {
    let mut r = BufReader::new(&b"*3\r\n$4\r\n\0\xff\r\n\r\n$-1\r\n:-9223372036854775808\r\n"[..]);
    assert_eq!(
        kv::read_reply(&mut r).await.unwrap(),
        Reply::Array(vec![
            Reply::Bulk(Some(vec![0, 255, 13, 10])),
            Reply::Bulk(None),
            Reply::Integer(i64::MIN)
        ])
    );
    for payload in [
        b"$1048577\r\n".as_slice(),
        b"*257\r\n",
        b"*1\r\n*1\r\n*1\r\n*1\r\n",
        b":9223372036854775808\r\n",
        b"$1\r\na!!",
        b"_\r\n",
        b"+OK\n",
        b"$-2\r\n",
    ] {
        assert!(
            kv::read_reply(&mut BufReader::new(payload)).await.is_err(),
            "{payload:?}"
        );
    }
    for prefix in [
        "UNKNOWN",
        "COMMITTED",
        "ERR signature validation failed",
        "FUTURE_ERROR",
    ] {
        let payload = format!("-{prefix} secret-value\r\n");
        let e = kv::read_reply(&mut BufReader::new(payload.as_bytes()))
            .await
            .unwrap_err();
        assert!(matches!(e.downcast_ref::<Error>(), Some(Error::Unknown)));
        assert!(!e.to_string().contains("secret-value"));
    }
}
#[test]
fn only_supported_commands_and_verified_endpoints() {
    for args in [
        vec!["MSET", "a", "b"],
        vec!["SET", "a", "b", "NX", "XX"],
        vec!["SCAN", "0", "COUNT", "257"],
        vec!["INCRBY", "a", "9223372036854775808"],
        vec!["EXPIRE", "a", "9223372036854775807"],
        vec!["INCRBY", "a", "01"],
    ] {
        assert!(Command::new(args.iter().map(|s| s.as_bytes().to_vec()).collect()).is_err());
    }
    assert!(Command::new(vec![b"GET".to_vec(), vec![0; 1025]]).is_err());
    assert!(Command::new(vec![
        b"SET".to_vec(),
        b"key".to_vec(),
        vec![0; 1024 * 1024 + 1]
    ])
    .is_err());
    for endpoint in [
        "redis://localhost:6380",
        "rediss://user:secret@localhost:6380",
        "rediss://localhost/path",
        "rediss://localhost:6380?x=y",
        "rediss://localhost:0",
    ] {
        assert!(Endpoint::parse(endpoint).is_err());
    }
    let v = Endpoint::parse("rediss://[::1]:6380").unwrap();
    assert_eq!(v.host, "::1");
    assert!(
        Command::new(vec![b"INCRBY".to_vec(), b"key".to_vec(), b"-1".to_vec()])
            .unwrap()
            .mutation
    );
}

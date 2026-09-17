//! The supported Pipe KV RESP2 subset. Every connection verifies TLS and every
//! exchange is sent at most once. A failed forwarded write has an unknown outcome.
use anyhow::{bail, ensure, Context, Result};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_rustls::{rustls, TlsConnector};

pub const MAX_KEY: usize = 1024;
pub const MAX_VALUE: usize = 1024 * 1024;
pub const MAX_KEYS: usize = 128;
pub const MAX_SCAN: usize = 256;
pub const MAX_RESPONSE: usize = 8 * 1024 * 1024;
const MAX_REQUEST: usize = MAX_VALUE + MAX_KEYS * MAX_KEY + 4096;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("KV connection or response failed; no automatic retry was performed")]
    Transport,
    #[error("KV mutation outcome is unknown; inspect the data before issuing another mutation")]
    Unknown,
    #[error("KV credential was rejected")]
    Authentication,
    #[error("KV command is outside the credential's permissions")]
    Authorization,
    #[error("KV service is unavailable")]
    Unavailable,
    #[error("KV server rejected the command ({0})")]
    Rejected(&'static str),
}
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Simple(Vec<u8>),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
    Array(Vec<Reply>),
}
#[derive(Debug)]
pub struct Command {
    args: Vec<Vec<u8>>,
    pub mutation: bool,
}
impl Command {
    pub fn new(args: Vec<Vec<u8>>) -> Result<Self> {
        let name = args.first().context("missing KV command")?.as_slice();
        let key = |b: &[u8]| -> Result<()> {
            ensure!(b.len() <= MAX_KEY, "KV key exceeds 1024 bytes");
            Ok(())
        };
        let integer = |b: &[u8]| -> Result<i64> {
            let s = std::str::from_utf8(b)?;
            let n: i64 = s.parse()?;
            ensure!(
                n.to_string() == s,
                "KV integer must be canonical signed 64-bit decimal"
            );
            Ok(n)
        };
        let mut mutation = false;
        match name {
            b"GET" | b"TTL" | b"PTTL" | b"PERSIST" => {
                ensure!(args.len() == 2, "expected one key");
                key(&args[1])?;
                mutation = name == b"PERSIST";
            }
            b"MGET" | b"DEL" | b"EXISTS" => {
                ensure!(
                    (2..=MAX_KEYS + 1).contains(&args.len()),
                    "expected 1..128 keys"
                );
                for k in &args[1..] {
                    key(k)?;
                }
                mutation = name == b"DEL";
            }
            b"SET" => {
                ensure!((3..=6).contains(&args.len()), "invalid SET arguments");
                key(&args[1])?;
                ensure!(args[2].len() <= MAX_VALUE, "KV value exceeds 1 MiB");
                let (mut condition, mut expiry, mut i) = (false, false, 3);
                while i < args.len() {
                    match args[i].as_slice() {
                        b"NX" | b"XX" => {
                            ensure!(!condition, "duplicate SET condition");
                            condition = true;
                            i += 1;
                        }
                        b"EX" | b"PX" => {
                            ensure!(!expiry && i + 1 < args.len(), "invalid SET expiry");
                            let n = integer(&args[i + 1])?;
                            ensure!(n > 0, "SET expiry must be positive");
                            if args[i] == b"EX" {
                                n.checked_mul(1000).context("expiry overflow")?;
                            }
                            expiry = true;
                            i += 2;
                        }
                        _ => bail!("unsupported SET option"),
                    }
                }
                mutation = true;
            }
            b"INCRBY" | b"DECRBY" | b"EXPIRE" | b"PEXPIRE" => {
                ensure!(args.len() == 3, "expected key and integer");
                key(&args[1])?;
                let n = integer(&args[2])?;
                if name == b"EXPIRE" {
                    n.checked_mul(1000).context("expiry overflow")?;
                }
                if name == b"DECRBY" {
                    n.checked_neg().context("counter overflow")?;
                }
                mutation = true;
            }
            b"SCAN" => {
                ensure!((2..=6).contains(&args.len()), "invalid SCAN arguments");
                std::str::from_utf8(&args[1])?.parse::<u64>()?;
                let (mut pattern, mut count, mut i) = (false, false, 2);
                while i < args.len() {
                    ensure!(i + 1 < args.len(), "missing SCAN option value");
                    match args[i].as_slice() {
                        b"MATCH" => {
                            ensure!(!pattern, "duplicate MATCH");
                            key(&args[i + 1])?;
                            pattern = true;
                        }
                        b"COUNT" => {
                            ensure!(!count, "duplicate COUNT");
                            let n = integer(&args[i + 1])?;
                            ensure!((1..=MAX_SCAN as i64).contains(&n), "COUNT must be 1..256");
                            count = true;
                        }
                        _ => bail!("unsupported SCAN option"),
                    }
                    i += 2;
                }
            }
            _ => bail!("unsupported Pipe KV command"),
        }
        let command = Self { args, mutation };
        ensure!(
            command.encoded().len() <= MAX_REQUEST,
            "KV request exceeds frame limit"
        );
        Ok(command)
    }
    pub fn name(&self) -> &str {
        std::str::from_utf8(&self.args[0]).unwrap()
    }
    pub fn encoded(&self) -> Vec<u8> {
        encode(&self.args)
    }
    fn valid_reply(&self, reply: &Reply) -> bool {
        match self.name() {
            "GET" => matches!(reply, Reply::Bulk(_)),
            "SET" => {
                matches!(reply, Reply::Simple(v) if v == b"OK")
                    || matches!(reply, Reply::Bulk(None))
            }
            "MGET" => {
                matches!(reply, Reply::Array(v) if v.len() == self.args.len()-1 && v.iter().all(|r| matches!(r,Reply::Bulk(_))))
            }
            "SCAN" => matches!(reply, Reply::Array(v) if v.len() == 2
                && matches!(&v[0], Reply::Bulk(Some(cursor)) if std::str::from_utf8(cursor).ok().and_then(|s|s.parse::<u64>().ok()).is_some())
                && matches!(&v[1],Reply::Array(keys) if keys.len() <= MAX_SCAN && keys.iter().all(|r| matches!(r,Reply::Bulk(Some(k)) if k.len()<=MAX_KEY)))),
            _ => matches!(reply, Reply::Integer(_)),
        }
    }
}
fn encode(args: &[Vec<u8>]) -> Vec<u8> {
    let mut v = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        v.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        v.extend_from_slice(arg);
        v.extend_from_slice(b"\r\n");
    }
    v
}
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}
impl Endpoint {
    pub fn parse(value: &str) -> Result<Self> {
        let url = url::Url::parse(value).context("invalid KV endpoint")?;
        ensure!(
            url.scheme() == "rediss"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && matches!(url.path(), "" | "/"),
            "KV endpoint must be rediss://host:port without credentials, path, query or fragment"
        );
        let host = match url.host().context("KV endpoint requires a host")? {
            url::Host::Domain(v) => v.to_owned(),
            url::Host::Ipv4(v) => v.to_string(),
            url::Host::Ipv6(v) => v.to_string(),
        };
        let port = url.port().unwrap_or(6380);
        ensure!(port != 0, "KV port must be positive");
        rustls::pki_types::ServerName::try_from(host.clone()).context("invalid TLS name")?;
        Ok(Self { host, port })
    }
}
pub fn tls_config(ca: Option<&Path>) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024 * 1024, "CA bundle exceeds 1 MiB");
        let certs =
            rustls_pemfile::certs(&mut bytes.as_slice()).collect::<std::io::Result<Vec<_>>>()?;
        ensure!(!certs.is_empty(), "CA bundle contains no certificates");
        for cert in certs {
            roots.add(cert)?;
        }
    }
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ))
}
/// One authenticated exchange. There is intentionally no reconnect/replay loop.
pub async fn execute(
    endpoint: &Endpoint,
    tls: Arc<rustls::ClientConfig>,
    credential: &str,
    secret: &str,
    command: &Command,
    timeout: Duration,
) -> Result<Reply> {
    ensure!(
        uuid::Uuid::parse_str(credential).is_ok(),
        "invalid KV credential ID"
    );
    ensure!(
        secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid KV credential secret"
    );
    let connection = async {
        let tcp = tokio::net::TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await?;
        tcp.set_nodelay(true)?;
        let name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())?;
        let stream = TlsConnector::from(tls).connect(name, tcp).await?;
        Ok::<_, anyhow::Error>(BufReader::new(stream))
    };
    let mut stream = tokio::time::timeout(timeout, connection)
        .await
        .map_err(|_| Error::Transport)?
        .map_err(|_| Error::Transport)?;
    let auth = async {
        stream
            .write_all(&encode(&[
                b"AUTH".to_vec(),
                credential.as_bytes().to_vec(),
                secret.as_bytes().to_vec(),
            ]))
            .await?;
        stream.flush().await?;
        match read_reply(&mut stream).await? {
            Reply::Simple(v) if v == b"OK" => Ok::<_, anyhow::Error>(()),
            _ => Err(Error::Authentication.into()),
        }
    };
    match tokio::time::timeout(timeout, auth).await {
        Ok(Ok(())) => {}
        Ok(Err(e))
            if matches!(
                e.downcast_ref::<Error>(),
                Some(
                    Error::Authentication
                        | Error::Authorization
                        | Error::Unavailable
                        | Error::Rejected(_)
                )
            ) =>
        {
            return Err(e)
        }
        _ => return Err(Error::Transport.into()),
    }
    let exchange = async {
        stream.write_all(&command.encoded()).await?;
        stream.flush().await?;
        let reply = read_reply(&mut stream).await?;
        ensure!(command.valid_reply(&reply), "unexpected KV response type");
        Ok::<_, anyhow::Error>(reply)
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(e)) if e.downcast_ref::<Error>().is_some() => Err(e),
        _ => Err(if command.mutation {
            Error::Unknown
        } else {
            Error::Transport
        }
        .into()),
    }
}
async fn line<R: AsyncBufRead + Unpin>(r: &mut R, budget: &mut usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    for _ in 0..1024 {
        ensure!(*budget > 0, "KV response exceeds 8 MiB");
        *budget -= 1;
        let b = r.read_u8().await?;
        v.push(b);
        if b == b'\n' {
            ensure!(
                v.len() >= 2 && v[v.len() - 2] == b'\r',
                "invalid RESP terminator"
            );
            v.truncate(v.len() - 2);
            return Ok(v);
        }
    }
    bail!("RESP header too long")
}
fn server_error(bytes: &[u8]) -> Error {
    // Only documented failures before commitment establish rejection. An
    // unrecognized gateway/node error can follow a committed mutation.
    if matches!(
        bytes,
        b"ERR increment or decrement would overflow"
            | b"ERR value is not an integer or out of range"
            | b"ERR invalid expire time"
            | b"ERR syntax error or unsupported option"
            | b"ERR unsupported command"
            | b"ERR key exceeds 1024 bytes"
            | b"ERR expected 1 to 128 keys"
            | b"ERR value exceeds 1 MiB"
    ) {
        return Error::Rejected("ERR");
    }
    match bytes.split(|b| *b == b' ').next().unwrap_or_default() {
        b"UNKNOWN" | b"COMMITTED" => Error::Unknown,
        b"NOCREDIT" => Error::Rejected("NOCREDIT"),
        b"NOAUTH" | b"WRONGPASS" => Error::Authentication,
        b"NOPERM" => Error::Authorization,
        b"TRYAGAIN" | b"LOADING" | b"BUSY" | b"CLUSTERDOWN" => Error::Unavailable,
        b"WRONGTYPE" => Error::Rejected("WRONGTYPE"),
        _ => Error::Unknown,
    }
}
pub async fn read_reply<R: AsyncBufRead + Unpin>(r: &mut R) -> Result<Reply> {
    async fn parse<R: AsyncBufRead + Unpin>(
        r: &mut R,
        budget: &mut usize,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<Reply> {
        ensure!(
            depth <= 2 && *nodes < 1024,
            "RESP nesting/element limit exceeded"
        );
        *nodes += 1;
        let header = line(r, budget).await?;
        let (prefix, body) = header.split_first().context("empty RESP header")?;
        match prefix {
            b'+' => Ok(Reply::Simple(body.to_vec())),
            b'-' => Err(server_error(body).into()),
            b':' => Ok(Reply::Integer(std::str::from_utf8(body)?.parse::<i64>()?)),
            b'$' => {
                let n = std::str::from_utf8(body)?.parse::<i64>()?;
                if n == -1 {
                    return Ok(Reply::Bulk(None));
                }
                ensure!(
                    (0..=MAX_VALUE as i64).contains(&n),
                    "RESP bulk size exceeds 1 MiB"
                );
                let n = n as usize;
                ensure!(n + 2 <= *budget, "KV response exceeds 8 MiB");
                *budget -= n + 2;
                let mut bytes = vec![0; n];
                r.read_exact(&mut bytes).await?;
                ensure!(r.read_u16().await? == 0x0d0a, "invalid bulk terminator");
                Ok(Reply::Bulk(Some(bytes)))
            }
            b'*' => {
                let n = std::str::from_utf8(body)?.parse::<usize>()?;
                ensure!(n <= MAX_SCAN, "RESP array size exceeds 256");
                let mut values = Vec::with_capacity(n);
                for _ in 0..n {
                    values.push(Box::pin(parse(r, budget, nodes, depth + 1)).await?);
                }
                Ok(Reply::Array(values))
            }
            _ => bail!("unsupported RESP reply type"),
        }
    }
    let mut budget = MAX_RESPONSE;
    parse(r, &mut budget, &mut 0, 0).await
}

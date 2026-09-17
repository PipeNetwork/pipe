//! Bounded encrypted journals with small, profile-specific keys in the secure store.
use crate::auth::ControlClient;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Context, Result};
use std::io::Read;
pub struct Spec<'a> {
    pub file: &'a str,
    pub key: &'a str,
    pub magic: &'a [u8; 8],
    pub limit: usize,
}
pub fn read(c: &ControlClient, s: &Spec<'_>) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let file = match std::fs::File::open(c.secrets.state_directory().join(s.file)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take((s.limit + 37) as u64).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() >= 36 && bytes.len() <= s.limit + 36 && bytes.starts_with(s.magic),
        "invalid encrypted journal; original file preserved"
    );
    let key = zeroize::Zeroizing::new(
        c.secrets
            .get(s.key)?
            .context("journal encryption key is missing; preserve recovery state")?,
    );
    let key = zeroize::Zeroizing::new(hex::decode(key.as_str())?);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow::anyhow!("invalid journal key"))?;
    let clear = cipher
        .decrypt(
            &Nonce::from(<[u8; 12]>::try_from(&bytes[8..20])?),
            Payload {
                msg: &bytes[20..],
                aad: s.magic,
            },
        )
        .map_err(|_| anyhow::anyhow!("journal authentication failed; original file preserved"))?;
    Ok(Some(zeroize::Zeroizing::new(clear)))
}
pub fn write(c: &ControlClient, s: &Spec<'_>, clear: &[u8]) -> Result<()> {
    ensure!(
        clear.len() <= s.limit,
        "journal size limit reached; preserve recovery state"
    );
    let key = match c.secrets.get(s.key)? {
        Some(key) => key,
        None => {
            let key = hex::encode(rand::random::<[u8; 32]>());
            c.secrets.set(s.key, &key)?;
            key
        }
    };
    let key = zeroize::Zeroizing::new(key);
    let key = zeroize::Zeroizing::new(hex::decode(key.as_str())?);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow::anyhow!("invalid journal key"))?;
    let nonce = rand::random::<[u8; 12]>();
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: clear,
                aad: s.magic,
            },
        )
        .map_err(|_| anyhow::anyhow!("journal encryption failed"))?;
    let mut bytes = s.magic.to_vec();
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    crate::keyring::atomic_private_write(&c.secrets.state_directory().join(s.file), &bytes)
}

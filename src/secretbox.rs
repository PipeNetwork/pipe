//! Explicit encrypted local secret fallback. Format is independent of PIPEENC2.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, ensure, Result};
use rand::RngCore;
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"PIPESEC3";
fn cipher(password: &str, salt: &[u8]) -> Result<Aes256Gcm> {
    let mut key = Zeroizing::new([0u8; 32]);
    let params = argon2::Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|_| anyhow!("invalid secret KDF parameters"))?;
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|_| anyhow!("secret key derivation failed"))?;
    Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow!("secret cipher failed"))
}
pub fn seal(clear: &[u8], password: &str) -> Result<Vec<u8>> {
    ensure!(
        password.len() >= 12,
        "secret storage password must contain at least 12 characters"
    );
    let mut header = vec![0; 36];
    header[..8].copy_from_slice(MAGIC);
    rand::rngs::OsRng.fill_bytes(&mut header[8..]);
    let encrypted = cipher(password, &header[8..24])?
        .encrypt(
            &Nonce::from(<[u8; 12]>::try_from(&header[24..36])?),
            Payload {
                msg: clear,
                aad: &header,
            },
        )
        .map_err(|_| anyhow!("secret encryption failed"))?;
    header.extend(encrypted);
    Ok(header)
}
pub fn open(sealed: &[u8], password: &str) -> Result<Vec<u8>> {
    ensure!(
        sealed.len() >= 52 && sealed.len() <= 16 * 1024 * 1024 && &sealed[..8] == MAGIC,
        "unsupported or corrupt secret store"
    );
    cipher(password, &sealed[8..24])?
        .decrypt(
            &Nonce::from(<[u8; 12]>::try_from(&sealed[24..36])?),
            Payload {
                msg: &sealed[36..],
                aad: &sealed[..36],
            },
        )
        .map_err(|_| anyhow!("incorrect password or corrupt secret store"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_and_randomized() {
        let p = "test-fallback-password";
        let a = seal(b"secret", p).unwrap();
        assert_ne!(a, seal(b"secret", p).unwrap());
        assert_eq!(open(&a, p).unwrap(), b"secret");
        assert!(open(&a, "incorrect").is_err());
        let mut b = a.clone();
        b[10] ^= 1;
        assert!(open(&b, p).is_err());
        assert!(!a.windows(6).any(|v| v == b"secret"));
    }
}

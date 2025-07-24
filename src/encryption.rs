use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of the AES-256 key in bytes
const KEY_SIZE: usize = 32;

/// Size of the GCM nonce in bytes
pub const NONCE_SIZE: usize = 12;

/// Size of the GCM authentication tag in bytes
const TAG_SIZE: usize = 16;

/// Size of the salt for password derivation
const SALT_SIZE: usize = 32;

/// Chunk size for streaming encryption (64KB)
const CHUNK_SIZE: usize = 65536;

/// Magic bytes to identify encrypted files
const MAGIC_BYTES: &[u8] = b"PIPE-ENC";

/// Version of the encryption format
const VERSION: u8 = 1;

/// Secure container for encryption keys that zeroes memory on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey {
    pub key: [u8; KEY_SIZE],
}

/// Header for encrypted files
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedFileHeader {
    /// Magic bytes for file identification
    magic: [u8; 8],
    /// Version of the encryption format
    version: u8,
    /// Salt used for password derivation (if applicable)
    salt: Option<[u8; SALT_SIZE]>,
    /// Nonce for AES-GCM
    nonce: [u8; NONCE_SIZE],
}

impl EncryptedFileHeader {
    fn new(salt: Option<[u8; SALT_SIZE]>, nonce: [u8; NONCE_SIZE]) -> Self {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(MAGIC_BYTES);

        Self {
            magic,
            version: VERSION,
            salt,
            nonce,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 1 + 1 + SALT_SIZE + NONCE_SIZE);
        bytes.extend_from_slice(&self.magic);
        bytes.push(self.version);

        // Write salt presence flag
        if let Some(salt) = &self.salt {
            bytes.push(1);
            bytes.extend_from_slice(salt);
        } else {
            bytes.push(0);
            bytes.extend_from_slice(&[0u8; SALT_SIZE]);
        }

        bytes.extend_from_slice(&self.nonce);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 + 1 + 1 + SALT_SIZE + NONCE_SIZE {
            return Err(anyhow!("Invalid header size"));
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);

        if magic != MAGIC_BYTES.as_ref() {
            return Err(anyhow!("Not an encrypted file"));
        }

        let version = bytes[8];
        if version != VERSION {
            return Err(anyhow!("Unsupported encryption version"));
        }

        let has_salt = bytes[9] == 1;
        let salt = if has_salt {
            let mut salt_bytes = [0u8; SALT_SIZE];
            salt_bytes.copy_from_slice(&bytes[10..10 + SALT_SIZE]);
            Some(salt_bytes)
        } else {
            None
        };

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[10 + SALT_SIZE..10 + SALT_SIZE + NONCE_SIZE]);

        Ok(Self {
            magic,
            version,
            salt,
            nonce,
        })
    }

    fn size() -> usize {
        8 + 1 + 1 + SALT_SIZE + NONCE_SIZE
    }
}

/// Derives an encryption key from a password using Argon2id
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<EncryptionKey> {
    let argon2 = Argon2::default();
    let salt_string =
        SaltString::encode_b64(salt).map_err(|e| anyhow!("Failed to encode salt: {}", e))?;

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| anyhow!("Failed to hash password: {}", e))?;

    let hash_bytes = password_hash
        .hash
        .ok_or_else(|| anyhow!("No hash generated"))?;
    let hash_vec = hash_bytes.as_bytes();

    if hash_vec.len() < KEY_SIZE {
        return Err(anyhow!("Hash too short"));
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&hash_vec[..KEY_SIZE]);

    Ok(EncryptionKey { key })
}

/// Generates a random salt for password derivation
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Encrypts data using AES-256-GCM with the provided key
pub fn encrypt_data(data: &[u8], key: &EncryptionKey) -> Result<(Vec<u8>, [u8; NONCE_SIZE])> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce_bytes, data)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    Ok((ciphertext, nonce))
}

/// Decrypts data using AES-256-GCM with the provided key and nonce
pub fn decrypt_data(
    ciphertext: &[u8],
    key: &EncryptionKey,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {}. This usually means the password is incorrect or the file is corrupted.", e))?;

    Ok(plaintext)
}

/// Encrypts a file with password-based encryption
pub async fn encrypt_file_with_password<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    password: &str,
    progress_callback: Option<Box<dyn Fn(usize) + Send>>,
) -> Result<()> {
    // Generate salt and derive key
    let salt = generate_salt();
    let key = derive_key_from_password(password, &salt)?;

    // Generate nonce
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    // Write header
    let header = EncryptedFileHeader::new(Some(salt), nonce);
    writer.write_all(&header.to_bytes())?;

    // Encrypt file in chunks
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut total_encrypted = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        // For each chunk, we need a unique nonce
        let mut chunk_nonce = nonce;
        // Add chunk counter to nonce to ensure uniqueness
        let counter = (total_encrypted / CHUNK_SIZE) as u64;
        chunk_nonce[..8].copy_from_slice(&counter.to_le_bytes());

        let chunk_data = &buffer[..bytes_read];
        let nonce_obj = Nonce::from_slice(&chunk_nonce);

        let ciphertext = cipher
            .encrypt(nonce_obj, chunk_data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Write chunk size and encrypted data
        writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        writer.write_all(&ciphertext)?;

        total_encrypted += bytes_read;

        if let Some(ref callback) = progress_callback {
            callback(bytes_read);
        }
    }

    Ok(())
}

/// Decrypts a file with password-based encryption
pub async fn decrypt_file_with_password<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    password: &str,
    progress_callback: Option<Box<dyn Fn(usize) + Send>>,
) -> Result<()> {
    // Read header
    let mut header_bytes = vec![0u8; EncryptedFileHeader::size()];
    reader.read_exact(&mut header_bytes)?;
    let header = EncryptedFileHeader::from_bytes(&header_bytes)?;

    // Derive key from password
    let salt = header.salt.ok_or_else(|| anyhow!("No salt in header"))?;
    let key = derive_key_from_password(password, &salt)?;

    // Decrypt file in chunks
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    let base_nonce = header.nonce;
    let mut chunk_counter = 0u64;

    loop {
        // Read chunk size
        let mut size_bytes = [0u8; 4];
        match reader.read_exact(&mut size_bytes) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let chunk_size = u32::from_le_bytes(size_bytes) as usize;
        if chunk_size == 0 || chunk_size > CHUNK_SIZE + TAG_SIZE {
            return Err(anyhow!("Invalid chunk size"));
        }

        // Read encrypted chunk
        let mut ciphertext = vec![0u8; chunk_size];
        reader.read_exact(&mut ciphertext)?;

        // Prepare chunk nonce
        let mut chunk_nonce = base_nonce;
        chunk_nonce[..8].copy_from_slice(&chunk_counter.to_le_bytes());
        let nonce_obj = Nonce::from_slice(&chunk_nonce);

        // Decrypt chunk
        let plaintext = cipher
            .decrypt(nonce_obj, ciphertext.as_ref())
            .map_err(|e| {
                anyhow!(
                    "Decryption failed at chunk {}: {}. Wrong password or corrupted file?",
                    chunk_counter,
                    e
                )
            })?;

        writer.write_all(&plaintext)?;

        if let Some(ref callback) = progress_callback {
            callback(plaintext.len());
        }

        chunk_counter += 1;
    }

    Ok(())
}

/// Check if a file is encrypted by reading the magic bytes
pub fn is_encrypted_file<R: Read + Seek>(mut reader: R) -> Result<bool> {
    let mut magic = [0u8; 8];
    match reader.read_exact(&mut magic) {
        Ok(_) => {
            // Reset the reader position
            reader.seek(SeekFrom::Start(0))?;
            Ok(magic == MAGIC_BYTES.as_ref())
        }
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let data = b"Hello, world! This is a test of encryption.";
        let password = "test_password_123";

        // Encrypt
        let mut encrypted = Vec::new();
        let reader = Cursor::new(data);
        encrypt_file_with_password(reader, &mut encrypted, password, None)
            .await
            .unwrap();

        // Decrypt
        let mut decrypted = Vec::new();
        let reader = Cursor::new(encrypted);
        decrypt_file_with_password(reader, &mut decrypted, password, None)
            .await
            .unwrap();

        assert_eq!(data.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_key_derivation() {
        let password = "test_password";
        let salt = generate_salt();

        let key1 = derive_key_from_password(password, &salt).unwrap();
        let key2 = derive_key_from_password(password, &salt).unwrap();

        // Same password and salt should produce same key
        assert_eq!(key1.key, key2.key);

        // Different salt should produce different key
        let salt2 = generate_salt();
        let key3 = derive_key_from_password(password, &salt2).unwrap();
        assert_ne!(key1.key, key3.key);
    }
}

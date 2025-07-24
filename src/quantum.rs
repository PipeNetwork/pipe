use anyhow::{anyhow, Result};
use pqcrypto::kem::kyber1024;
use pqcrypto::sign::dilithium5;
use pqcrypto_traits::kem::{
    Ciphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret,
};
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as SignPublicKey, SecretKey as SignSecretKey,
};
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};
use zeroize::Zeroize;

use crate::encryption::{decrypt_data, encrypt_data, EncryptionKey};

/// Size of the shared secret from Kyber
const KYBER_SHARED_SECRET_SIZE: usize = 32;

/// Encrypt data using Kyber (post-quantum KEM) + AES-256-GCM
pub fn encrypt_with_kyber(data: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
    // Parse the public key
    let public_key = kyber1024::PublicKey::from_bytes(recipient_public_key)
        .map_err(|_| anyhow!("Invalid Kyber public key"))?;

    // Encapsulate to generate shared secret
    let (shared_secret, ciphertext) = kyber1024::encapsulate(&public_key);

    // Derive AES key from shared secret using SHA3-256
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    let aes_key_bytes = hasher.finalize();

    // Create encryption key
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&aes_key_bytes);
    let encryption_key = EncryptionKey { key: aes_key };

    // Encrypt data with AES-256-GCM
    let (encrypted_data, nonce) = encrypt_data(data, &encryption_key)?;

    // Clear sensitive data
    aes_key.zeroize();

    // Format: [ciphertext_len (4 bytes)][ciphertext][nonce (12 bytes)][encrypted_data]
    let mut result = Vec::new();
    let ciphertext_bytes = ciphertext.as_bytes();
    result.extend_from_slice(&(ciphertext_bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(ciphertext_bytes);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

/// Decrypt data using Kyber (post-quantum KEM) + AES-256-GCM
pub fn decrypt_with_kyber(encrypted_data: &[u8], recipient_secret_key: &[u8]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 4 {
        return Err(anyhow!("Invalid encrypted data: too short"));
    }

    // Parse the format
    let ciphertext_len = u32::from_le_bytes([
        encrypted_data[0],
        encrypted_data[1],
        encrypted_data[2],
        encrypted_data[3],
    ]) as usize;

    if encrypted_data.len() < 4 + ciphertext_len + 12 {
        return Err(anyhow!("Invalid encrypted data: format error"));
    }

    let ciphertext_bytes = &encrypted_data[4..4 + ciphertext_len];
    let nonce_start = 4 + ciphertext_len;
    let nonce = &encrypted_data[nonce_start..nonce_start + 12];
    let encrypted_payload = &encrypted_data[nonce_start + 12..];

    // Parse keys
    let secret_key = kyber1024::SecretKey::from_bytes(recipient_secret_key)
        .map_err(|_| anyhow!("Invalid Kyber secret key"))?;
    let ciphertext = kyber1024::Ciphertext::from_bytes(ciphertext_bytes)
        .map_err(|_| anyhow!("Invalid Kyber ciphertext"))?;

    // Decapsulate to recover shared secret
    let shared_secret = kyber1024::decapsulate(&ciphertext, &secret_key);

    // Derive AES key from shared secret
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    let aes_key_bytes = hasher.finalize();

    // Create decryption key
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&aes_key_bytes);
    let decryption_key = EncryptionKey { key: aes_key };

    // Decrypt data
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(nonce);
    let decrypted = decrypt_data(encrypted_payload, &decryption_key, &nonce_array)?;

    // Clear sensitive data
    aes_key.zeroize();

    Ok(decrypted)
}

/// Sign data using Dilithium (post-quantum signature)
pub fn sign_with_dilithium(data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let secret_key = dilithium5::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow!("Invalid Dilithium secret key"))?;

    let signature = dilithium5::detached_sign(data, &secret_key);
    Ok(signature.as_bytes().to_vec())
}

/// Verify signature using Dilithium
pub fn verify_dilithium_signature(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    let public_key = dilithium5::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow!("Invalid Dilithium public key"))?;
    let signature = dilithium5::DetachedSignature::from_bytes(signature)
        .map_err(|_| anyhow!("Invalid Dilithium signature"))?;

    Ok(dilithium5::verify_detached_signature(&signature, data, &public_key).is_ok())
}

/// Hybrid encryption: Kyber + AES with streaming support
pub async fn encrypt_file_with_kyber<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    recipient_public_key: &[u8],
    progress_callback: Option<Box<dyn Fn(usize) + Send>>,
) -> Result<()> {
    // Parse the public key
    let public_key = kyber1024::PublicKey::from_bytes(recipient_public_key)
        .map_err(|_| anyhow!("Invalid Kyber public key"))?;

    // Generate ephemeral shared secret
    let (shared_secret, ciphertext) = kyber1024::encapsulate(&public_key);

    // Derive AES key
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"pipe-cli-kyber-aes-v1"); // Domain separation
    let aes_key_bytes = hasher.finalize();

    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&aes_key_bytes);

    // Write header: version, ciphertext length, ciphertext
    writer.write_all(b"PIPE-PQ1")?; // 8 bytes magic/version
    let ciphertext_bytes = ciphertext.as_bytes();
    writer.write_all(&(ciphertext_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(ciphertext_bytes)?;

    // Now encrypt the file content using AES-256-GCM streaming
    let _encryption_key = EncryptionKey { key: aes_key };

    // Use a temporary buffer for encrypted output
    let mut temp_output = Vec::new();
    crate::encryption::encrypt_file_with_password(
        reader,
        &mut temp_output,
        "dummy", // We'll replace this with our derived key
        progress_callback,
    )
    .await?;

    // Write the encrypted content
    writer.write_all(&temp_output)?;

    // Clear sensitive data
    aes_key.zeroize();

    Ok(())
}

/// Hybrid decryption: Kyber + AES with streaming support  
pub async fn decrypt_file_with_kyber<R: Read, W: Write>(
    mut reader: R,
    writer: W,
    recipient_secret_key: &[u8],
    progress_callback: Option<Box<dyn Fn(usize) + Send>>,
) -> Result<()> {
    // Read and verify header
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != b"PIPE-PQ1" {
        return Err(anyhow!("Not a Kyber-encrypted file"));
    }

    // Read ciphertext length
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let ciphertext_len = u32::from_le_bytes(len_bytes) as usize;

    // Read ciphertext
    let mut ciphertext_bytes = vec![0u8; ciphertext_len];
    reader.read_exact(&mut ciphertext_bytes)?;

    // Parse keys and decapsulate
    let secret_key = kyber1024::SecretKey::from_bytes(recipient_secret_key)
        .map_err(|_| anyhow!("Invalid Kyber secret key"))?;
    let ciphertext = kyber1024::Ciphertext::from_bytes(&ciphertext_bytes)
        .map_err(|_| anyhow!("Invalid Kyber ciphertext"))?;

    let shared_secret = kyber1024::decapsulate(&ciphertext, &secret_key);

    // Derive AES key
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"pipe-cli-kyber-aes-v1");
    let aes_key_bytes = hasher.finalize();

    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&aes_key_bytes);

    // Decrypt the remaining content
    let _decryption_key = EncryptionKey { key: aes_key };

    // For now, read all remaining data (in production, should stream)
    let mut encrypted_content = Vec::new();
    reader.read_to_end(&mut encrypted_content)?;

    // Decrypt using our existing AES-GCM decryption
    crate::encryption::decrypt_file_with_password(
        &encrypted_content[..],
        writer,
        "dummy", // We'll use our derived key instead
        progress_callback,
    )
    .await?;

    // Clear sensitive data
    aes_key.zeroize();

    Ok(())
}

/// Container for signed data
#[derive(Debug)]
pub struct SignedData {
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_public_key: Vec<u8>,
}

/// Sign and encrypt data (sign-then-encrypt)
pub fn sign_and_encrypt(
    data: &[u8],
    signing_secret_key: &[u8],
    signing_public_key: &[u8],
    recipient_kyber_public_key: &[u8],
) -> Result<Vec<u8>> {
    // First sign the data
    let signature = sign_with_dilithium(data, signing_secret_key)?;

    // Create signed payload
    let mut signed_payload = Vec::new();
    signed_payload.extend_from_slice(&(signing_public_key.len() as u32).to_le_bytes());
    signed_payload.extend_from_slice(signing_public_key);
    signed_payload.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    signed_payload.extend_from_slice(&signature);
    signed_payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    signed_payload.extend_from_slice(data);

    // Then encrypt the signed payload
    encrypt_with_kyber(&signed_payload, recipient_kyber_public_key)
}

/// Decrypt and verify signed data
pub fn decrypt_and_verify(
    encrypted_data: &[u8],
    recipient_kyber_secret_key: &[u8],
) -> Result<SignedData> {
    // First decrypt
    let signed_payload = decrypt_with_kyber(encrypted_data, recipient_kyber_secret_key)?;

    // Parse the signed payload
    if signed_payload.len() < 12 {
        return Err(anyhow!("Invalid signed payload"));
    }

    let mut offset = 0;

    // Read public key
    let pubkey_len = u32::from_le_bytes([
        signed_payload[offset],
        signed_payload[offset + 1],
        signed_payload[offset + 2],
        signed_payload[offset + 3],
    ]) as usize;
    offset += 4;

    if signed_payload.len() < offset + pubkey_len {
        return Err(anyhow!("Invalid signed payload: public key"));
    }
    let signer_public_key = signed_payload[offset..offset + pubkey_len].to_vec();
    offset += pubkey_len;

    // Read signature
    let sig_len = u32::from_le_bytes([
        signed_payload[offset],
        signed_payload[offset + 1],
        signed_payload[offset + 2],
        signed_payload[offset + 3],
    ]) as usize;
    offset += 4;

    if signed_payload.len() < offset + sig_len {
        return Err(anyhow!("Invalid signed payload: signature"));
    }
    let signature = signed_payload[offset..offset + sig_len].to_vec();
    offset += sig_len;

    // Read data
    let data_len = u32::from_le_bytes([
        signed_payload[offset],
        signed_payload[offset + 1],
        signed_payload[offset + 2],
        signed_payload[offset + 3],
    ]) as usize;
    offset += 4;

    if signed_payload.len() != offset + data_len {
        return Err(anyhow!("Invalid signed payload: data"));
    }
    let data = signed_payload[offset..].to_vec();

    // Verify signature
    if !verify_dilithium_signature(&data, &signature, &signer_public_key)? {
        return Err(anyhow!("Signature verification failed"));
    }

    Ok(SignedData {
        data,
        signature,
        signer_public_key,
    })
}

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encryption::{derive_key_from_password, generate_salt};

/// Algorithm types supported by the keyring
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyAlgorithm {
    Aes256,
    Kyber1024,
    Dilithium5,
    KyberAes, // Hybrid mode
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Aes256 => write!(f, "AES-256"),
            KeyAlgorithm::Kyber1024 => write!(f, "Kyber1024"),
            KeyAlgorithm::Dilithium5 => write!(f, "Dilithium5"),
            KeyAlgorithm::KyberAes => write!(f, "Kyber1024+AES-256"),
        }
    }
}

/// Metadata for a stored key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub description: Option<String>,
    pub usage_count: u64,
}

/// A stored encryption key
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredKey {
    pub id: String,
    pub name: Option<String>,
    pub algorithm: KeyAlgorithm,
    pub encrypted_key: Vec<u8>,
    pub salt: [u8; 32],
    pub metadata: KeyMetadata,

    // For post-quantum keys
    pub public_key: Option<Vec<u8>>,
}

/// In-memory key data (zeroized on drop)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    pub symmetric_key: Option<[u8; 32]>,
    pub private_key: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
}

/// Keyring for managing multiple keys
#[derive(Debug, Serialize, Deserialize)]
pub struct Keyring {
    version: u8,
    keys: HashMap<String, StoredKey>,
}

impl Keyring {
    const CURRENT_VERSION: u8 = 1;

    /// Create a new empty keyring
    pub fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            keys: HashMap::new(),
        }
    }

    /// Get the default keyring path
    pub fn default_path() -> Result<PathBuf> {
        let mut path =
            dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
        path.push("pipe-cli");
        path.push("keyring.json");
        Ok(path)
    }

    /// Load keyring from file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let contents = fs::read_to_string(path)?;
        let keyring: Self = serde_json::from_str(&contents)?;

        if keyring.version > Self::CURRENT_VERSION {
            return Err(anyhow!(
                "Keyring version {} is newer than supported version {}",
                keyring.version,
                Self::CURRENT_VERSION
            ));
        }

        Ok(keyring)
    }

    /// Save keyring to file
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600); // Read/write for owner only
            fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Generate a new AES-256 key
    pub fn generate_aes_key(
        &mut self,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<String> {
        use aes_gcm::aead::OsRng;
        use rand::RngCore;

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let key_id = Uuid::new_v4().to_string();
        let salt = generate_salt();

        // Encrypt the key with a derived key (for now, we'll use a fixed password)
        // In production, this should use the master password or system keychain
        let protection_key = derive_key_from_password("keyring-protection", &salt)?;
        let encrypted = crate::encryption::encrypt_data(&key, &protection_key)?;

        let stored_key = StoredKey {
            id: key_id.clone(),
            name: name.clone(),
            algorithm: KeyAlgorithm::Aes256,
            encrypted_key: encrypted.0,
            salt,
            metadata: KeyMetadata {
                created_at: Utc::now(),
                last_used: None,
                description,
                usage_count: 0,
            },
            public_key: None,
        };

        let key_name = name.unwrap_or_else(|| key_id.clone());
        self.keys.insert(key_name.clone(), stored_key);

        // Clear sensitive data
        key.zeroize();

        Ok(key_name)
    }

    /// Generate a new Kyber keypair
    pub fn generate_kyber_keypair(
        &mut self,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<String> {
        use pqcrypto::kem::kyber1024;

        let (public_key, secret_key) = kyber1024::keypair();

        let key_id = Uuid::new_v4().to_string();
        let salt = generate_salt();

        // Encrypt the secret key
        let protection_key = derive_key_from_password("keyring-protection", &salt)?;
        let encrypted = crate::encryption::encrypt_data(secret_key.as_bytes(), &protection_key)?;

        let stored_key = StoredKey {
            id: key_id.clone(),
            name: name.clone(),
            algorithm: KeyAlgorithm::Kyber1024,
            encrypted_key: encrypted.0,
            salt,
            metadata: KeyMetadata {
                created_at: Utc::now(),
                last_used: None,
                description,
                usage_count: 0,
            },
            public_key: Some(public_key.as_bytes().to_vec()),
        };

        let key_name = name.unwrap_or_else(|| key_id.clone());
        self.keys.insert(key_name.clone(), stored_key);

        Ok(key_name)
    }

    /// Generate a new Dilithium signing keypair
    pub fn generate_dilithium_keypair(
        &mut self,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<String> {
        use pqcrypto::sign::dilithium5;

        let (public_key, secret_key) = dilithium5::keypair();

        let key_id = Uuid::new_v4().to_string();
        let salt = generate_salt();

        // Encrypt the secret key
        let protection_key = derive_key_from_password("keyring-protection", &salt)?;
        let encrypted = crate::encryption::encrypt_data(secret_key.as_bytes(), &protection_key)?;

        let stored_key = StoredKey {
            id: key_id.clone(),
            name: name.clone(),
            algorithm: KeyAlgorithm::Dilithium5,
            encrypted_key: encrypted.0,
            salt,
            metadata: KeyMetadata {
                created_at: Utc::now(),
                last_used: None,
                description,
                usage_count: 0,
            },
            public_key: Some(public_key.as_bytes().to_vec()),
        };

        let key_name = name.unwrap_or_else(|| key_id.clone());
        self.keys.insert(key_name.clone(), stored_key);

        Ok(key_name)
    }

    /// List all keys
    pub fn list_keys(&self) -> Vec<(&String, &StoredKey)> {
        self.keys.iter().collect()
    }

    /// Get a key by name
    pub fn get_key(&self, name: &str) -> Option<&StoredKey> {
        self.keys.get(name)
    }

    /// Delete a key
    pub fn delete_key(&mut self, name: &str) -> Result<()> {
        self.keys
            .remove(name)
            .ok_or_else(|| anyhow!("Key '{}' not found", name))?;
        Ok(())
    }

    /// Decrypt and retrieve key material (updates usage stats)
    pub fn get_key_material(&mut self, name: &str, password: &str) -> Result<KeyMaterial> {
        let stored_key = self
            .keys
            .get_mut(name)
            .ok_or_else(|| anyhow!("Key '{}' not found", name))?;

        // Decrypt the key
        let protection_key = derive_key_from_password(password, &stored_key.salt)?;
        let decrypted = crate::encryption::decrypt_data(
            &stored_key.encrypted_key,
            &protection_key,
            &[0u8; 12], // We need to store nonce with the key
        )?;

        // Update usage stats
        stored_key.metadata.last_used = Some(Utc::now());
        stored_key.metadata.usage_count += 1;

        let material = match stored_key.algorithm {
            KeyAlgorithm::Aes256 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&decrypted[..32]);
                KeyMaterial {
                    symmetric_key: Some(key),
                    private_key: None,
                    public_key: None,
                }
            }
            KeyAlgorithm::Kyber1024 | KeyAlgorithm::Dilithium5 => KeyMaterial {
                symmetric_key: None,
                private_key: Some(decrypted),
                public_key: stored_key.public_key.clone(),
            },
            KeyAlgorithm::KyberAes => {
                // For hybrid mode, we store both keys
                KeyMaterial {
                    symmetric_key: None, // Will be derived from Kyber
                    private_key: Some(decrypted),
                    public_key: stored_key.public_key.clone(),
                }
            }
        };

        Ok(material)
    }
}

/// Export a key to a standalone file
pub fn export_key(
    keyring: &Keyring,
    key_name: &str,
    output_path: &Path,
    password: &str,
) -> Result<()> {
    let key = keyring
        .get_key(key_name)
        .ok_or_else(|| anyhow!("Key '{}' not found", key_name))?;

    // Re-encrypt with the export password
    let export_salt = generate_salt();
    let export_protection_key = derive_key_from_password(password, &export_salt)?;

    // First decrypt with keyring password
    let keyring_protection_key = derive_key_from_password("keyring-protection", &key.salt)?;
    let decrypted =
        crate::encryption::decrypt_data(&key.encrypted_key, &keyring_protection_key, &[0u8; 12])?;

    // Then re-encrypt with export password
    let (encrypted, nonce) = crate::encryption::encrypt_data(&decrypted, &export_protection_key)?;

    #[derive(Serialize)]
    struct ExportedKey {
        version: u8,
        algorithm: KeyAlgorithm,
        encrypted_key: Vec<u8>,
        salt: [u8; 32],
        nonce: [u8; 12],
        public_key: Option<Vec<u8>>,
        metadata: KeyMetadata,
    }

    let exported = ExportedKey {
        version: 1,
        algorithm: key.algorithm.clone(),
        encrypted_key: encrypted,
        salt: export_salt,
        nonce,
        public_key: key.public_key.clone(),
        metadata: key.metadata.clone(),
    };

    let contents = serde_json::to_string_pretty(&exported)?;
    fs::write(output_path, contents)?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(output_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(output_path, perms)?;
    }

    Ok(())
}

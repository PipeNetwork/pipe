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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub id: String,
    pub name: Option<String>,
    pub algorithm: KeyAlgorithm,
    pub encrypted_key: Vec<u8>,
    pub salt: [u8; 32],
    #[serde(default = "default_nonce")]
    pub nonce: [u8; 12], // Required for AES-GCM decryption
    pub metadata: KeyMetadata,

    // For post-quantum keys
    pub public_key: Option<Vec<u8>>,
}

// Default nonce for backward compatibility (existing keys won't have this field)
fn default_nonce() -> [u8; 12] {
    [0u8; 12]
}

/// In-memory key data (zeroized on drop)
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    pub symmetric_key: Option<[u8; 32]>,
    pub private_key: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
}

/// Password verification data
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordVerification {
    /// Encrypted known value to verify password
    pub encrypted_verifier: Vec<u8>,
    /// Salt for password verification
    pub salt: [u8; 32],
    /// Nonce for verification
    pub nonce: [u8; 12],
}

/// Keyring for managing multiple keys
#[derive(Debug, Serialize, Deserialize)]
pub struct Keyring {
    version: u8,
    keys: HashMap<String, StoredKey>,
    /// Password verification data (new in version 2)
    #[serde(skip_serializing_if = "Option::is_none")]
    password_verification: Option<PasswordVerification>,
    /// Migration flag to detect legacy keyrings
    #[serde(default = "default_legacy_mode")]
    legacy_mode: bool,
}

fn default_legacy_mode() -> bool {
    false
}

impl Keyring {
    const CURRENT_VERSION: u8 = 2;
    const LEGACY_VERSION: u8 = 1;
    const PASSWORD_VERIFIER: &'static [u8] = b"pipe-cli-keyring-v2-verified";

    /// Create a new empty keyring
    pub fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            keys: HashMap::new(),
            password_verification: None,
            legacy_mode: false,
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
        let mut keyring: Self = serde_json::from_str(&contents)?;

        // Check if this is a legacy keyring
        if keyring.version == Self::LEGACY_VERSION || keyring.password_verification.is_none() {
            keyring.legacy_mode = true;
            eprintln!("⚠️  Warning: Legacy keyring detected. Keys are encrypted with default password.");
            eprintln!("   Please migrate your keyring by running: pipe keyring-migrate");
        }

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

    /// Initialize master password for the keyring
    pub fn initialize_password(&mut self, password: &str) -> Result<()> {
        if self.password_verification.is_some() && !self.legacy_mode {
            return Err(anyhow!("Keyring already has a master password"));
        }

        let salt = generate_salt();
        let protection_key = derive_key_from_password(password, &salt)?;
        let (encrypted_verifier, nonce) = crate::encryption::encrypt_data(Self::PASSWORD_VERIFIER, &protection_key)?;

        self.password_verification = Some(PasswordVerification {
            encrypted_verifier,
            salt,
            nonce,
        });
        self.version = Self::CURRENT_VERSION;
        self.legacy_mode = false;

        Ok(())
    }

    /// Verify the master password
    pub fn verify_password(&self, password: &str) -> Result<bool> {
        // Legacy mode: accept both the hardcoded password and user's new password
        if self.legacy_mode {
            return Ok(password == "keyring-protection");
        }

        let verification = self.password_verification.as_ref()
            .ok_or_else(|| anyhow!("No password set for keyring"))?;

        let protection_key = derive_key_from_password(password, &verification.salt)?;
        
        match crate::encryption::decrypt_data(
            &verification.encrypted_verifier,
            &protection_key,
            &verification.nonce,
        ) {
            Ok(decrypted) => Ok(decrypted == Self::PASSWORD_VERIFIER),
            Err(_) => Ok(false),
        }
    }

    /// Get the appropriate password for key operations
    fn get_key_password(&self, user_password: &str) -> String {
        if self.legacy_mode {
            // For legacy keyrings, always use the hardcoded password
            "keyring-protection".to_string()
        } else {
            user_password.to_string()
        }
    }

    /// Migrate a legacy keyring to use a user-defined password
pub fn migrate_from_legacy(&mut self, old_password: &str, new_password: &str) -> Result<()> {
    if !self.legacy_mode {
        return Err(anyhow!("Keyring is not in legacy mode"));
    }

    // Verify the old password (should be "keyring-protection")
    if old_password != "keyring-protection" {
        return Err(anyhow!("Invalid legacy password"));
    }

    // Re-encrypt all keys with the new password
    let mut updated_keys = HashMap::new();

    for (name, mut stored_key) in self.keys.clone() {
        // Decrypt with old password
        if stored_key.encrypted_key.len() < 16 {
            return Err(anyhow!("Ciphertext too short for AES-GCM decryption"));
        }
        let old_protection_key = derive_key_from_password(old_password, &stored_key.salt)?;
        let decrypted = crate::encryption::decrypt_data(
            &stored_key.encrypted_key,
            &old_protection_key,
            &stored_key.nonce,
        )?;

        // Re-encrypt with new password
        let new_salt = generate_salt();
        let new_protection_key = derive_key_from_password(new_password, &new_salt)?;
        let (encrypted_key, nonce) = crate::encryption::encrypt_data(&decrypted, &new_protection_key)?;

        stored_key.encrypted_key = encrypted_key;
        stored_key.salt = new_salt;
        stored_key.nonce = nonce;

        updated_keys.insert(name, stored_key);
    }

    // Update keyring
    self.keys = updated_keys;
    self.initialize_password(new_password)?;

    Ok(())
}

    /// Generate a new AES-256 key
    pub fn generate_aes_key(
        &mut self,
        name: Option<String>,
        description: Option<String>,
        password: &str,
    ) -> Result<String> {
        // Verify password if not in legacy mode
        if !self.legacy_mode && !self.verify_password(password)? {
            return Err(anyhow!("Invalid keyring password"));
        }

        use aes_gcm::aead::OsRng;
        use rand::RngCore;

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let key_id = Uuid::new_v4().to_string();
        let salt = generate_salt();

        // Use the appropriate password based on mode
        let key_password = self.get_key_password(password);
        let protection_key = derive_key_from_password(&key_password, &salt)?;
        let (encrypted_key, nonce) = crate::encryption::encrypt_data(&key, &protection_key)?;

        let stored_key = StoredKey {
            id: key_id.clone(),
            name: name.clone(),
            algorithm: KeyAlgorithm::Aes256,
            encrypted_key,
            salt,
            nonce,
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
        password: &str,
    ) -> Result<String> {
        // Verify password if not in legacy mode
        if !self.legacy_mode && !self.verify_password(password)? {
            return Err(anyhow!("Invalid keyring password"));
        }

        use pqcrypto_mlkem::mlkem1024 as kyber1024;

        let (public_key, secret_key) = kyber1024::keypair();

        let key_id = Uuid::new_v4().to_string();
        let salt = generate_salt();

        // Use the appropriate password based on mode
        let key_password = self.get_key_password(password);
        let protection_key = derive_key_from_password(&key_password, &salt)?;
        let (encrypted_key, nonce) = crate::encryption::encrypt_data(secret_key.as_bytes(), &protection_key)?;

        let stored_key = StoredKey {
            id: key_id.clone(),
            name: name.clone(),
            algorithm: KeyAlgorithm::Kyber1024,
            encrypted_key,
            salt,
            nonce,
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
        password: &str,
    ) -> Result<String> {
        // Verify password if not in legacy mode
        if !self.legacy_mode && !self.verify_password(password)? {
            return Err(anyhow!("Invalid keyring password"));
        }

        use pqcrypto_mldsa::mldsa87 as dilithium5;

        let (public_key, secret_key) = dilithium5::keypair();

        let key_id = Uuid::new_v4().to_string();
        let salt = generate_salt();

        // Use the appropriate password based on mode
        let key_password = self.get_key_password(password);
        let protection_key = derive_key_from_password(&key_password, &salt)?;
        let (encrypted_key, nonce) = crate::encryption::encrypt_data(secret_key.as_bytes(), &protection_key)?;

        let stored_key = StoredKey {
            id: key_id.clone(),
            name: name.clone(),
            algorithm: KeyAlgorithm::Dilithium5,
            encrypted_key,
            salt,
            nonce,
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
        // Use the appropriate password based on mode
        let key_password = self.get_key_password(password);
        
        let stored_key = self
            .keys
            .get_mut(name)
            .ok_or_else(|| anyhow!("Key '{}' not found", name))?;

        // Decrypt the key
        let protection_key = derive_key_from_password(&key_password, &stored_key.salt)?;

        if stored_key.algorithm == KeyAlgorithm::KyberAes {
            // For hybrid keys, we need to handle both Kyber and AES
            let kyber_key = stored_key.public_key.as_ref()
                .ok_or_else(|| anyhow!("Kyber public key not found"))?;
            
            let decrypted = crate::encryption::decrypt_data(
                &stored_key.encrypted_key,
                &protection_key,
                &stored_key.nonce,
            )?;

            // Derive symmetric key from Kyber
            let symmetric_key = crate::encryption::derive_symmetric_key_from_kyber(&decrypted, kyber_key)?;

            return Ok(KeyMaterial {
                symmetric_key: Some(symmetric_key),
                private_key: None,
                public_key: Some(kyber_key.clone()),
            });
        }
        if stored_key.encrypted_key.len() < 16 {
            return Err(anyhow!("Ciphertext too short for AES-GCM decryption"));
        }

        let decrypted = crate::encryption::decrypt_data(
            &stored_key.encrypted_key,
            &protection_key,
            &stored_key.nonce,
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

    /// Get reference to keys
    pub fn keys(&self) -> &HashMap<String, StoredKey> {
        &self.keys
    }

    /// Check if keyring has a password set
    pub fn has_password(&self) -> bool {
        self.password_verification.is_some()
    }

    /// Check if keyring is in legacy mode
    pub fn is_legacy(&self) -> bool {
        self.legacy_mode
    }
}

/// Export a key to a standalone file
pub fn export_key(
    keyring: &Keyring,
    key_name: &str,
    output_path: &Path,
    keyring_password: &str,
    export_password: &str,
) -> Result<()> {
    let key = keyring
        .get_key(key_name)
        .ok_or_else(|| anyhow!("Key '{}' not found", key_name))?;

    // Re-encrypt with the export password
    let export_salt = generate_salt();
    let export_protection_key = derive_key_from_password(export_password, &export_salt)?;

    // First decrypt with keyring password
    let key_password = keyring.get_key_password(keyring_password);
    let keyring_protection_key = derive_key_from_password(&key_password, &key.salt)?;

    // Ensure the key is long enough for decryption
    if key.encrypted_key.len() < 16 {
        return Err(anyhow!("Ciphertext too short for AES-GCM decryption"));
    }

    let decrypted =
        crate::encryption::decrypt_data(&key.encrypted_key, &keyring_protection_key, &key.nonce)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Helper function to create a test keyring with password
    fn create_test_keyring(legacy: bool) -> (Keyring, String) {
        let mut keyring = Keyring::new();
        let password = if legacy {
            keyring.legacy_mode = true;
            "keyring-protection".to_string()
        } else {
            let test_password = "test_password_123";
            keyring.initialize_password(test_password).unwrap();
            test_password.to_string()
        };
        (keyring, password)
    }

    #[test]
    fn test_aes_key_generation_and_export() {
        // Create a temporary directory for the keyring
        let temp_dir = TempDir::new().unwrap();
        let keyring_path = temp_dir.path().join("test_keyring.json");
        
        // Test with new keyring (custom password)
        let (mut keyring, password) = create_test_keyring(false);
        
        // Generate an AES key
        let key_name = keyring.generate_aes_key(
            Some("test_aes_key".to_string()),
            Some("Test AES key for export".to_string()),
            &password
        ).unwrap();
        
        // Save the keyring
        keyring.save_to_file(&keyring_path).unwrap();
        
        // Load the keyring again
        let loaded_keyring = Keyring::load_from_file(&keyring_path).unwrap();
        
        // Export the key
        let export_path = temp_dir.path().join("exported_key.json");
        let export_password = "test_export_password";
        
        export_key(&loaded_keyring, &key_name, &export_path, &password, export_password).unwrap();
        
        // Verify the exported file exists
        assert!(export_path.exists());
        
        // Read and parse the exported key
        let exported_content = fs::read_to_string(&export_path).unwrap();
        let exported_json: serde_json::Value = serde_json::from_str(&exported_content).unwrap();
        
        // Verify the exported key has the required fields
        assert_eq!(exported_json["version"], 1);
        assert_eq!(exported_json["algorithm"], "aes256");
        assert!(exported_json["encrypted_key"].is_array());
        assert!(exported_json["salt"].is_array());
        assert!(exported_json["nonce"].is_array());
    }

    #[test]
    fn test_legacy_keyring_generation() {
        // Test that legacy keyrings still work
        let temp_dir = TempDir::new().unwrap();
        let keyring_path = temp_dir.path().join("legacy_keyring.json");
        
        let (mut keyring, password) = create_test_keyring(true);
        assert!(keyring.is_legacy());
        assert_eq!(password, "keyring-protection");
        
        // Generate a key with legacy password
        let _key_name = keyring.generate_aes_key(
            Some("legacy_key".to_string()),
            None,
            &password
        ).unwrap();
        
        keyring.save_to_file(&keyring_path).unwrap();
        
        // Load and verify it's detected as legacy
        let loaded = Keyring::load_from_file(&keyring_path).unwrap();
        assert!(loaded.is_legacy());
    }

    #[test]
    fn test_kyber_key_generation_and_export() {
        let temp_dir = TempDir::new().unwrap();
        let keyring_path = temp_dir.path().join("test_keyring.json");
        
        let (mut keyring, password) = create_test_keyring(false);
        
        // Generate a Kyber keypair
        let key_name = keyring.generate_kyber_keypair(
            Some("test_kyber_key".to_string()),
            Some("Test Kyber key for export".to_string()),
            &password
        ).unwrap();
        
        keyring.save_to_file(&keyring_path).unwrap();
        
        let loaded_keyring = Keyring::load_from_file(&keyring_path).unwrap();
        
        // Export the key
        let export_path = temp_dir.path().join("exported_kyber_key.json");
        let export_password = "test_kyber_export_password";
        
        export_key(&loaded_keyring, &key_name, &export_path, &password, export_password).unwrap();
        
        // Verify the exported file exists and has public key
        assert!(export_path.exists());
        
        let exported_content = fs::read_to_string(&export_path).unwrap();
        let exported_json: serde_json::Value = serde_json::from_str(&exported_content).unwrap();
        
        assert_eq!(exported_json["algorithm"], "kyber1024");
        assert!(exported_json["public_key"].is_array());
    }

    #[test]
    fn test_dilithium_key_generation_and_export() {
        let temp_dir = TempDir::new().unwrap();
        let keyring_path = temp_dir.path().join("test_keyring.json");
        
        let (mut keyring, password) = create_test_keyring(false);
        
        // Generate a Dilithium keypair
        let key_name = keyring.generate_dilithium_keypair(
            Some("test_dilithium_key".to_string()),
            Some("Test Dilithium key for export".to_string()),
            &password
        ).unwrap();
        
        keyring.save_to_file(&keyring_path).unwrap();
        
        let loaded_keyring = Keyring::load_from_file(&keyring_path).unwrap();
        
        // Export the key
        let export_path = temp_dir.path().join("exported_dilithium_key.json");
        let export_password = "test_dilithium_export_password";
        
        export_key(&loaded_keyring, &key_name, &export_path, &password, export_password).unwrap();
        
        // Verify the exported file exists and has public key
        assert!(export_path.exists());
        
        let exported_content = fs::read_to_string(&export_path).unwrap();
        let exported_json: serde_json::Value = serde_json::from_str(&exported_content).unwrap();
        
        assert_eq!(exported_json["algorithm"], "dilithium5");
        assert!(exported_json["public_key"].is_array());
    }

    #[test]
    fn test_password_verification() {
        let (keyring, password) = create_test_keyring(false);
        
        // Test correct password
        assert!(keyring.verify_password(&password).unwrap());
        
        // Test wrong password
        assert!(!keyring.verify_password("wrong_password").unwrap());
        
        // Test empty password
        assert!(!keyring.verify_password("").unwrap());
    }

    #[test]
    fn test_keyring_migration() {
        let temp_dir = TempDir::new().unwrap();
        let keyring_path = temp_dir.path().join("migrate_keyring.json");
        
        // Create a legacy keyring with a key
        let (mut keyring, old_password) = create_test_keyring(true);
        
        let key_name = keyring.generate_aes_key(
            Some("test_key".to_string()),
            None,
            &old_password
        ).unwrap();
        
        // Save as legacy
        keyring.save_to_file(&keyring_path).unwrap();
        
        // Load and migrate
        let mut loaded = Keyring::load_from_file(&keyring_path).unwrap();
        assert!(loaded.is_legacy());
        
        let new_password = "my_secure_password_123";
        loaded.migrate_from_legacy(&old_password, new_password).unwrap();
        
        // Verify migration worked
        assert!(!loaded.is_legacy());
        assert!(loaded.verify_password(new_password).unwrap());
        assert!(!loaded.verify_password(&old_password).unwrap());
        
        // Verify we can still access the key with new password
        let key_material = loaded.get_key_material(&key_name, new_password).unwrap();
        assert!(key_material.symmetric_key.is_some());
    }

    #[test]
    fn test_list_and_delete_keys() {
        let (mut keyring, password) = create_test_keyring(false);
        
        // Generate a few keys
        let key1 = keyring.generate_aes_key(
            Some("key1".to_string()),
            Some("First key".to_string()),
            &password
        ).unwrap();
        
        let key2 = keyring.generate_aes_key(
            Some("key2".to_string()),
            Some("Second key".to_string()),
            &password
        ).unwrap();
        
        // List keys
        let keys = keyring.list_keys();
        assert_eq!(keys.len(), 2);
        
        // Delete a key
        keyring.delete_key(&key1).unwrap();
        
        // Verify it's gone
        let keys = keyring.list_keys();
        assert_eq!(keys.len(), 1);
        assert!(keyring.get_key(&key1).is_none());
        assert!(keyring.get_key(&key2).is_some());
    }

    #[test]
    fn test_get_key_material() {
        let (mut keyring, password) = create_test_keyring(false);
        
        // Generate an AES key
        let key_name = keyring.generate_aes_key(
            Some("test_material_key".to_string()),
            Some("Test key for get_key_material".to_string()),
            &password
        ).unwrap();
        
        // Get key material with correct password
        let material = keyring.get_key_material(&key_name, &password).unwrap();
        assert!(material.symmetric_key.is_some());
        assert_eq!(material.symmetric_key.unwrap().len(), 32);
        
        // Check usage stats were updated
        let key = keyring.get_key(&key_name).unwrap();
        assert_eq!(key.metadata.usage_count, 1);
        assert!(key.metadata.last_used.is_some());
    }

    #[test]
    fn test_wrong_password_error() {
        let (mut keyring, password) = create_test_keyring(false);
        
        let key_name = keyring.generate_aes_key(
            Some("test_wrong_pass".to_string()),
            None,
            &password
        ).unwrap();
        
        // Try to get key material with wrong password (should fail in non-legacy mode)
        let result = keyring.get_key_material(&key_name, "wrong_password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Decryption failed"));
    }

    #[test]
    fn test_key_not_found_error() {
        let (mut keyring, password) = create_test_keyring(false);
        
        // Try to get non-existent key
        let result = keyring.get_key_material("non_existent_key", &password);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_dilithium_key_material() {
        let (mut keyring, password) = create_test_keyring(false);
        
        let key_name = keyring.generate_dilithium_keypair(
            Some("test_signing_material".to_string()),
            Some("Test Dilithium key material".to_string()),
            &password
        ).unwrap();
        
        let material = keyring.get_key_material(&key_name, &password).unwrap();
        
        // Dilithium keys should have private and public keys
        assert!(material.private_key.is_some());
        assert!(material.public_key.is_some());
        assert!(material.symmetric_key.is_none());
    }

    #[test]
    fn test_kyber_key_material() {
        let (mut keyring, password) = create_test_keyring(false);
        
        let key_name = keyring.generate_kyber_keypair(
            Some("test_kyber_material".to_string()),
            Some("Test Kyber key material".to_string()),
            &password
        ).unwrap();
        
        let material = keyring.get_key_material(&key_name, &password).unwrap();
        
        // Kyber keys should have private and public keys
        assert!(material.private_key.is_some());
        assert!(material.public_key.is_some());
        assert!(material.symmetric_key.is_none());
    }

    #[test]
    fn test_sign_and_verify_workflow() {
        use crate::quantum::{sign_with_dilithium, verify_dilithium_signature};
        
        let (mut keyring, password) = create_test_keyring(false);
        
        // Generate a signing key
        let key_name = keyring.generate_dilithium_keypair(
            Some("workflow_sign_key".to_string()),
            None,
            &password
        ).unwrap();
        
        // Get key material
        let material = keyring.get_key_material(&key_name, &password).unwrap();
        
        // Sign some data
        let test_data = b"Hello, quantum world!";
        let private_key = material.private_key.as_ref().unwrap();
        let public_key = material.public_key.as_ref().unwrap();
        
        let signature = sign_with_dilithium(test_data, private_key).unwrap();
        
        // Verify the signature
        let verification = verify_dilithium_signature(
            test_data,
            &signature,
            public_key
        ).unwrap();
        
        assert!(verification);
    }
}

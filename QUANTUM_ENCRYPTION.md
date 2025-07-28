# Quantum Encryption in pipe-cli

## Overview

pipe-cli now includes post-quantum cryptography to protect files against future quantum computer attacks. This implementation uses NIST-standardized algorithms that are considered secure against both classical and quantum computers.

## Algorithms Used

### Kyber-1024 (ML-KEM)
- **Purpose**: Key Encapsulation Mechanism (KEM) for encryption
- **Security Level**: NIST Level 5 (equivalent to AES-256)
- **Public Key Size**: 1,568 bytes
- **Secret Key Size**: 3,168 bytes
- **Ciphertext Size**: 1,568 bytes
- **Standardized**: FIPS 203 (2024)

### Dilithium5 (ML-DSA)
- **Purpose**: Digital signatures for authenticity
- **Security Level**: NIST Level 5 (highest)
- **Public Key Size**: 2,592 bytes
- **Secret Key Size**: 4,896 bytes
- **Signature Size**: 4,627 bytes
- **Standardized**: FIPS 204 (2024)

## Implementation Details

### Sign-then-Encrypt Pattern

The implementation follows the sign-then-encrypt pattern for maximum security:

1. **Sign**: The plaintext is signed with Dilithium private key
2. **Package**: The signature and signer's public key are packaged with the data
3. **Encrypt**: The entire package is encrypted with Kyber

This ensures both:
- **Authenticity**: The signature proves who created the file
- **Confidentiality**: The encryption keeps the content secret

### Key Management

Quantum keys are stored locally in `~/.pipe-cli/quantum-keys/` as JSON files:

```json
{
  "kyber_public": [...],
  "kyber_secret": [...],
  "dilithium_public": [...],
  "dilithium_secret": [...],
  "file_id": "myfile",
  "created_at": "2024-07-25T00:00:00Z"
}
```

Keys are:
- Generated per file
- Never uploaded to the server
- Required for decryption
- ~100KB per keypair

### File Format

Quantum-encrypted files have the following structure:

```
[Kyber Ciphertext (1,568 bytes)]
[Encrypted Payload containing:]
  - Dilithium Public Key Length (4 bytes)
  - Dilithium Public Key (2,592 bytes)
  - Signature Length (4 bytes)
  - Signature (4,627 bytes)
  - Data Length (4 bytes)
  - Original Data (variable)
```

Total overhead: ~8.8KB per file

### Double Encryption

When using both quantum and password encryption (`--quantum --encrypt`):

1. **Password Encryption First**:
   - Derive key from password using Argon2id
   - Encrypt with AES-256-GCM
   - Prepend 12-byte nonce

2. **Quantum Encryption Second**:
   - Sign the password-encrypted data
   - Encrypt with Kyber

This provides:
- Defense in depth
- Protection against quantum attacks
- Traditional password-based access control

## Usage Examples

### Basic Quantum Encryption
```bash
# Upload with quantum encryption
pipe upload-file document.pdf secure-doc --quantum

# Download (automatically detects .qenc extension)
pipe download-file secure-doc.qenc document.pdf
```

### Quantum + Password Encryption
```bash
# Upload with both protections
pipe upload-file secrets.txt ultra-secure --quantum --encrypt --password "mypass"

# Download and decrypt both layers
pipe download-file ultra-secure.qenc secrets.txt --decrypt --password "mypass"
```

### Key Management
```bash
# Keys are automatically created and stored
ls ~/.pipe-cli/quantum-keys/

# Each file has its own keypair
cat ~/.pipe-cli/quantum-keys/myfile.quantum
```

## Security Considerations

### Advantages
- **Future-Proof**: Secure against quantum computers
- **Authenticated**: Signatures prevent tampering
- **NIST-Approved**: Uses standardized algorithms
- **Local Keys**: Keys never leave your machine

### Limitations
- **Key Loss = Data Loss**: Backup your quantum keys!
- **Overhead**: Adds ~8.8KB to each file
- **Performance**: Slightly slower than classical crypto
- **Key Size**: Keys are large (~100KB each)

### Best Practices
1. **Backup Keys**: Store copies of `~/.pipe-cli/quantum-keys/` securely
2. **Use for Sensitive Data**: Best for long-term sensitive files
3. **Combine with Passwords**: Use `--quantum --encrypt` for maximum security
4. **Test Recovery**: Verify you can decrypt files before deleting originals

## Performance

Typical performance on modern hardware:
- **Key Generation**: ~50ms
- **Encryption**: ~10MB/s
- **Decryption**: ~15MB/s
- **Overhead**: 8.8KB per file

## Compatibility

- Files with `.qenc` extension are automatically handled as quantum-encrypted
- Quantum encryption is optional - regular uploads still work
- Keys are portable between machines (copy `~/.pipe-cli/quantum-keys/`)

## Future Enhancements

Potential improvements:
- Key backup/recovery mechanisms
- Shared quantum-encrypted files
- Hardware security module (HSM) support
- Batch quantum operations
- Key rotation capabilities

## Technical References

- [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: Module-Lattice-Based Digital Signature Algorithm](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) 

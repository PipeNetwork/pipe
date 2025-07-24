# pipe-cli

A powerful command-line interface for interacting with the Pipe distributed storage network.

## Features

- **Decentralized Storage**: Upload and download files to/from the Pipe network
- **Client-Side Encryption**: AES-256-GCM encryption with password-based key derivation
- **Tiered Upload System**: Multiple upload tiers with different performance characteristics
- **Directory Operations**: Upload entire directories with progress tracking
- **Resumable Uploads**: Skip already uploaded files with `--skip-uploaded`
- **JWT Authentication**: Secure authentication with JWT tokens
- **Service Discovery**: Automatic selection of optimal storage nodes

## Installation

```bash
cargo install --path .
```

## Quick Start

### Basic Usage

```bash
# Create a new user
pipe create-user

# Upload a file
pipe upload-file photo.jpg my-photo

# Download a file
pipe download-file my-photo downloaded-photo.jpg

# Upload a directory
pipe upload-directory /path/to/folder --tier normal
```

### Encryption (NEW!)

Pipe-cli now supports client-side AES-256-GCM encryption for maximum privacy:

```bash
# Upload with encryption
pipe upload-file sensitive.pdf secure-doc --encrypt
Enter encryption password: ****
Confirm encryption password: ****

# Download and decrypt
pipe download-file secure-doc decrypted.pdf --decrypt
Enter decryption password: ****

# Encrypt entire directory
pipe upload-directory /sensitive/data --encrypt
```

#### Encryption Features

- **AES-256-GCM**: Military-grade encryption with authenticated encryption
- **Password-Based**: Secure key derivation using Argon2id
- **Key-Based**: Support for managed encryption keys
- **Post-Quantum**: CRYSTALS-Kyber and Dilithium for quantum resistance
- **Streaming**: Encrypts large files in chunks for memory efficiency
- **Transparent**: Encrypted files are marked with `.enc` extension automatically
- **Zero-Knowledge**: Your data is encrypted before leaving your device

#### How It Works

1. When you upload with `--encrypt`, pipe-cli:
   - Prompts for a password (or uses `--password` if provided)
   - Derives a 256-bit key using Argon2id with a random salt
   - Encrypts your file using AES-256-GCM
   - Uploads the encrypted file with `.enc` extension

2. When you download with `--decrypt`, pipe-cli:
   - Downloads the encrypted file
   - Prompts for the password
   - Decrypts the file to your specified output path

3. Encrypted files include a header with:
   - Magic bytes ("PIPE-ENC") for identification
   - Version information for future compatibility
   - Salt for password-based key derivation
   - Nonce for AES-GCM encryption

## Storage Tiers

| Tier | Upload Speed | Cost | Use Case |
|------|-------------|------|----------|
| Normal | Standard | 1x | Regular files |
| Priority | 2x faster | 2x | Important files |
| Premium | 4x faster | 4x | Time-sensitive |
| Ultra | 8x faster | 8x | Mission critical |
| Enterprise | 16x faster | 16x | Maximum performance |

## Configuration

Configuration is stored in `~/.pipe-cli.json`:

```json
{
  "user_id": "your-user-id",
  "user_app_key": "your-app-key",
  "api_endpoints": ["https://api1.pipe.com", "https://api2.pipe.com"],
  "jwt_token": "your-jwt-token"
}
```

## Advanced Features

### Skip Already Uploaded Files

When uploading directories, skip files that were successfully uploaded before:

```bash
pipe upload-directory /large/dataset --skip-uploaded
```

### Custom API Endpoint

```bash
# Use a different endpoint (default is https://us-west-00-firestarter.pipenetwork.com)
pipe upload-file data.csv mydata --api http://localhost:3333
```

### List User Files

```bash
pipe list-user-files
```

### Check File Information

Get detailed information about a file including encryption status:

```bash
pipe file-info myfile.pdf
# Shows size, upload date, encryption status, etc.
```

### Local Encryption/Decryption

Encrypt or decrypt files locally without uploading/downloading:

```bash
# Encrypt a file locally
pipe encrypt-local sensitive.doc sensitive.doc.enc

# Decrypt a file locally  
pipe decrypt-local sensitive.doc.enc sensitive.doc
```

### Key Management

Pipe-cli includes a secure keyring for managing encryption keys:

```bash
# Generate an AES-256 key
pipe keygen --name mydata --algorithm aes256

# Generate a post-quantum Kyber key (for encryption)
pipe keygen --name quantum-safe --algorithm kyber1024

# Generate a post-quantum Dilithium key (for signatures)
pipe keygen --name signing-key --algorithm dilithium5

# List all keys
pipe keylist

# Export a key (password protected)
pipe keyexport mydata mydata.key

# Delete a key
pipe keydelete old-key
```

### Post-Quantum Cryptography

Protect your data against future quantum computers:

```bash
# Upload with post-quantum encryption (requires Kyber key)
pipe upload-file document.pdf qdoc --encrypt --key quantum-safe --quantum

# Sign a file with Dilithium
pipe signfile document.pdf document.sig --key signing-key

# Verify a signature
pipe verifysignature document.pdf document.sig --public-key document.sig.pubkey
```

## Security Notes

- **Passwords are never stored**: Only the encrypted data is uploaded
- **Use strong passwords**: Combine uppercase, lowercase, numbers, and symbols
- **Backup your passwords**: Lost passwords mean lost data
- **Local encryption**: All encryption happens on your device

## License

MIT
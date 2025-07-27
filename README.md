# pipe-cli

A powerful command-line interface for interacting with the Pipe distributed storage network.

## Features

- **Decentralized Storage**: Upload and download files to/from the Pipe network
- **Client-Side Encryption**: AES-256-GCM encryption with password-based key derivation
- **Quantum-Resistant Encryption**: Post-quantum cryptography using Kyber-1024 (ML-KEM) and Dilithium5 (ML-DSA)
- **Tiered Upload System**: Multiple upload tiers with different performance characteristics
- **Directory Operations**: Upload entire directories with progress tracking
- **Resumable Uploads**: Skip already uploaded files with `--skip-uploaded`
- **JWT Authentication**: Secure authentication with JWT tokens
- **Service Discovery**: Automatic selection of optimal storage nodes
- **Multiple Account Support**: Manage multiple accounts with custom config files
- **Local Key Management**: Generate and manage encryption keys locally with built-in keyring

## Prerequisites
To build make sure you have [Rust](https://www.rust-lang.org/tools/install) and required system packages installed :

```bash
# install dependencies
sudo apt update && sudo apt install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  git \
  curl

# install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

## Installation

### From GitHub

```bash
# Clone the repository
git clone https://github.com/PipeNetwork/pipe.git
cd pipe

# Install pipe-cli globally on your system
cargo install --path .
```

### From Local Source

If you already have the source code:

```bash
cd /path/to/pipe
cargo install --path .
```

## Quick Start

### Basic Usage

```bash
# Create a new user
pipe new-user <your_username>

# Upload a file
pipe upload-file photo.jpg my-photo

# Download a file
pipe download-file my-photo downloaded-photo.jpg

# Upload a directory
pipe upload-directory /path/to/folder --tier normal

# Download a directory (NEW!)
pipe download-directory folder ~/restored/folder --parallel 10
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

### Directory Downloads (NEW!)

Pipe-cli now supports downloading entire directories based on your upload history:

```bash
# Download a directory you previously uploaded
pipe download-directory photos/vacation ~/restored/vacation

# Download with parallel transfers for speed
pipe download-directory documents ~/Documents --parallel 10

# See what would be downloaded without actually downloading
pipe download-directory projects ~/restore --dry-run

# Filter files with regex
pipe download-directory logs ~/logs --filter ".*2024.*\.log$"

# Download and decrypt
pipe download-directory encrypted ~/decrypted --decrypt
```

#### Directory Download Features

- **Upload Log Based**: Uses your local upload history (`~/.pipe-cli-uploads.json`)
- **Preserves Structure**: Maintains original directory hierarchy
- **Parallel Downloads**: Configurable concurrency (default: 5)
- **Filtering**: Regex pattern matching for selective downloads
- **Dry Run**: Preview what would be downloaded
- **Decryption Support**: Decrypt files during download

#### Encryption Features

- **AES-256-GCM**: Military-grade encryption with authenticated encryption
- **Password-Based**: Secure key derivation using Argon2id
- **Key-Based**: Support for managed encryption keys
- **Post-Quantum**: CRYSTALS-Kyber and Dilithium for quantum resistance (see Quantum Encryption section)
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

### Quantum-Resistant Encryption

pipe-cli supports post-quantum cryptography to protect against future quantum computer attacks:

```bash
# Upload with quantum encryption
pipe upload-file secret.pdf quantum-secret --quantum

# Download quantum-encrypted file (auto-detected by .qenc extension)
pipe download-file quantum-secret.qenc decrypted.pdf

# Combine quantum + password encryption for maximum security
pipe upload-file topsecret.doc ultra-secure --quantum --encrypt
Enter encryption password: ****
Confirm encryption password: ****
```

#### Quantum Features

- **Kyber-1024 (ML-KEM)**: NIST-standardized quantum-resistant key encapsulation mechanism
- **Dilithium5 (ML-DSA)**: NIST-standardized quantum-resistant digital signatures
- **Sign-then-Encrypt**: Ensures both authenticity and confidentiality
- **Key Management**: Quantum keys stored locally in `~/.pipe-cli/quantum-keys/`
- **Automatic Detection**: Files with `.qenc` extension are automatically handled as quantum-encrypted
- **Hybrid Encryption**: Can combine with password encryption for defense in depth

#### How Quantum Encryption Works

1. **Key Generation**: Generates two quantum-resistant keypairs:
   - Kyber keypair for encryption/decryption
   - Dilithium keypair for signing/verification

2. **Signing**: Your data is signed with your Dilithium private key

3. **Encryption**: The signed data is encrypted with the Kyber public key

4. **Upload**: The quantum-encrypted file is uploaded with `.qenc` extension

5. **Download & Verify**: During download, the signature is verified before decryption

#### Security Considerations

- **Overhead**: Quantum encryption adds ~8KB overhead (signatures + ciphertext)
- **Key Size**: Quantum keys are ~100KB each (stored locally, never uploaded)
- **Future-Proof**: Protects against both current and future quantum computer attacks
- **Performance**: Slightly slower than classical encryption due to larger key sizes

## Storage Tiers

| Tier | Upload Speed | Cost | Use Case |
|------|-------------|------|----------|
| Normal | Standard | 1x | Regular files |
| Priority | 2x faster | 2x | Important files |
| Premium | 4x faster | 4x | Time-sensitive |
| Ultra | 8x faster | 8x | Mission critical |
| Enterprise | 16x faster | 16x | Maximum performance |

## Configuration

Configuration is stored in `~/.pipe-cli.json` by default:

```json
{
  "user_id": "your-user-id",
  "user_app_key": "your-app-key",
  "api_endpoints": ["https:/us-west-00-firestarter.pipenetwork.com", "https://us-east-00-firestarter.pipenetwork.com"],
  "jwt_token": "your-jwt-token"
}
```

### Multiple Accounts Support

pipe-cli now supports managing multiple accounts on the same machine through custom configuration files.

#### Using Command Line Option

Specify a custom config file with `--config`:

```bash
# Use work account
pipe --config ~/.pipe-cli-work.json upload-file report.pdf

# Use personal account
pipe --config ~/.pipe-cli-personal.json upload-file photo.jpg
```

#### Using Environment Variable

Set the `PIPE_CLI_CONFIG` environment variable:

```bash
# Set config for current session
export PIPE_CLI_CONFIG=~/.pipe-cli-work.json
pipe upload-file report.pdf

# Or for a single command
PIPE_CLI_CONFIG=~/.pipe-cli-personal.json pipe upload-file photo.jpg
```

#### Using Shell Aliases (Recommended)

Create convenient aliases in your `~/.bashrc` or `~/.zshrc`:

```bash
alias pipe-work='pipe --config ~/.pipe-cli-work.json'
alias pipe-personal='pipe --config ~/.pipe-cli-personal.json'

# Usage
pipe-work upload-file report.pdf
pipe-personal download-file vacation.jpg
```

#### Setting Up Multiple Accounts

1. Create separate accounts:
```bash
pipe --config ~/.pipe-cli-work.json new-user
# Enter work username...

pipe --config ~/.pipe-cli-personal.json new-user
# Enter personal username...
```

2. Each account has its own isolated configuration
3. Credentials are never mixed between accounts

#### Priority Order

Configuration file location is determined in this order:
1. `--config` command line option (highest priority)
2. `PIPE_CLI_CONFIG` environment variable
3. Default `~/.pipe-cli.json` (lowest priority)

## Advanced Features

### Skip Already Uploaded Files

When uploading directories, skip files that were successfully uploaded before:

```bash
pipe upload-directory /large/dataset --skip-uploaded
```

### Custom API Endpoint

```bash
# Use a different endpoint (default is https://us-west-00-firestarter.pipenetwork.com)
pipe upload-file data.csv mydata --api https://us-east-00-firestarter.pipenetwork.com
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
pipe key-gen --name mydata --algorithm aes256

# Generate a post-quantum Kyber key (for encryption)
pipe key-gen --name quantum-safe --algorithm kyber1024

# Generate a post-quantum Dilithium key (for signatures)
pipe key-gen --name signing-key --algorithm dilithium5

# List all keys
pipe key-list

# Export a key (password protected)
pipe key-export mydata mydata.key

# Delete a key
pipe key-delete old-key

# Migrate legacy keyring to custom password (recommended)
pipe keyring-migrate
```

**Security Update**: The keyring now supports custom master passwords! 
- New users: You'll be prompted to set a password when creating your first key
- Existing users: Run `pipe keyring-migrate` to upgrade from the default password
- Legacy mode: If you see warnings about "legacy keyring", your keys are still using the old hardcoded password `keyring-protection`

### Post-Quantum Cryptography

Protect your data against future quantum computers using NIST-standardized algorithms:

```bash
# Upload with quantum-resistant encryption
# This generates quantum keys automatically and saves them locally
pipe upload-file document.pdf qdoc --quantum

# Upload with both quantum and password encryption
pipe upload-file sensitive.pdf sdoc --quantum --encrypt

# Download quantum-encrypted files
pipe download-file qdoc decrypted.pdf --quantum

# Sign a file with Dilithium5 (ML-DSA)
pipe sign-file document.pdf document.sig --key signing-key

# Verify a signature
pipe verify-signature document.pdf document.sig --public-key document.sig.pubkey
```

**Quantum Encryption Details**:
- Uses Kyber-1024 (ML-KEM) for key encapsulation
- Uses Dilithium5 (ML-DSA) for digital signatures
- Implements sign-then-encrypt pattern for authenticity and confidentiality
- Quantum keys are automatically generated and stored locally
- Files uploaded with `--quantum` have `.qenc` extension on the server

## Troubleshooting

### "File not found" Errors When Downloading

If you get "File not found" errors:
- For encrypted files: use the `--decrypt` flag (don't include `.enc` in the filename)
- Check exact filename with `pipe list-uploads`
- Ensure you're logged in as the file owner

### Keyring Password Issues

If key operations fail with "Decryption failed":
- Use password `keyring-protection` when prompted for "keyring password"
- Keys generated before v0.1.x may not work due to a bug (regenerate them)
- For new installations, all key operations should work with the default password

### Download Decoding Issues

Downloads are automatically base64 decoded. If you encounter issues:
- Ensure you're using the latest version
- For binary files, decoding happens automatically
- No manual base64 decoding is needed

## Security Notes

- **Passwords are never stored**: Only the encrypted data is uploaded
- **Use strong passwords**: Combine uppercase, lowercase, numbers, and symbols
- **Backup your passwords**: Lost passwords mean lost data
- **Local encryption**: All encryption happens on your device
- **Quantum-safe options**: Use `--quantum` flag for future-proof encryption
- **Key storage**: All keys are stored locally in an encrypted keyring

## Recent Updates

### v0.1.x
- **Fixed**: Base64 decoding now happens automatically for all downloads
- **Fixed**: Key export and signing operations (nonce storage bug resolved)
- **Added**: Full quantum-resistant encryption with Kyber-1024 and Dilithium5
- **Added**: Multiple account support via `--config` option
- **Improved**: Better error messages for file not found errors
- **Note**: Keys generated before this version may need to be regenerated

## License

MIT

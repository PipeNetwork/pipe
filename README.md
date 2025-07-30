# pipe-cli

A powerful command-line interface for interacting with the Pipe distributed storage network.

## Features

- **Decentralized Storage**: Upload and download files to/from the Pipe network
- **Directory Sync**: Intelligent sync with `.pipe-sync` metadata tracking and incremental updates
- **Client-Side Encryption**: AES-256-GCM encryption with password-based key derivation
- **Quantum-Resistant Encryption**: Post-quantum cryptography using Kyber-1024 (ML-KEM) and Dilithium5 (ML-DSA)
- **Tiered Upload System**: Multiple upload tiers with different performance characteristics
- **Directory Operations**: Upload entire directories with progress tracking
- **Resumable Uploads**: Skip already uploaded files with `--skip-uploaded`
- **JWT Authentication**: Secure authentication with JWT tokens
- **Service Discovery**: Automatic selection of optimal storage nodes
- **Multiple Account Support**: Manage multiple accounts with custom config files
- **Local Key Management**: Generate and manage encryption keys locally with built-in keyring
- **Blake3 File IDs**: Every file gets a unique Blake3 hash ID for content-based addressing
- **Integrity Verification**: Automatic integrity checking using Blake3 hashes

## Auto Installation
```bash

bash <(curl -sSL https://raw.githubusercontent.com/pipenetwork/pipe/main/setup.sh)

```

## Manually Installation

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

### Pre-built Binaries (Recommended)

Download pre-built binaries for your platform from the [latest release](https://github.com/PipeNetwork/pipe/releases/latest):

- **Linux**: `pipe-linux-amd64` (Intel/AMD) or `pipe-linux-arm64` (ARM)
- **macOS**: `pipe-macos-amd64` (Intel) or `pipe-macos-arm64` (Apple Silicon)
- **Windows**: `pipe-windows-amd64.exe`

#### Linux/macOS Installation
```bash
# Download the binary (replace URL with your platform's binary)
wget https://github.com/PipeNetwork/pipe/releases/latest/download/pipe-linux-amd64

# Make it executable
chmod +x pipe-linux-amd64

# Move to PATH
sudo mv pipe-linux-amd64 /usr/local/bin/pipe

# Verify installation
pipe --version
```

#### Windows Installation
1. Download `pipe-windows-amd64.exe` from the releases page
2. Rename it to `pipe.exe`
3. Add it to your PATH or run it directly from the command prompt

### From Source

```bash
# Clone the repository
git clone https://github.com/PipeNetwork/pipe.git
cd pipe/pipe-cli

# Install pipe-cli globally on your system
cargo install --path .
```

### From Local Source

If you already have the source code:

```bash
cd /path/to/pipe/pipe-cli
cargo install --path .
```

## Quick Start

### Basic Usage

**Note**: Commands use kebab-case (e.g., `new-user`, `upload-file`)

```bash
# Create a new user
pipe new-user <your_username>

# Upload a file
pipe upload-file photo.jpg my-photo

# Check upload cost before uploading (NEW!)
pipe upload-file photo.jpg my-photo --dry-run

# Download a file (now with streaming!)
pipe download-file my-photo downloaded-photo.jpg

# Use legacy download endpoint if needed
pipe download-file my-photo downloaded-photo.jpg --legacy

# Upload a directory
pipe upload-directory /path/to/folder --tier normal

# Download a directory (NEW!)
pipe download-directory folder ~/restored/folder --parallel 10

# Manage referrals
pipe referral generate         # Generate your referral code
pipe referral show            # Show your code and stats
pipe referral apply CODE-1234 # Apply someone's referral code

# Sync directories (NEW!)
pipe sync ./local/folder remote/folder  # Upload sync
pipe sync remote/folder ./local/folder  # Download sync (limited)

# update pipe-cli
pipe update
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

### Directory Sync (NEW!)

Pipe-cli now supports intelligent directory synchronization with metadata tracking:

```bash
# Sync a local directory to remote (upload)
pipe sync ./documents docs/backup

# Sync with specific conflict resolution
pipe sync ./photos vacation-photos --conflict newer

# Dry run to see what would be synced
pipe sync ./projects remote/projects --dry-run

# Sync with parallel transfers
pipe sync ./data remote/data --parallel 10
```

#### Sync Features

- **Incremental Sync**: Only syncs files that have actually changed
- **`.pipe-sync` Metadata**: Tracks file states, hashes, and sync history
- **Conflict Detection**: Detects when both local and remote have changed
- **Blake3 Verification**: Fast hash-based change detection for data integrity
- **Multiple Strategies**: Choose how to resolve conflicts (newer, larger, local, remote, ask)
- **Dry Run Mode**: Preview changes before syncing
- **Progress Tracking**: Visual progress bars for all operations

#### How Sync Works

1. **First Sync**: Creates `.pipe-sync` metadata file tracking all file states
2. **Incremental Syncs**: Compares current files against last sync state
3. **Change Detection**: Uses size, modification time, and Blake3 hash
4. **Smart Conflicts**: Only flags files changed on both sides as conflicts

Example `.pipe-sync` file:
```json
{
  "last_sync": "2024-01-15T10:30:00Z",
  "files": {
    "document.pdf": {
      "path": "document.pdf",
      "size": 102400,
      "modified": "2024-01-15T09:00:00Z",
      "hash": "a665a45920422f9d417e4867efdc4fb8...",
      "last_synced": "2024-01-15T10:30:00Z",
      "sync_version": 1
    }
  }
}
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
# Upload with password encryption
pipe upload-file secret.pdf secure-doc --encrypt
Enter encryption password: ****
Confirm encryption password: ****

# Download and decrypt 
pipe download-file secure-doc.enc decrypted.pdf --decrypt
Enter decryption password: ****
```

#### Quantum Features

- **Kyber-1024 (ML-KEM)**: NIST-standardized quantum-resistant key encapsulation mechanism
- **Dilithium5 (ML-DSA)**: NIST-standardized quantum-resistant digital signatures
- **Key Management**: Quantum keys stored locally in the keyring
- **Sign and Verify**: Use quantum-resistant signatures for file authenticity

#### How Quantum Cryptography Works

1. **Key Generation**: Generate quantum-resistant keypairs:
   - Kyber keypair for future encryption features
   - Dilithium keypair for signing/verification

2. **Signing**: Sign files with your Dilithium private key for authenticity

3. **Verification**: Verify signatures using the corresponding public key

#### Security Considerations

- **Key Size**: Quantum keys are larger than classical keys (stored locally in keyring)
- **Future-Proof**: Protects against future quantum computer attacks
- **Signatures**: Dilithium5 provides quantum-resistant digital signatures

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

### File IDs and Blake3 Hashes

Every uploaded file gets a unique Blake3 hash ID that can be used for:
- Content-based addressing
- Integrity verification
- Deduplication detection

```bash
# Upload shows the Blake3 hash
pipe upload-file video.mp4 my-video
# Output: Blake3 hash: 7b3a5e8f9c2d4a1b...
# Output: 📋 File ID (Blake3): 7b3a5e8f9c2d4a1b5e3f8c9d2a4b6e8f9c3d5a7b8e1f4c9d3a5b7e9f

# Find uploads by hash or path
pipe find-upload video.mp4                    # Find by local path
pipe find-upload 7b3a5e8f --by-hash          # Find by Blake3 hash prefix

# Use file ID for operations (coming soon - requires server support)
pipe download-file 7b3a5e8f output.mp4 --file-id
pipe delete-file 7b3a5e8f --file-id
pipe create-public-link 7b3a5e8f --file-id

# Rehash old uploads (adds Blake3 to upload history)
pipe rehash-uploads --verbose
```

### Cost Estimation (Dry Run)

Check upload costs before committing to an upload:

```bash
# Estimate cost for a single file upload
pipe upload-file large-video.mp4 my-video --dry-run

# Check cost for priority upload
pipe priority-upload data.zip important-data --dry-run

# Works with different tiers
pipe upload-file dataset.csv my-data --tier ultra --dry-run
```

The dry run will show:
- File size
- Selected upload tier and rate
- Estimated token cost
- Your current token balance
- Whether you have sufficient tokens

### Public Links

Create shareable public links for your files:

```bash
# Create a public link
pipe create-public-link myfile.pdf

# Create with custom preview text for social media
pipe create-public-link myfile.pdf --title "My Document" --description "Important file"

# Delete a public link
pipe delete-public-link <link-hash>

# Download from a public link
pipe public-download <link-hash> output.pdf
```

### Priority Operations

For faster transfers with priority lanes:

```bash
# Priority upload (single file)
pipe priority-upload large-file.zip important-data

# Priority download
pipe priority-download important-data restored.zip
```

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

### List Upload History

```bash
pipe list-uploads
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
# Generate quantum-resistant keys
pipe key-gen --name quantum-encrypt --algorithm kyber1024
pipe key-gen --name quantum-sign --algorithm dilithium5

# Sign a file with Dilithium5 (ML-DSA)
pipe sign-file document.pdf document.sig --key quantum-sign

# Verify a signature
pipe verify-signature document.pdf document.sig --public-key quantum-sign.pub
```

**Quantum Cryptography Support**:
- Kyber-1024 (ML-KEM) keys can be generated for future use
- Dilithium5 (ML-DSA) for quantum-resistant digital signatures
- Keys are stored in the local keyring

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

### v0.3.x (Latest)
- **Added**: Directory sync with `.pipe-sync` metadata tracking
- **Added**: Incremental sync - only sync files that have changed
- **Added**: Blake3 hash-based change detection
- **Added**: Conflict detection and resolution strategies
- **Added**: Sync state tracking with version history
- **Improved**: Efficient sync operations with progress tracking

### v0.1.x
- **Fixed**: Base64 decoding now happens automatically for all downloads
- **Fixed**: Key export and signing operations (nonce storage bug resolved)
- **Added**: Quantum-resistant key generation and digital signatures (Kyber-1024 and Dilithium5)
- **Added**: Multiple account support via `--config` option
- **Improved**: Better error messages for file not found errors
- **Note**: Keys generated before this version may need to be regenerated

### v0.2.x (Latest)
- **Added**: High-performance streaming downloads (no more base64 encoding overhead!)
- **Added**: Direct streaming from storage to disk (lower memory usage)
- **Added**: `--legacy` flag for backward compatibility with old download endpoint
- **Improved**: Download speeds significantly improved, especially for large files
- **Fixed**: No more timeouts on large file downloads

#### Streaming Downloads

The new streaming download feature provides:
- **Direct streaming**: Files stream directly from storage to your disk
- **Lower memory usage**: No need to buffer entire file in memory
- **Faster downloads**: No base64 encoding/decoding overhead
- **Progress tracking**: Real-time download progress with accurate speeds
- **Backward compatibility**: Use `--legacy` flag if you encounter issues

```bash
# Default: Use new high-performance streaming
pipe download-file large-video.mp4

# Fallback: Use legacy endpoint if needed
pipe download-file large-video.mp4 --legacy
```

### Referral Program

Earn PIPE tokens by referring friends to the Pipe Network!

#### How It Works

1. **Generate Your Code**: Run `pipe referral generate` to get your unique referral code
2. **Share**: Give your code to friends who want to join Pipe Network
3. **Earn**: Receive 100 PIPE tokens when they complete a qualifying swap (1+ DevNet SOL)

#### Program Rules

- **Minimum Swap**: Referred user must swap at least 1 DevNet SOL to activate reward
- **Reward Amount**: 100 PIPE tokens per successful referral
- **Processing Time**: Rewards may take up to 24 hours to process
- **Fraud Prevention**: All referrals are subject to automated fraud checks
- **DevNet SOL**: Get free DevNet SOL at [https://faucet.solana.com/](https://faucet.solana.com/)

#### Commands

```bash
# Generate your referral code
pipe referral generate

# Check your referral stats
pipe referral show

# Apply a referral code (for new users)
pipe referral apply USERNAME-XXXX
```

### Token and Balance Management

Check your balances:

```bash
# Check PIPE token balance
pipe check-token

# Check SOL balance
pipe check-sol

# Swap SOL for PIPE tokens
pipe swap-sol-for-pipe 0.5  # Swap 0.5 SOL for PIPE
```

### Token Usage Tracking

Track how your PIPE tokens are being spent on storage vs bandwidth:

```bash
# View last 30 days (default)
pipe token-usage

# View detailed breakdown by tier
pipe token-usage --detailed

# View last 7 days with details
pipe token-usage --period 7d --detailed

# View last 90 days
pipe token-usage --period 90d

# View last year
pipe token-usage --period 365d

# View all time usage
pipe token-usage --period all
```

The report shows:
- 📦 **Storage (Uploads)**: Tokens spent storing your files
- 🌐 **Bandwidth (Downloads)**: Tokens spent retrieving files
- 💰 **Total Usage**: Combined costs and token distribution
  - Currently 100% of tokens are burned (removed from circulation)
  - Historical data may show treasury allocations from when the split was 90/10

Example output:
```
📊 Token Usage Report (30d)

📦 Storage (Uploads):
   Data uploaded:     1,234.56 GB
   Tokens spent:      30,863.4000 PIPE
   → Burned:          27,777.0600 PIPE (90%)
   → Treasury:        3,086.3400 PIPE (10%)

🌐 Bandwidth (Downloads):
   Data downloaded:   567.89 GB
   Tokens spent:      567.8900 PIPE
   → Burned:          511.1010 PIPE (90%)
   → Treasury:        56.7890 PIPE (10%)

💰 Total:
   Data transferred:  1,802.45 GB
   Tokens spent:      31,431.2900 PIPE
   → Burned:          28,288.1610 PIPE
   → Treasury:        3,143.1290 PIPE
```

## License

MIT

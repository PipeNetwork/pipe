# Local encrypted file format, version 2

`src/crypto.rs` reads and writes this format exclusively. The magic remains
`PIPEENC2`; the following version byte is **2**. Version 1 is rejected because
it allowed unauthenticated truncation. There is no automatic legacy fallback.

All integers below are unsigned, big endian. Encryption uses AES-256-GCM with
16-byte tags and a 32-byte key derived from the password's UTF-8 bytes using
Argon2id v0x13. Empty passwords are rejected. Passwords are not normalized.

## Header (55 bytes)

| Offset | Bytes | Field | Writer value / reader constraint |
| --- | --- | --- | --- |
| 0 | 8 | Magic | ASCII `PIPEENC2` |
| 8 | 1 | Format version | 2 |
| 9 | 1 | KDF identifier | 1 = Argon2id |
| 10 | 1 | Argon2 version | 0x13 |
| 11 | 4 | Memory cost, KiB | 19456; accepted range 19456–65536 |
| 15 | 4 | Iterations | 2; accepted range 2–6 |
| 19 | 4 | Parallelism / lanes | 1; accepted range 1–4 |
| 23 | 16 | Salt | Fresh operating-system randomness per encryption |
| 39 | 12 | Base nonce | Fresh operating-system randomness per encryption |
| 51 | 4 | Plaintext chunk size | Exactly 65536 |

The reader validates all identifiers, costs, and chunk size before invoking
Argon2. These checks bound resource use even though the header is untrusted at
that point. Every byte of the serialized header is authenticated by every
record, starting with the encrypted length metadata.

## Records

Each record is `AES-GCM ciphertext || tag`. There are no cleartext record length,
type, or index prefixes. Record boundaries, types, and indices are implicit:

| Record | Type for AAD | Index | Plaintext payload |
| --- | --- | --- | --- |
| Length metadata | 0 | 0 | Original byte length `L`, u64 |
| Data | 1 | 1 through `N` | Next `min(65536, remaining)` plaintext bytes |
| Final | 2 | `N + 1` | `L` as u64 followed by `N` as u64 |

`N = ceil(L / 65536)`. Every data record except the last has exactly 65536
plaintext bytes. For `L = 0`, `N = 0`; both metadata and final records are still
mandatory. Metadata occupies 24 bytes and the final record occupies 32 bytes.
The reader uses `L` only after successful metadata authentication.

For each record, construct the 12-byte nonce by XORing the base nonce's final
eight bytes with the record index's eight-byte big-endian representation; the
first four bytes remain unchanged. Construct AAD as:

`complete 55-byte header || one-byte type || eight-byte big-endian index`

Each index is used once per file key. At most `2^32 - 2` data chunks are accepted,
reserving two invocations for metadata and final authentication, and arithmetic
never wraps. No file key or salt/base-nonce pair is deliberately reused.

Every expected record must be read in full and authenticate successfully. The
final record must match both the original length and the number of chunks.
Exactly EOF must follow it. Missing records, partial records, reordered or
duplicated chunks, cross-file splices, appended bytes (including a concatenated
valid file), and incorrect passwords cause errors. Authenticating an empty
file also requires the password. As with any standalone encrypted file, this
format cannot detect replacement of the entire object with another valid
object encrypted under the same password; object identity belongs to a higher
layer.

Length metadata is encrypted, but this format does **not** provide length
hiding: the unpadded ciphertext size permits inference of the plaintext size.
Total encoded size is `55 + 24 + L + 16*N + 32` bytes.

## Output handling

Both public file operations write to a `tempfile::NamedTempFile` in the output
directory. Decryption commits only after metadata, all chunks, the final
record, and EOF pass validation. Before commit the temporary file is synced,
then persisted by atomic replacement of the destination. This uses
[`NamedTempFile::persist`](https://docs.rs/tempfile/3/tempfile/struct.NamedTempFile.html#method.persist).
Authentication and parse errors remove the temporary file on normal error
unwinding and leave any existing destination intact; missing destinations stay
missing. Using the same input and output path is supported. Temporary files
have the library's private default permissions (0600 on Unix).

Encryption requires a regular file so its original length is known without
buffering the file. It reads exactly that length and checks EOF, rejecting
observed growth or shrinkage. It does not promise a consistent snapshot of a
file concurrently modified without changing its size.

Working memory is bounded by the validated KDF cost plus a few chunk buffers.
Plaintext buffers and the raw derived key are zeroized on drop. Atomic replacement
does not promise directory-entry durability across sudden power loss: the
parent directory is not synced. Abrupt process termination can leave a private
temporary file behind; normal authentication failures clean it up.

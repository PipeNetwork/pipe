//! Authenticated streaming encryption; see CRYPTO_FORMAT.md for the wire format.
//! Version 1 is intentionally rejected because it did not authenticate EOF.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"PIPEENC2";
const VERSION: u8 = 2;
const KDF_ARGON2ID: u8 = 1;
const ARGON2_VERSION: u8 = 0x13;
const HEADER_LEN: usize = 55;
const TAG_LEN: usize = 16;
const METADATA: u8 = 0;
const DATA: u8 = 1;
const FINAL: u8 = 2;
const MIN_MEMORY_KIB: u32 = 19 * 1024;
const MAX_MEMORY_KIB: u32 = 64 * 1024;
const MAX_ITERATIONS: u32 = 6;
const MAX_LANES: u32 = 4;
// Reserve metadata and final records: at most 2^32 GCM invocations per key.
const MAX_CHUNKS: u64 = (1u64 << 32) - 2;
pub const CHUNK_SIZE: usize = 64 * 1024;

struct Header {
    bytes: [u8; HEADER_LEN],
}

impl Header {
    fn new() -> Result<Self> {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = VERSION;
        bytes[9] = KDF_ARGON2ID;
        bytes[10] = ARGON2_VERSION;
        bytes[11..15].copy_from_slice(&MIN_MEMORY_KIB.to_be_bytes());
        bytes[15..19].copy_from_slice(&2u32.to_be_bytes());
        bytes[19..23].copy_from_slice(&1u32.to_be_bytes());
        OsRng
            .try_fill_bytes(&mut bytes[23..51])
            .context("generate encryption salt and nonce")?;
        bytes[51..55].copy_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
        Ok(Self { bytes })
    }

    fn read(source: &mut impl Read) -> Result<Self> {
        let mut bytes = [0u8; HEADER_LEN];
        source
            .read_exact(&mut bytes)
            .context("read encryption header")?;
        let header = Self { bytes };
        header.params()?;
        Ok(header)
    }

    fn params(&self) -> Result<Params> {
        let bytes = &self.bytes;
        if &bytes[..8] != MAGIC || bytes[8] != VERSION {
            bail!("unsupported encrypted object format or version");
        }
        if bytes[9] != KDF_ARGON2ID || bytes[10] != ARGON2_VERSION {
            bail!("unsupported encrypted object KDF");
        }
        let memory = u32::from_be_bytes(bytes[11..15].try_into()?);
        let iterations = u32::from_be_bytes(bytes[15..19].try_into()?);
        let lanes = u32::from_be_bytes(bytes[19..23].try_into()?);
        // Untrusted until metadata authentication: bound all costs before KDF.
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory)
            || !(2..=MAX_ITERATIONS).contains(&iterations)
            || !(1..=MAX_LANES).contains(&lanes)
        {
            bail!("encrypted object KDF parameters are outside supported bounds");
        }
        if u32::from_be_bytes(bytes[51..55].try_into()?) != CHUNK_SIZE as u32 {
            bail!("unsupported encrypted object chunk size");
        }
        Params::new(memory, iterations, lanes, Some(32))
            .map_err(|e| anyhow!("invalid encryption parameters: {e}"))
    }

    fn cipher(&self, password: &str) -> Result<Aes256Gcm> {
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params()?);
        let mut key = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(password.as_bytes(), &self.bytes[23..39], &mut *key)
            .map_err(|e| anyhow!("derive encryption key: {e}"))?;
        Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow!("initialize encryption"))
    }

    fn nonce(&self, index: u64) -> [u8; 12] {
        let mut value = [0u8; 12];
        value.copy_from_slice(&self.bytes[39..51]);
        for (target, byte) in value[4..].iter_mut().zip(index.to_be_bytes()) {
            *target ^= byte;
        }
        value
    }

    fn aad(&self, kind: u8, index: u64) -> [u8; HEADER_LEN + 9] {
        let mut aad = [0u8; HEADER_LEN + 9];
        aad[..HEADER_LEN].copy_from_slice(&self.bytes);
        aad[HEADER_LEN] = kind;
        aad[HEADER_LEN + 1..].copy_from_slice(&index.to_be_bytes());
        aad
    }
}

fn write_record(
    destination: &mut impl Write,
    cipher: &Aes256Gcm,
    header: &Header,
    kind: u8,
    index: u64,
    plaintext: &[u8],
) -> Result<()> {
    let encrypted = cipher
        .encrypt(
            &Nonce::from(header.nonce(index)),
            Payload {
                msg: plaintext,
                aad: &header.aad(kind, index),
            },
        )
        .map_err(|_| anyhow!("encrypt record {index}"))?;
    destination
        .write_all(&encrypted)
        .context("write encrypted record")
}

fn read_record(
    source: &mut impl Read,
    cipher: &Aes256Gcm,
    header: &Header,
    kind: u8,
    index: u64,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    // Only internal bounded sizes reach here; no untrusted length prefixes.
    let mut encrypted = vec![0u8; length + TAG_LEN];
    source
        .read_exact(&mut encrypted)
        .context("truncated encrypted record")?;
    cipher
        .decrypt(
            &Nonce::from(header.nonce(index)),
            Payload {
                msg: &encrypted,
                aad: &header.aad(kind, index),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("encrypted object authentication failed at record {index}"))
}

fn chunk_count(length: u64) -> Result<u64> {
    let chunks = length.div_ceil(CHUNK_SIZE as u64);
    if chunks > MAX_CHUNKS {
        bail!("encrypted file has too many chunks");
    }
    Ok(chunks)
}

fn final_metadata(length: u64, chunks: u64) -> [u8; 16] {
    let mut result = [0u8; 16];
    result[..8].copy_from_slice(&length.to_be_bytes());
    result[8..].copy_from_slice(&chunks.to_be_bytes());
    result
}

fn require_eof(source: &mut impl Read) -> Result<()> {
    // read_to_end retries interrupted reads; take bounds the allocation/read.
    if source.take(1).read_to_end(&mut Vec::new())? != 0 {
        bail!("unexpected trailing bytes or input changed during encryption");
    }
    Ok(())
}

fn destination(output: &Path) -> Result<NamedTempFile> {
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary output in {}", parent.display()))
}

fn commit(destination: NamedTempFile, output: &Path) -> Result<()> {
    destination.as_file().sync_all().context("sync output")?;
    destination
        .persist(output)
        .map_err(|e| anyhow!("commit {}: {e}", output.display()))?;
    Ok(())
}

pub fn encrypt_file(input: &Path, output: &Path, password: &str) -> Result<()> {
    if password.is_empty() {
        bail!("encryption password cannot be empty");
    }
    let mut source = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let metadata = source.metadata()?;
    if !metadata.is_file() {
        bail!("encryption input must be a regular file");
    }
    let length = metadata.len();
    let chunks = chunk_count(length)?;
    let header = Header::new()?;
    let cipher = header.cipher(password)?;
    let mut destination = destination(output)?;
    destination.write_all(&header.bytes)?;
    write_record(
        &mut destination,
        &cipher,
        &header,
        METADATA,
        0,
        &length.to_be_bytes(),
    )?;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut remaining = length;
    for index in 1..=chunks {
        let count = remaining.min(CHUNK_SIZE as u64) as usize;
        source
            .read_exact(&mut buffer[..count])
            .context("read plaintext (input may have changed)")?;
        write_record(
            &mut destination,
            &cipher,
            &header,
            DATA,
            index,
            &buffer[..count],
        )?;
        remaining -= count as u64;
    }
    require_eof(&mut source)?;
    write_record(
        &mut destination,
        &cipher,
        &header,
        FINAL,
        chunks + 1,
        &final_metadata(length, chunks),
    )?;
    drop(source);
    commit(destination, output)
}

pub fn decrypt_file(input: &Path, output: &Path, password: &str) -> Result<()> {
    if password.is_empty() {
        bail!("encryption password cannot be empty");
    }
    let mut source = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let header = Header::read(&mut source)?;
    let cipher = header.cipher(password)?;
    let metadata = read_record(&mut source, &cipher, &header, METADATA, 0, 8)?;
    let length = u64::from_be_bytes(metadata.as_slice().try_into()?);
    let chunks = chunk_count(length)?;
    let mut destination = destination(output)?;
    let mut remaining = length;
    for index in 1..=chunks {
        let count = remaining.min(CHUNK_SIZE as u64) as usize;
        let plaintext = read_record(&mut source, &cipher, &header, DATA, index, count)?;
        destination.write_all(&plaintext)?;
        remaining -= count as u64;
    }
    let final_record = read_record(&mut source, &cipher, &header, FINAL, chunks + 1, 16)?;
    if final_record.as_slice() != final_metadata(length, chunks) {
        bail!("encrypted object final metadata mismatch");
    }
    require_eof(&mut source)?;
    drop(source);
    commit(destination, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "test password";
    const DATA_START: usize = HEADER_LEN + 8 + TAG_LEN;
    const FULL_RECORD: usize = CHUNK_SIZE + TAG_LEN;

    fn encrypted(data: &[u8]) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in");
        let output = dir.path().join("enc");
        std::fs::write(&input, data).unwrap();
        encrypt_file(&input, &output, PASSWORD).unwrap();
        std::fs::read(output).unwrap()
    }

    fn rejects(bytes: &[u8], password: &str) {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("enc");
        let output = dir.path().join("out");
        std::fs::write(&input, bytes).unwrap();
        std::fs::write(&output, b"keep existing user file").unwrap();
        assert!(decrypt_file(&input, &output, password).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"keep existing user file");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            2,
            "temporary output leaked"
        );
    }

    #[test]
    fn round_trip_empty_partial_and_chunk_boundaries() {
        for length in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE + 7,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("in");
            let enc = dir.path().join("enc");
            let out = dir.path().join("out");
            let data: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            std::fs::write(&input, &data).unwrap();
            std::fs::write(&out, b"replace me").unwrap();
            encrypt_file(&input, &enc, PASSWORD).unwrap();
            decrypt_file(&enc, &out, PASSWORD).unwrap();
            assert_eq!(std::fs::read(out).unwrap(), data);
            assert_eq!(
                std::fs::metadata(enc).unwrap().len(),
                HEADER_LEN as u64
                    + 24
                    + length as u64
                    + chunk_count(length as u64).unwrap() * 16
                    + 32
            );
        }
    }

    #[test]
    fn wrong_password_rejected_even_for_empty_plaintext() {
        for data in [&b""[..], &b"secret"[..]] {
            let enc = encrypted(data);
            rejects(&enc, "wrong password");
            rejects(&enc, "");
        }
    }

    #[test]
    fn truncation_at_record_boundaries_and_inside_records_is_rejected() {
        let enc = encrypted(&vec![42; 2 * CHUNK_SIZE + 7]);
        let final_start = enc.len() - 32;
        for end in [
            0,
            8,
            HEADER_LEN - 1,
            HEADER_LEN,
            HEADER_LEN + 1,
            DATA_START - 1,
            DATA_START,
            DATA_START + 1,
            DATA_START + FULL_RECORD - 1,
            DATA_START + FULL_RECORD,
            DATA_START + 2 * FULL_RECORD,
            final_start - 1,
            final_start,
            final_start + 1,
            enc.len() - 1,
        ] {
            rejects(&enc[..end], PASSWORD);
        }
        let empty = encrypted(b"");
        rejects(&empty[..DATA_START], PASSWORD);
        rejects(&empty[..empty.len() - 1], PASSWORD);
    }

    #[test]
    fn header_metadata_ciphertext_and_tags_are_authenticated() {
        let enc = encrypted(&vec![42; CHUNK_SIZE + 7]);
        // Includes a supported-but-modified memory cost, salt, nonce, metadata,
        // both data records/tags and final record/tag (after plaintext writes).
        for offset in [
            0,
            8,
            9,
            10,
            14,
            18,
            22,
            23,
            38,
            39,
            50,
            54,
            HEADER_LEN,
            DATA_START - 1,
            DATA_START,
            DATA_START + FULL_RECORD - 1,
            DATA_START + FULL_RECORD,
            enc.len() - 33,
            enc.len() - 32,
            enc.len() - 1,
        ] {
            let mut damaged = enc.clone();
            damaged[offset] ^= 1;
            rejects(&damaged, PASSWORD);
        }
    }

    #[test]
    fn rejects_reordered_duplicated_deleted_spliced_and_trailing_records() {
        let enc = encrypted(&vec![42; 2 * CHUNK_SIZE]);
        let first = DATA_START..DATA_START + FULL_RECORD;
        let second = DATA_START + FULL_RECORD..DATA_START + 2 * FULL_RECORD;
        let mut reordered = enc.clone();
        reordered[first.clone()].copy_from_slice(&enc[second.clone()]);
        reordered[second.clone()].copy_from_slice(&enc[first.clone()]);
        rejects(&reordered, PASSWORD);
        let mut duplicate = enc.clone();
        duplicate[second.clone()].copy_from_slice(&enc[first.clone()]);
        rejects(&duplicate, PASSWORD);
        let mut deleted = enc.clone();
        deleted.drain(second);
        rejects(&deleted, PASSWORD);
        let other = encrypted(&vec![42; 2 * CHUNK_SIZE]);
        let mut spliced = enc.clone();
        spliced[first.clone()].copy_from_slice(&other[first]);
        rejects(&spliced, PASSWORD);
        for suffix in [&b"\0"[..], enc.as_slice()] {
            let mut trailing = enc.clone();
            trailing.extend_from_slice(suffix);
            rejects(&trailing, PASSWORD);
        }
    }

    #[test]
    fn kdf_and_chunk_sizes_are_bounded_before_key_derivation() {
        let header = Header::new().unwrap();
        for (offset, invalid) in [
            (11, 0),
            (11, MIN_MEMORY_KIB - 1),
            (11, MAX_MEMORY_KIB + 1),
            (11, u32::MAX),
            (15, 0),
            (15, 1),
            (15, MAX_ITERATIONS + 1),
            (19, 0),
            (19, MAX_LANES + 1),
            (51, 0),
            (51, u32::MAX),
        ] {
            let mut bytes = header.bytes;
            bytes[offset..offset + 4].copy_from_slice(&invalid.to_be_bytes());
            assert!(Header::read(&mut &bytes[..]).is_err());
        }
        assert_eq!(
            chunk_count(MAX_CHUNKS * CHUNK_SIZE as u64).unwrap(),
            MAX_CHUNKS
        );
        assert!(chunk_count(MAX_CHUNKS * CHUNK_SIZE as u64 + 1).is_err());
        assert!(chunk_count(u64::MAX).is_err());
    }

    #[test]
    fn authenticated_but_inconsistent_final_metadata_is_rejected() {
        let mut enc = encrypted(b"secret");
        let header = Header::read(&mut &enc[..]).unwrap();
        let cipher = header.cipher(PASSWORD).unwrap();
        enc.truncate(enc.len() - 32);
        write_record(&mut enc, &cipher, &header, FINAL, 2, &final_metadata(5, 1)).unwrap();
        rejects(&enc, PASSWORD);
    }

    #[test]
    fn complete_header_is_aad_even_when_using_the_original_key() {
        let enc = encrypted(b"");
        let original = Header::read(&mut &enc[..]).unwrap();
        let cipher = original.cipher(PASSWORD).unwrap();
        // Bypass parsing and KDF deliberately: all serialized header bytes
        // must be cryptographically bound, not merely checked by the parser.
        for offset in 0..HEADER_LEN {
            let mut header = Header {
                bytes: original.bytes,
            };
            header.bytes[offset] ^= 1;
            assert!(
                read_record(&mut &enc[HEADER_LEN..], &cipher, &header, METADATA, 0, 8).is_err(),
                "unauthenticated header byte {offset}"
            );
        }
    }

    #[test]
    fn stored_nondefault_kdf_parameters_are_used_and_oversized_length_is_rejected() {
        let mut header = Header::new().unwrap();
        header.bytes[11..15].copy_from_slice(&(MIN_MEMORY_KIB + 1024).to_be_bytes());
        header.bytes[15..19].copy_from_slice(&3u32.to_be_bytes());
        header.bytes[19..23].copy_from_slice(&2u32.to_be_bytes());
        let cipher = header.cipher(PASSWORD).unwrap();
        let mut enc = header.bytes.to_vec();
        write_record(&mut enc, &cipher, &header, METADATA, 0, &0u64.to_be_bytes()).unwrap();
        write_record(&mut enc, &cipher, &header, FINAL, 1, &final_metadata(0, 0)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("enc");
        let output = dir.path().join("out");
        std::fs::write(&input, &enc).unwrap();
        decrypt_file(&input, &output, PASSWORD).unwrap();
        assert!(std::fs::read(&output).unwrap().is_empty());

        enc.truncate(HEADER_LEN);
        write_record(
            &mut enc,
            &cipher,
            &header,
            METADATA,
            0,
            &u64::MAX.to_be_bytes(),
        )
        .unwrap();
        rejects(&enc, PASSWORD);
    }

    #[test]
    fn failed_decryption_does_not_create_output_and_same_path_is_safe() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("file");
        let output = dir.path().join("missing");
        let mut enc = encrypted(b"secret");
        *enc.last_mut().unwrap() ^= 1;
        std::fs::write(&input, &enc).unwrap();
        assert!(decrypt_file(&input, &output, PASSWORD).is_err());
        assert!(!output.exists());
        assert!(decrypt_file(&input, &input, PASSWORD).is_err());
        assert_eq!(std::fs::read(&input).unwrap(), enc);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        std::fs::write(&input, b"secret").unwrap();
        encrypt_file(&input, &input, PASSWORD).unwrap();
        decrypt_file(&input, &input, PASSWORD).unwrap();
        assert_eq!(std::fs::read(input).unwrap(), b"secret");
    }

    #[test]
    fn encryption_uses_fresh_salt_and_nonce_and_preserves_output_on_error() {
        let first = encrypted(b"secret");
        let second = encrypted(b"secret");
        assert_ne!(&first[23..39], &second[23..39]);
        assert_ne!(&first[39..51], &second[39..51]);
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"keep").unwrap();
        assert!(encrypt_file(&file, &file, "").is_err());
        assert!(encrypt_file(&dir.path().join("missing"), &file, PASSWORD).is_err());
        assert_eq!(std::fs::read(file).unwrap(), b"keep");
    }
}

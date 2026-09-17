//! Deliberately narrow validator for the control API's USDC wallet invoices.
//! No RPC, account lookups, arbitrary programs, or opaque-message signing.
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const MAINNET: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
pub(crate) const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ASSOCIATED: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const COMPUTE: &str = "ComputeBudget111111111111111111111111111111";
const WIRE_MAX: usize = 1232;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Terms {
    network: String,
    asset: String,
    pay_to: String,
    payer: String,
    amount: String,
    memo: String,
    decimals: u8,
    blockhash: String,
    last_valid_block_height: u64,
    expires_at: i64,
    message_version: Option<u8>,
    compute_unit_limit: Option<u32>,
    compute_unit_price_micro_lamports: Option<u64>,
}

pub(crate) fn pubkey(value: &str) -> Result<[u8; 32]> {
    ensure!(value.len() <= 44, "Solana public key is too long");
    let bytes: [u8; 32] = bs58::decode(value)
        .into_vec()?
        .try_into()
        .map_err(|_| anyhow!("Solana public key must contain 32 bytes"))?;
    ensure!(
        bs58::encode(bytes).into_string() == value,
        "noncanonical public key"
    );
    Ok(bytes)
}

pub(crate) fn payer_from_wallet(wallet: &str) -> Result<String> {
    let bytes: [u8; 32] = hex::decode(wallet)?
        .try_into()
        .map_err(|_| anyhow!("credit wallet must be 32-byte hex"))?;
    Ok(bs58::encode(bytes).into_string())
}

fn ata(owner: &[u8; 32], mint: &[u8; 32]) -> Result<[u8; 32]> {
    let token = pubkey(TOKEN)?;
    let associated = pubkey(ASSOCIATED)?;
    for bump in (0..=255u8).rev() {
        let mut hash = Sha256::new();
        for seed in [
            owner.as_slice(),
            token.as_slice(),
            mint.as_slice(),
            &[bump],
            associated.as_slice(),
            b"ProgramDerivedAddress",
        ] {
            hash.update(seed);
        }
        let key: [u8; 32] = hash.finalize().into();
        if CompressedEdwardsY(key).decompress().is_none() {
            return Ok(key);
        }
    }
    Err(anyhow!("could not derive associated token account"))
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        ensure!(count <= self.0.len(), "truncated Solana transaction");
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn short(&mut self) -> Result<usize> {
        let mut value = 0usize;
        for index in 0..3 {
            let byte = self.byte()?;
            ensure!(index != 2 || byte <= 3, "invalid shortvec");
            value |= ((byte & 127) as usize) << (index * 7);
            if byte & 128 == 0 {
                ensure!(index == 0 || byte != 0, "noncanonical shortvec");
                return Ok(value);
            }
        }
        Err(anyhow!("invalid shortvec"))
    }
}

/// Validate against both the user's persisted intent and the invoice terms.
/// Only one signer and the exact ATA transfer/memo (plus pinned compute fees)
/// are allowed. The maximum priority fee is 5,000 lamports; there are no SOL
/// transfers, account creations, or additional signature fees in this message.
pub(crate) fn validate(
    invoice: &Value,
    id: Uuid,
    wallet: &str,
    payer: &str,
    amount: u64,
) -> Result<Vec<u8>> {
    ensure!(
        invoice["invoice_id"].as_str() == Some(id.to_string().as_str()),
        "invoice ID mismatch"
    );
    ensure!(
        invoice["credit_wallet"] == wallet,
        "invoice credit wallet mismatch"
    );
    ensure!(
        invoice["amount_atoms"].as_str() == Some(amount.to_string().as_str()),
        "invoice amount mismatch"
    );
    ensure!(
        invoice["method"] == "solana_wallet",
        "not a wallet payment invoice"
    );
    let raw_terms = &invoice["terms"];
    for field in [
        "messageVersion",
        "computeUnitLimit",
        "computeUnitPriceMicroLamports",
    ] {
        ensure!(
            !raw_terms.get(field).is_some_and(Value::is_null),
            "null wallet fee/version field"
        );
    }
    let t: Terms = serde_json::from_value(raw_terms.clone()).context("invalid invoice terms")?;
    ensure!(
        t.network == MAINNET && t.asset == USDC && t.decimals == 6,
        "invoice must use canonical mainnet USDC"
    );
    ensure!(
        t.payer == payer && amount > 0 && t.amount == amount.to_string(),
        "invoice differs from payment intent"
    );
    ensure!(
        t.memo == format!("pipe-credit:{id}"),
        "invoice memo mismatch"
    );
    ensure!(
        t.last_valid_block_height > 0 && t.expires_at > 0,
        "invalid invoice lifetime"
    );
    let versioned = match (
        t.message_version,
        t.compute_unit_limit,
        t.compute_unit_price_micro_lamports,
    ) {
        (None, None, None) => false,
        (Some(2..=4), Some(50_000), Some(100_000)) => true,
        _ => {
            return Err(anyhow!(
                "unsupported message version or excessive compute fee"
            ))
        }
    };
    let payer = pubkey(payer)?;
    let recipient = pubkey(&t.pay_to)?;
    ensure!(
        payer != recipient && CompressedEdwardsY(payer).decompress().is_some(),
        "invalid or self-paying payer"
    );
    let mint = pubkey(USDC)?;
    let source = ata(&payer, &mint)?;
    let destination = ata(&recipient, &mint)?;
    let token = pubkey(TOKEN)?;
    let memo = pubkey(MEMO)?;
    let compute = pubkey(COMPUTE)?;
    let encoded = invoice["unsignedTransaction"]
        .as_str()
        .context("invoice omitted unsignedTransaction")?;
    ensure!(
        encoded.len() <= WIRE_MAX.div_ceil(3) * 4,
        "transaction exceeds wire limit"
    );
    let wire = STANDARD
        .decode(encoded)
        .context("invalid transaction base64")?;
    ensure!(wire.len() <= WIRE_MAX, "transaction exceeds wire limit");
    let mut r = Reader(&wire);
    ensure!(
        r.short()? == 1 && r.take(64)? == [0u8; 64],
        "expected one empty signature"
    );
    if versioned {
        ensure!(r.byte()? == 0x80, "expected v0 transaction");
    }
    ensure!(
        r.take(3)? == [1, 0, if versioned { 4 } else { 3 }],
        "unsafe account privileges or signer count"
    );
    let count = r.short()?;
    ensure!(
        count == if versioned { 7 } else { 6 },
        "unexpected transaction accounts"
    );
    let mut keys = Vec::<[u8; 32]>::new();
    for _ in 0..count {
        let key = r.take(32)?.try_into().unwrap();
        ensure!(!keys.contains(&key), "duplicate transaction account");
        keys.push(key);
    }
    ensure!(
        keys[0] == payer && keys[1..3].contains(&source) && keys[1..3].contains(&destination),
        "payer or writable ATAs mismatch"
    );
    let mut readonly = vec![mint, token, memo];
    if versioned {
        readonly.push(compute);
    }
    ensure!(
        keys[3..].iter().all(|key| readonly.contains(key)),
        "unexpected read-only account"
    );
    ensure!(
        r.take(32)? == pubkey(&t.blockhash)?,
        "blockhash differs from invoice"
    );
    ensure!(
        r.short()? == if versioned { 4 } else { 2 },
        "unexpected instruction count"
    );
    let index = |key: &[u8; 32]| keys.iter().position(|v| v == key).unwrap() as u8;
    let mut expected: Vec<(u8, Vec<u8>, Vec<u8>)> = Vec::new();
    if versioned {
        let mut limit = vec![2];
        limit.extend_from_slice(&50_000u32.to_le_bytes());
        let mut price = vec![3];
        price.extend_from_slice(&100_000u64.to_le_bytes());
        expected.push((index(&compute), vec![], limit));
        expected.push((index(&compute), vec![], price));
    }
    let mut transfer = vec![12];
    transfer.extend_from_slice(&amount.to_le_bytes());
    transfer.push(6);
    expected.push((
        index(&token),
        vec![index(&source), index(&mint), index(&destination), 0],
        transfer,
    ));
    expected.push((index(&memo), vec![0], t.memo.into_bytes()));
    for (program, accounts, data) in expected {
        ensure!(r.byte()? == program, "unexpected instruction program");
        let n = r.short()?;
        ensure!(
            r.take(n)? == accounts,
            "instruction accounts differ from invoice"
        );
        let n = r.short()?;
        ensure!(r.take(n)? == data, "instruction data differs from invoice");
    }
    if versioned {
        ensure!(r.short()? == 0, "address lookup tables are not allowed");
    }
    ensure!(r.0.is_empty(), "trailing transaction bytes");
    Ok(wire)
}

pub(crate) fn sign(wire: &[u8], key: &SigningKey) -> Result<String> {
    ensure!(
        wire.len() > 65 && wire[0] == 1 && wire[1..65] == [0u8; 64],
        "expected validated unsigned wire"
    );
    // Also bind the actual message's fee payer to the loaded CLI signing key.
    let start = 65 + usize::from(wire[65] == 0x80) + 4;
    ensure!(
        wire.get(start..start + 32) == Some(key.verifying_key().as_bytes().as_slice()),
        "CLI signing key is not the invoice payer"
    );
    let mut signed = wire.to_vec();
    signed[1..65].copy_from_slice(&key.sign(&wire[65..]).to_bytes());
    Ok(STANDARD.encode(signed))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// Backend v4/web3 account order, independently assembled as wire bytes.
    pub(crate) fn invoice(id: Uuid, key: &SigningKey, version: Option<u8>) -> Value {
        let payer = key.verifying_key().to_bytes();
        let recipient = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
        let mint = pubkey(USDC).unwrap();
        let source = ata(&payer, &mint).unwrap();
        let destination = ata(&recipient, &mint).unwrap();
        let token = pubkey(TOKEN).unwrap();
        let memo_program = pubkey(MEMO).unwrap();
        let compute = pubkey(COMPUTE).unwrap();
        let blockhash = [17; 32];
        let mut keys = vec![payer, source, destination];
        if version.is_some() {
            keys.extend([compute, token, mint, memo_program]);
        } else {
            keys.extend([token, mint, memo_program]);
        }
        if version.is_none() || version == Some(2) {
            keys[1..3].sort();
            keys[3..].sort();
        }
        let index = |key: &[u8; 32]| keys.iter().position(|k| k == key).unwrap() as u8;
        let memo = format!("pipe-credit:{id}");
        let mut instructions: Vec<(u8, Vec<u8>, Vec<u8>)> = vec![];
        if version.is_some() {
            instructions.push((index(&compute), vec![], vec![2, 0x50, 0xc3, 0, 0]));
            instructions.push((
                index(&compute),
                vec![],
                vec![3, 0xa0, 0x86, 1, 0, 0, 0, 0, 0],
            ));
        }
        instructions.push((
            index(&token),
            vec![index(&source), index(&mint), index(&destination), 0],
            vec![12, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0, 6],
        ));
        instructions.push((index(&memo_program), vec![0], memo.as_bytes().to_vec()));
        let mut wire = vec![1];
        wire.extend([0; 64]);
        if version.is_some() {
            wire.push(0x80);
        }
        wire.extend([
            1,
            0,
            if version.is_some() { 4 } else { 3 },
            keys.len() as u8,
        ]);
        for key in keys {
            wire.extend(key);
        }
        wire.extend(blockhash);
        wire.push(instructions.len() as u8);
        for (program, accounts, data) in instructions {
            wire.push(program);
            wire.push(accounts.len() as u8);
            wire.extend(accounts);
            wire.push(data.len() as u8);
            wire.extend(data);
        }
        if version.is_some() {
            wire.push(0);
        }
        let mut terms = json!({"network":MAINNET,"asset":USDC,
            "payTo":bs58::encode(recipient).into_string(),"payer":bs58::encode(payer).into_string(),
            "amount":"1000000","memo":memo,"decimals":6,"blockhash":bs58::encode(blockhash).into_string(),
            "lastValidBlockHeight":999999999,"expiresAt":chrono::Utc::now().timestamp() + 600});
        if let Some(version) = version {
            terms["messageVersion"] = json!(version);
            terms["computeUnitLimit"] = json!(50000);
            terms["computeUnitPriceMicroLamports"] = json!(100000);
        }
        json!({"invoice_id":id,"credit_wallet":hex::encode(payer),"amount_atoms":"1000000",
            "state":"created","method":"solana_wallet","terms":terms,"unsignedTransaction":STANDARD.encode(wire)})
    }

    fn check(value: &Value, key: &SigningKey, id: Uuid) -> Result<Vec<u8>> {
        validate(
            value,
            id,
            &hex::encode(key.verifying_key().to_bytes()),
            &bs58::encode(key.verifying_key().to_bytes()).into_string(),
            1_000_000,
        )
    }

    #[test]
    fn accepts_backend_versions_and_verifiable_signature() {
        let key = SigningKey::from_bytes(&[7; 32]);
        for version in [None, Some(2), Some(3), Some(4)] {
            let id = Uuid::new_v4();
            let value = invoice(id, &key, version);
            let wire = check(&value, &key, id).unwrap();
            let signed = STANDARD.decode(sign(&wire, &key).unwrap()).unwrap();
            let signature = ed25519_dalek::Signature::from_slice(&signed[1..65]).unwrap();
            key.verifying_key()
                .verify_strict(&signed[65..], &signature)
                .unwrap();
            assert!(sign(&wire, &SigningKey::from_bytes(&[8; 32])).is_err());
        }
    }

    #[test]
    fn rejects_every_single_byte_wire_mutation_and_truncation() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let id = Uuid::new_v4();
        let value = invoice(id, &key, Some(4));
        let wire = check(&value, &key, id).unwrap();
        for offset in 0..wire.len() {
            let mut changed = wire.clone();
            changed[offset] ^= 1;
            let mut bad = value.clone();
            bad["unsignedTransaction"] = json!(STANDARD.encode(changed));
            assert!(
                check(&bad, &key, id).is_err(),
                "accepted mutation at {offset}"
            );
            bad["unsignedTransaction"] = json!(STANDARD.encode(&wire[..offset]));
            assert!(
                check(&bad, &key, id).is_err(),
                "accepted truncation at {offset}"
            );
        }
        let mut bad = value;
        let mut extra = wire;
        extra.push(0);
        bad["unsignedTransaction"] = json!(STANDARD.encode(extra));
        assert!(check(&bad, &key, id).is_err());
    }

    #[test]
    fn rejects_changed_terms_amount_mint_payer_recipient_memo_and_fees() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let id = Uuid::new_v4();
        let value = invoice(id, &key, Some(4));
        for (field, replacement) in [
            ("network", json!("solana:devnet")),
            ("asset", json!(TOKEN)),
            ("amount", json!("01000000")),
            ("amount", json!("2000000")),
            ("payer", json!(USDC)),
            ("payTo", json!(TOKEN)),
            ("memo", json!(format!("pipe-credit:{}", Uuid::new_v4()))),
            ("decimals", json!(9)),
            ("blockhash", json!(USDC)),
            ("computeUnitLimit", json!(50001)),
            ("computeUnitPriceMicroLamports", json!(100001)),
            ("computeUnitPriceMicroLamports", Value::Null),
            ("messageVersion", json!(5)),
            ("lastValidBlockHeight", json!(0)),
            ("expiresAt", json!(0)),
        ] {
            let mut bad = value.clone();
            bad["terms"][field] = replacement;
            assert!(check(&bad, &key, id).is_err(), "accepted changed {field}");
        }
        let mut bad = value;
        bad["credit_wallet"] = json!("another wallet");
        assert!(check(&bad, &key, id).is_err());
    }
}

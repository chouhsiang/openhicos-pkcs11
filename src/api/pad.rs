//! DigestInfo builders and RSA-OAEP decode for the high-level API.

use super::{Error, OaepHash, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub(crate) const DIGESTINFO_SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

pub(crate) fn digestinfo_md5(hash: &[u8; 16]) -> [u8; 34] {
    let prefix: [u8; 18] = [
        0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05,
        0x00, 0x04, 0x10,
    ];
    let mut out = [0u8; 34];
    out[..18].copy_from_slice(&prefix);
    out[18..].copy_from_slice(hash);
    out
}

pub(crate) fn digestinfo_sha1(hash: &[u8; 20]) -> [u8; 35] {
    let prefix: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    let mut out = [0u8; 35];
    out[..15].copy_from_slice(&prefix);
    out[15..].copy_from_slice(hash);
    out
}

pub(crate) fn digestinfo_sha256(hash: &[u8; 32]) -> [u8; 51] {
    let mut out = [0u8; 51];
    out[..19].copy_from_slice(&DIGESTINFO_SHA256_PREFIX);
    out[19..].copy_from_slice(hash);
    out
}

pub(crate) fn digestinfo_sha384(hash: &[u8; 48]) -> [u8; 67] {
    let prefix: [u8; 19] = [
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    let mut out = [0u8; 67];
    out[..19].copy_from_slice(&prefix);
    out[19..].copy_from_slice(hash);
    out
}

pub(crate) fn digestinfo_sha512(hash: &[u8; 64]) -> [u8; 83] {
    let prefix: [u8; 19] = [
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];
    let mut out = [0u8; 83];
    out[..19].copy_from_slice(&prefix);
    out[19..].copy_from_slice(hash);
    out
}

fn hash_oaep(alg: OaepHash, data: &[u8]) -> Vec<u8> {
    match alg {
        OaepHash::Sha1 => Sha1::digest(data).to_vec(),
        OaepHash::Sha256 => Sha256::digest(data).to_vec(),
        OaepHash::Sha384 => Sha384::digest(data).to_vec(),
        OaepHash::Sha512 => Sha512::digest(data).to_vec(),
    }
}

fn mgf1(alg: OaepHash, seed: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(length);
    let mut counter = 0u32;
    while out.len() < length {
        let mut block = Vec::with_capacity(seed.len() + 4);
        block.extend_from_slice(seed);
        block.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&hash_oaep(alg, &block));
        counter = counter
            .checked_add(1)
            .ok_or_else(|| Error::Internal("MGF1 counter overflow".into()))?;
    }
    out.truncate(length);
    Ok(out)
}

pub(crate) fn oaep_decode(alg: OaepHash, label: &[u8], em: &[u8]) -> Result<Vec<u8>> {
    let h_len = hash_oaep(alg, b"").len();
    if em.len() < 2 * h_len + 2 || em[0] != 0x00 {
        return Err(Error::DecryptFailed);
    }
    let masked_seed = &em[1..1 + h_len];
    let masked_db = &em[1 + h_len..];
    let seed_mask = mgf1(alg, masked_db, h_len)?;
    let seed: Vec<u8> = masked_seed
        .iter()
        .zip(seed_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let db_mask = mgf1(alg, &seed, masked_db.len())?;
    let db: Vec<u8> = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let lhash = hash_oaep(alg, label);
    if db.len() < h_len || db[..h_len] != lhash[..] {
        return Err(Error::DecryptFailed);
    }
    let mut i = h_len;
    while i < db.len() && db[i] == 0 {
        i += 1;
    }
    if i >= db.len() || db[i] != 0x01 {
        return Err(Error::DecryptFailed);
    }
    Ok(db[i + 1..].to_vec())
}

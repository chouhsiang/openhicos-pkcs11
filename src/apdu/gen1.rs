//! Gen1 — 一代卡 APDU helpers (T7S style).
//!
//! Covers 工商憑證與一代自然人憑證等共用 CLA `0x80` 流程。
//! PIN VERIFY uses fixed 2-key 3DES. RSA sign uses proprietary `EA` / `C1`.
//!
//! Covers 工商憑證與一代自然人憑證等共用 CLA `0x80` 流程。
//! PIN VERIFY uses fixed 2-key 3DES. RSA sign uses proprietary `EA` / `C1`.
//! Public-key records use P2=`00` with a length prefix.

use super::{cla, select_fid, select_mf, PinResult, PIN_MAX};
use crate::pcsc::PcscConn;
use des::cipher::{BlockCipherEncrypt, KeyInit};
use des::TdesEde2;

const SECURE_PIN_KEY: [u8; 16] = [
    0x43, 0x48, 0x54, 0x54, 0x4c, 0x38, 0x66, 0x30, 0x48, 0x69, 0x43, 0x61, 0x72, 0x64, 0x56, 0x32,
];
const RSA_BLOCK_LEN: usize = 256;
const RSA_CHUNK_LEN: usize = 128;

fn tdes_encrypt_block(key: &[u8; 16], block: &mut [u8; 8]) -> Result<(), ()> {
    let cipher = TdesEde2::new_from_slice(key).map_err(|_| ())?;
    cipher.encrypt_block(block.into());
    Ok(())
}

fn tdes_cbc_mac(key: &[u8; 16], iv: &[u8; 8], data: &[u8]) -> Result<[u8; 8], ()> {
    let mut mac = *iv;
    let pad = 8 - (data.len() % 8);
    let mut padded = Vec::with_capacity(data.len() + pad);
    padded.extend_from_slice(data);
    padded.resize(data.len() + pad, pad as u8);
    for chunk in padded.chunks_exact(8) {
        for i in 0..8 {
            mac[i] ^= chunk[i];
        }
        tdes_encrypt_block(key, &mut mac)?;
    }
    Ok(mac)
}

fn tdes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 8], data: &[u8]) -> Result<Vec<u8>, ()> {
    let pad = 8 - (data.len() % 8);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.resize(data.len() + pad, pad as u8);
    let mut previous = *iv;
    for chunk in out.chunks_exact_mut(8) {
        for i in 0..8 {
            chunk[i] ^= previous[i];
        }
        let block: &mut [u8; 8] = chunk.try_into().map_err(|_| ())?;
        tdes_encrypt_block(key, block)?;
        previous.copy_from_slice(block);
    }
    Ok(out)
}

fn select_key_ef(pcsc: &mut PcscConn) -> Result<(), ()> {
    if select_fid(pcsc, 0x0810).is_ok() {
        return Ok(());
    }
    select_mf(pcsc)?;
    select_fid(pcsc, 0x5030)?;
    select_fid(pcsc, 0x0810)
}

/// Gen1 protects VERIFY with 2-key 3DES CBC encryption and a CBC MAC.
/// Sending a conventional clear-text VERIFY is rejected and can consume a PIN
/// retry, so this has no plain fallback.
pub fn verify_pin(pcsc: &mut PcscConn, _pin_ref: u8, pin: &[u8]) -> PinResult {
    if pin.is_empty() || pin.len() > PIN_MAX {
        return PinResult::Error;
    }
    if select_key_ef(pcsc).is_err() {
        return PinResult::Error;
    }
    let mut pinbuf = [0xFFu8; PIN_MAX];
    pinbuf[..pin.len()].copy_from_slice(pin);
    let mut iv = [0u8; 8];
    if getrandom::fill(&mut iv).is_err() {
        return PinResult::Error;
    }
    let mac = match tdes_cbc_mac(&SECURE_PIN_KEY, &iv, &pinbuf) {
        Ok(mac) => mac,
        Err(_) => return PinResult::Error,
    };
    let mut protected = Vec::with_capacity(PIN_MAX + mac.len());
    protected.extend_from_slice(&pinbuf);
    protected.extend_from_slice(&mac);
    let encrypted = match tdes_cbc_encrypt(&SECURE_PIN_KEY, &iv, &protected) {
        Ok(encrypted) => encrypted,
        Err(_) => return PinResult::Error,
    };
    let mut cmd = vec![0x8C, 0x20, 0x00, 0x01, (iv.len() + encrypted.len()) as u8];
    cmd.extend_from_slice(&iv);
    cmd.extend_from_slice(&encrypted);
    let mut resp = Vec::new();
    let sw = match pcsc.transmit(&cmd, &mut resp) {
        Ok(sw) => sw,
        Err(_) => return PinResult::Error,
    };
    if sw == 0x9000 {
        PinResult::Ok
    } else if sw == 0x6983 {
        PinResult::Locked
    } else if (sw & 0xFFF0) == 0x63C0 {
        PinResult::Incorrect
    } else {
        PinResult::Error
    }
}

fn pkcs1_v15_signature_block(data: &[u8]) -> Result<[u8; RSA_BLOCK_LEN], ()> {
    if data.len() > RSA_BLOCK_LEN - 11 {
        return Err(());
    }
    let mut block = [0xFFu8; RSA_BLOCK_LEN];
    block[0] = 0x00;
    block[1] = 0x01;
    let separator = RSA_BLOCK_LEN - data.len() - 1;
    block[separator] = 0x00;
    block[separator + 1..].copy_from_slice(data);
    Ok(block)
}

/// Strip PKCS#1 v1.5 encryption padding (`00 02 | PS | 00 | M`).
fn pkcs1_v15_unpad_type2(block: &[u8]) -> Result<&[u8], ()> {
    if block.len() != RSA_BLOCK_LEN || block[0] != 0x00 || block[1] != 0x02 {
        return Err(());
    }
    let mut i = 2usize;
    while i < block.len() && block[i] != 0x00 {
        i += 1;
    }
    if i < 10 || i >= block.len() {
        return Err(());
    }
    Ok(&block[i + 1..])
}

/// Proprietary gen1 RSA private operation: two 128-byte `EA` transfers then
/// one `C1` continuation read.
fn rsa_private(
    pcsc: &mut PcscConn,
    key_ref: u8,
    input: &[u8; RSA_BLOCK_LEN],
    out: &mut [u8; RSA_BLOCK_LEN],
) -> Result<(), ()> {
    select_key_ef(pcsc)?;

    let mut result = Vec::with_capacity(RSA_BLOCK_LEN);
    for (index, chunk) in input.chunks_exact(RSA_CHUNK_LEN).enumerate() {
        let p1 = if index == 0 { 0x82 } else { 0x02 };
        let mut cmd = vec![0x80, 0xEA, p1, key_ref, RSA_CHUNK_LEN as u8];
        cmd.extend_from_slice(chunk);
        let mut resp = Vec::new();
        if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? != 0x9000 {
            return Err(());
        }
        result.extend_from_slice(&resp);
    }
    while result.len() < RSA_BLOCK_LEN {
        let offset = result.len();
        let want = RSA_CHUNK_LEN.min(RSA_BLOCK_LEN - offset);
        let cmd = [0x80, 0xC1, (offset >> 8) as u8, offset as u8, want as u8];
        let mut resp = Vec::new();
        if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? != 0x9000
            || resp.is_empty()
            || resp.len() > want
        {
            return Err(());
        }
        result.extend_from_slice(&resp);
    }
    if result.len() != RSA_BLOCK_LEN {
        return Err(());
    }
    out.copy_from_slice(&result);
    Ok(())
}

pub fn rsa_private_op(
    pcsc: &mut PcscConn,
    key_ref: u8,
    input: &[u8],
    out: &mut [u8],
) -> Result<usize, ()> {
    if input.len() != RSA_BLOCK_LEN || out.len() < RSA_BLOCK_LEN {
        return Err(());
    }
    let mut block_in = [0u8; RSA_BLOCK_LEN];
    block_in.copy_from_slice(input);
    let mut block_out = [0u8; RSA_BLOCK_LEN];
    rsa_private(pcsc, key_ref, &block_in, &mut block_out)?;
    out[..RSA_BLOCK_LEN].copy_from_slice(&block_out);
    Ok(RSA_BLOCK_LEN)
}

pub fn sign(pcsc: &mut PcscConn, key_ref: u8, data: &[u8], out: &mut [u8]) -> Result<usize, ()> {
    if out.len() < RSA_BLOCK_LEN {
        return Err(());
    }
    let block = pkcs1_v15_signature_block(data)?;
    let mut signature = [0u8; RSA_BLOCK_LEN];
    rsa_private(pcsc, key_ref, &block, &mut signature)?;
    out[..RSA_BLOCK_LEN].copy_from_slice(&signature);
    Ok(RSA_BLOCK_LEN)
}

/// Gen1 RSA decrypt (CKM_RSA_PKCS): same `80 EA`/`80 C1` as sign, then type-2 unpad.
pub fn decrypt(
    pcsc: &mut PcscConn,
    key_ref: u8,
    cipher: &[u8],
    out: &mut [u8],
) -> Result<usize, ()> {
    if cipher.len() != RSA_BLOCK_LEN {
        return Err(());
    }
    let mut input = [0u8; RSA_BLOCK_LEN];
    input.copy_from_slice(cipher);
    let mut block = [0u8; RSA_BLOCK_LEN];
    rsa_private(pcsc, key_ref, &input, &mut block)?;
    let msg = pkcs1_v15_unpad_type2(&block)?;
    if msg.len() > out.len() {
        return Err(());
    }
    out[..msg.len()].copy_from_slice(msg);
    Ok(msg.len())
}

/// Select key EF then READ RECORD with the active CLA (gen1 style).
pub fn read_key_record(pcsc: &mut PcscConn, record: u8, want: usize) -> Result<Vec<u8>, ()> {
    let cmd = [cla(), 0xB2, record, 0x00, want as u8];
    let mut resp = Vec::new();
    if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? != 0x9000 {
        return Err(());
    }
    if resp.is_empty() {
        Err(())
    } else {
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_protection_mac_and_ciphertext_lengths() {
        let iv = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pin = [b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF, 0xFF, 0xFF];
        let mac = tdes_cbc_mac(&SECURE_PIN_KEY, &iv, &pin).unwrap();
        assert_eq!(mac.len(), 8);
        let mut protected = pin.to_vec();
        protected.extend_from_slice(&mac);
        let encrypted = tdes_cbc_encrypt(&SECURE_PIN_KEY, &iv, &protected).unwrap();
        assert_eq!(encrypted.len(), 24);
        // Same inputs must yield the same ciphertext (regression guard).
        let again = tdes_cbc_encrypt(&SECURE_PIN_KEY, &iv, &protected).unwrap();
        assert_eq!(encrypted, again);
    }

    #[test]
    fn pkcs1_signature_block_has_expected_layout() {
        let block = pkcs1_v15_signature_block(b"abc").unwrap();
        assert_eq!(&block[..2], &[0x00, 0x01]);
        assert!(block[2..252].iter().all(|b| *b == 0xFF));
        assert_eq!(&block[252..], &[0x00, b'a', b'b', b'c']);
    }
}

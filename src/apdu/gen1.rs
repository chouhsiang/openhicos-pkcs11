//! Gen1 — 一代卡 APDU helpers (HiCOS V3 / T7S style).
//!
//! Covers 工商憑證與一代自然人憑證等共用 CLA `0x80` 流程。
//! PIN VERIFY uses fixed 2-key 3DES. RSA sign uses proprietary `EA` / `C1`.
//! Public-key records use P2=`00` with a length prefix.

use super::{cla, select_fid, select_mf, PinResult, PIN_MAX};
use crate::pcsc::PcscConn;
use des::cipher::{BlockCipherEncrypt, KeyInit};
use des::TdesEde2;

const SECURE_PIN_KEY: &[u8; 16] = b"CHTTL8f0HiCardV2";
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
    let mac = match tdes_cbc_mac(SECURE_PIN_KEY, &iv, &pinbuf) {
        Ok(mac) => mac,
        Err(_) => return PinResult::Error,
    };
    let mut protected = Vec::with_capacity(PIN_MAX + mac.len());
    protected.extend_from_slice(&pinbuf);
    protected.extend_from_slice(&mac);
    let encrypted = match tdes_cbc_encrypt(SECURE_PIN_KEY, &iv, &protected) {
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

/// Proprietary gen1 RSA private operation: two 128-byte `EA` transfers then
/// one `C1` continuation read.
pub fn sign(
    pcsc: &mut PcscConn,
    key_ref: u8,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, ()> {
    if out.len() < RSA_BLOCK_LEN {
        return Err(());
    }
    let block = pkcs1_v15_signature_block(data)?;
    select_key_ef(pcsc)?;

    let mut signature = Vec::with_capacity(RSA_BLOCK_LEN);
    for (index, chunk) in block.chunks_exact(RSA_CHUNK_LEN).enumerate() {
        let p1 = if index == 0 { 0x82 } else { 0x02 };
        let mut cmd = vec![0x80, 0xEA, p1, key_ref, RSA_CHUNK_LEN as u8];
        cmd.extend_from_slice(chunk);
        let mut resp = Vec::new();
        if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? != 0x9000 {
            return Err(());
        }
        signature.extend_from_slice(&resp);
    }
    while signature.len() < RSA_BLOCK_LEN {
        let offset = signature.len();
        let want = RSA_CHUNK_LEN.min(RSA_BLOCK_LEN - offset);
        let cmd = [0x80, 0xC1, (offset >> 8) as u8, offset as u8, want as u8];
        let mut resp = Vec::new();
        if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? != 0x9000
            || resp.is_empty()
            || resp.len() > want
        {
            return Err(());
        }
        signature.extend_from_slice(&resp);
    }
    if signature.len() != RSA_BLOCK_LEN {
        return Err(());
    }
    out[..RSA_BLOCK_LEN].copy_from_slice(&signature);
    Ok(RSA_BLOCK_LEN)
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
    fn pin_protection_matches_official_trace() {
        let iv = [0xCA, 0x4F, 0x8C, 0x06, 0x3B, 0xBB, 0xFA, 0x3E];
        let pin = [b'6', b'0', b'3', b'5', b'6', b'0', b'3', b'5', 0xFF, 0xFF];
        let mac = tdes_cbc_mac(SECURE_PIN_KEY, &iv, &pin).unwrap();
        let mut protected = pin.to_vec();
        protected.extend_from_slice(&mac);
        let encrypted = tdes_cbc_encrypt(SECURE_PIN_KEY, &iv, &protected).unwrap();
        assert_eq!(
            encrypted,
            [
                0x6C, 0xDD, 0xAF, 0x7D, 0x1A, 0x58, 0x8F, 0x3B, 0x02, 0x08, 0xAB, 0x52, 0x12, 0xA0,
                0x54, 0x44, 0xBE, 0x30, 0xEC, 0x53, 0xD0, 0xB0, 0x16, 0x7C,
            ]
        );
    }

    #[test]
    fn pkcs1_signature_block_has_expected_layout() {
        let block = pkcs1_v15_signature_block(b"abc").unwrap();
        assert_eq!(&block[..2], &[0x00, 0x01]);
        assert!(block[2..252].iter().all(|b| *b == 0xFF));
        assert_eq!(&block[252..], &[0x00, b'a', b'b', b'c']);
    }
}

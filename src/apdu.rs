//! APDU layer for HiCOS smart cards.

use crate::pcsc::PcscConn;
use des::cipher::{BlockCipherEncrypt, KeyInit};
use des::TdesEde2;
use std::cell::Cell;

pub const PIN_MAX: usize = 10;
pub const CHUNK: usize = 0xC8;
const HICOS_V3_KEY: &[u8; 16] = b"CHTTL8f0HiCardV2";
const RSA_BLOCK_LEN: usize = 256;
const RSA_CHUNK_LEN: usize = 128;

thread_local! {
    static CLA: Cell<u8> = Cell::new(0x80);
    static CLA_LOCKED: Cell<bool> = Cell::new(false);
}

pub fn reset_cla() {
    CLA.with(|c| c.set(0x80));
    CLA_LOCKED.with(|l| l.set(false));
}

fn cla() -> u8 {
    CLA.with(|c| c.get())
}

fn select_mf_with_cla(pcsc: &mut PcscConn, cla: u8) -> Result<(), ()> {
    let cmd = [cla, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
    let mut resp = Vec::new();
    let sw = pcsc.transmit(&cmd, &mut resp).map_err(|_| ())?;
    if sw == 0x9000 {
        Ok(())
    } else {
        Err(())
    }
}

pub fn select_mf(pcsc: &mut PcscConn) -> Result<(), ()> {
    if CLA_LOCKED.with(|l| l.get()) {
        return select_mf_with_cla(pcsc, cla());
    }
    for &try_cla in &[0x80u8, 0x00] {
        if select_mf_with_cla(pcsc, try_cla).is_ok() {
            CLA.with(|c| c.set(try_cla));
            CLA_LOCKED.with(|l| l.set(true));
            return Ok(());
        }
    }
    Err(())
}

pub fn select_fid(pcsc: &mut PcscConn, fid: u16) -> Result<(), ()> {
    let cmd = [
        cla(),
        0xA4,
        0x00,
        0x00,
        0x02,
        (fid >> 8) as u8,
        (fid & 0xFF) as u8,
    ];
    let mut resp = Vec::new();
    if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? == 0x9000 {
        Ok(())
    } else {
        Err(())
    }
}

pub fn select_path(pcsc: &mut PcscConn, path: &[u8], from_mf: bool) -> Result<(), ()> {
    if path.is_empty() || path.len() & 1 != 0 {
        return Err(());
    }
    if from_mf {
        select_mf(pcsc)?;
    }
    let mut i = 0;
    while i + 1 < path.len() {
        if i == 0 && path[0] == 0x3F && path[1] == 0x00 && from_mf {
            i += 2;
            continue;
        }
        let fid = ((path[i] as u16) << 8) | path[i + 1] as u16;
        select_fid(pcsc, fid)?;
        i += 2;
    }
    Ok(())
}

pub enum PinResult {
    Ok,
    Locked,
    Incorrect,
    Error,
}

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

fn select_hicos_key_ef(pcsc: &mut PcscConn) -> Result<(), ()> {
    if select_fid(pcsc, 0x0810).is_ok() {
        return Ok(());
    }
    select_mf(pcsc)?;
    select_fid(pcsc, 0x5030)?;
    select_fid(pcsc, 0x0810)
}

/// HiCOS V3/T7S protects VERIFY with 2-key 3DES CBC encryption and a CBC MAC.
/// Sending a conventional clear-text VERIFY to this card is rejected and can
/// consume a PIN retry, so this routine intentionally has no plain fallback.
pub fn verify_pin(pcsc: &mut PcscConn, _pin_ref: u8, pin: &[u8]) -> PinResult {
    if pin.is_empty() || pin.len() > PIN_MAX {
        return PinResult::Error;
    }
    if select_hicos_key_ef(pcsc).is_err() {
        return PinResult::Error;
    }
    let mut pinbuf = [0xFFu8; PIN_MAX];
    pinbuf[..pin.len()].copy_from_slice(pin);
    let mut iv = [0u8; 8];
    if getrandom::fill(&mut iv).is_err() {
        return PinResult::Error;
    }
    let mac = match tdes_cbc_mac(HICOS_V3_KEY, &iv, &pinbuf) {
        Ok(mac) => mac,
        Err(_) => return PinResult::Error,
    };
    let mut protected = Vec::with_capacity(PIN_MAX + mac.len());
    protected.extend_from_slice(&pinbuf);
    protected.extend_from_slice(&mac);
    let encrypted = match tdes_cbc_encrypt(HICOS_V3_KEY, &iv, &protected) {
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

/// Perform the proprietary HiCOS V3 RSA private operation used by the official
/// module: two 128-byte `EA` transfers followed by one `C1` continuation read.
pub fn hicos_v3_sign(
    pcsc: &mut PcscConn,
    key_ref: u8,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, ()> {
    if out.len() < RSA_BLOCK_LEN {
        return Err(());
    }
    let block = pkcs1_v15_signature_block(data)?;
    select_hicos_key_ef(pcsc)?;

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

pub fn read_binary(pcsc: &mut PcscConn, offset: u32, buf: &mut [u8]) -> Result<usize, ()> {
    if buf.is_empty() || buf.len() > 255 || offset > 0x7FFF {
        return Err(());
    }
    let mut try_want = buf.len();
    loop {
        let cmd = [
            cla(),
            0xB0,
            ((offset >> 8) & 0x7F) as u8,
            (offset & 0xFF) as u8,
            try_want as u8,
        ];
        let mut resp = Vec::new();
        let sw = pcsc.transmit(&cmd, &mut resp).map_err(|_| ())?;
        if sw == 0x6987 && try_want > 16 {
            try_want = 16;
            continue;
        }
        if sw != 0x9000 && (sw & 0xFF00) != 0x6200 {
            return Err(());
        }
        let n = resp.len().min(buf.len());
        buf[..n].copy_from_slice(&resp[..n]);
        return Ok(n);
    }
}

/// READ RECORD on the currently selected EF. HiCOS uses P2=0x00 with the
/// record number in P1 rather than the ISO 7816 `04` addressing mode.
pub fn read_record(pcsc: &mut PcscConn, record: u8, want: usize) -> Result<Vec<u8>, ()> {
    if want == 0 || want > 255 {
        return Err(());
    }
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

/// Read `len` bytes starting at `offset` from the currently selected EF.
pub fn read_binary_range(pcsc: &mut PcscConn, offset: u32, len: usize) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(len);
    let mut off = offset;
    while out.len() < len {
        let want = CHUNK.min(len - out.len());
        let mut chunk = vec![0u8; want];
        let got = read_binary(pcsc, off, &mut chunk)?;
        if got == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..got]);
        off += got as u32;
        if got < want {
            break;
        }
    }
    if out.is_empty() {
        Err(())
    } else {
        Ok(out)
    }
}

pub fn read_ef(pcsc: &mut PcscConn) -> Result<Vec<u8>, ()> {
    let mut buf = Vec::new();
    let mut off = 0u32;
    let chunk_sz = 0x20usize;
    loop {
        let mut chunk = vec![0u8; chunk_sz];
        let got = read_binary(pcsc, off, &mut chunk).unwrap_or(0);
        if got == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..got]);
        off += got as u32;
        if got < chunk_sz {
            break;
        }
        if off > 64 * 1024 {
            return Err(());
        }
    }
    if buf.is_empty() {
        Err(())
    } else {
        Ok(buf)
    }
}

pub fn mse_set_dst(pcsc: &mut PcscConn, key_ref: u8) -> Result<(), ()> {
    let cmd = [
        cla(),
        0x22,
        0x41,
        0xA4,
        0x06,
        0x84,
        0x01,
        key_ref,
        0x80,
        0x01,
        0x02,
    ];
    let mut resp = Vec::new();
    if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? == 0x9000 {
        Ok(())
    } else {
        Err(())
    }
}

pub fn mse_set_decipher(pcsc: &mut PcscConn, key_ref: u8) -> Result<(), ()> {
    let mut cmd = [
        cla(),
        0x22,
        0x41,
        0xB8,
        0x06,
        0x84,
        0x01,
        key_ref,
        0x80,
        0x01,
        0x02,
    ];
    let mut resp = Vec::new();
    if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? == 0x9000 {
        return Ok(());
    }
    cmd[5] = 0x83;
    if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? == 0x9000 {
        Ok(())
    } else {
        Err(())
    }
}

pub fn pso_cds(pcsc: &mut PcscConn, data: &[u8], out: &mut [u8]) -> Result<usize, ()> {
    if data.is_empty() || data.len() > 255 {
        return Err(());
    }
    let mut cmd = vec![cla(), 0x2A, 0x9E, 0x9A, data.len() as u8];
    cmd.extend_from_slice(data);
    cmd.push(0x00);
    let mut resp = Vec::new();
    if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? != 0x9000 {
        return Err(());
    }
    if resp.len() > out.len() {
        return Err(());
    }
    out[..resp.len()].copy_from_slice(&resp);
    Ok(resp.len())
}

pub fn pso_decipher(pcsc: &mut PcscConn, cipher: &[u8], out: &mut [u8]) -> Result<usize, ()> {
    if cipher.is_empty() || cipher.len() > 512 {
        return Err(());
    }
    let lc = cipher.len() + 1;
    if lc > 255 {
        return Err(());
    }
    let mut cmd = vec![cla(), 0x2A, 0x80, 0x86, lc as u8, 0x00];
    cmd.extend_from_slice(cipher);
    cmd.push(0x00);
    let mut resp = Vec::new();
    let mut sw = pcsc.transmit(&cmd, &mut resp).map_err(|_| ())?;
    if sw != 0x9000 {
        cmd = vec![cla(), 0x2A, 0x80, 0x86, cipher.len() as u8];
        cmd.extend_from_slice(cipher);
        cmd.push(0x00);
        resp.clear();
        sw = pcsc.transmit(&cmd, &mut resp).map_err(|_| ())?;
        if sw != 0x9000 {
            return Err(());
        }
    }
    if resp.len() > out.len() {
        return Err(());
    }
    out[..resp.len()].copy_from_slice(&resp);
    Ok(resp.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hicos_v3_pin_protection_matches_official_trace() {
        let iv = [0xCA, 0x4F, 0x8C, 0x06, 0x3B, 0xBB, 0xFA, 0x3E];
        let pin = [b'6', b'0', b'3', b'5', b'6', b'0', b'3', b'5', 0xFF, 0xFF];
        let mac = tdes_cbc_mac(HICOS_V3_KEY, &iv, &pin).unwrap();
        let mut protected = pin.to_vec();
        protected.extend_from_slice(&mac);
        let encrypted = tdes_cbc_encrypt(HICOS_V3_KEY, &iv, &protected).unwrap();
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

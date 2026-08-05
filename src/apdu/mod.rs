//! APDU layer for HiCOS smart cards.
//!
//! Card-specific commands live in submodules by **card generation** (not agency):
//! - [`gen1`] — 一代卡：CLA `0x80`、`8C 20` VERIFY、`80 EA`/`C1` 簽章
//!   （含工商憑證與一代自然人憑證）
//! - [`gen2`] — 二代卡：GPPKI AID + SCP03 SM（Diverse / `04 20` / `84 EA`）

pub mod gen1;
pub mod gen2;

use crate::pcsc::PcscConn;
use std::cell::Cell;

pub const PIN_MAX: usize = 10;
pub const CHUNK: usize = 0xC8;

/// Card access profile detected at bind time (by APDU generation).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CardProfile {
    /// 一代卡 (HiCOS V3 style): CLA `0x80`.
    Gen1,
    /// 二代卡 (GPPKI applet): CLA `0x00` + AID, SCP03.
    Gen2,
}

thread_local! {
    static CLA: Cell<u8> = Cell::new(0x80);
    static CLA_LOCKED: Cell<bool> = Cell::new(false);
    static PROFILE: Cell<CardProfile> = Cell::new(CardProfile::Gen1);
}

pub fn reset_cla() {
    CLA.with(|c| c.set(0x80));
    CLA_LOCKED.with(|l| l.set(false));
    PROFILE.with(|p| p.set(CardProfile::Gen1));
}

pub(crate) fn cla() -> u8 {
    CLA.with(|c| c.get())
}

pub fn profile() -> CardProfile {
    PROFILE.with(|p| p.get())
}

pub(crate) fn set_profile(profile: CardProfile) {
    PROFILE.with(|p| p.set(profile));
    match profile {
        CardProfile::Gen1 => {
            CLA.with(|c| c.set(0x80));
            CLA_LOCKED.with(|l| l.set(true));
        }
        CardProfile::Gen2 => {
            CLA.with(|c| c.set(0x00));
            CLA_LOCKED.with(|l| l.set(true));
        }
    }
}

pub(crate) fn select_mf_with_cla(pcsc: &mut PcscConn, try_cla: u8) -> Result<(), ()> {
    let cmd = [try_cla, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
    let mut resp = Vec::new();
    let sw = pcsc.transmit(&cmd, &mut resp).map_err(|_| ())?;
    if sw == 0x9000 {
        Ok(())
    } else {
        Err(())
    }
}

/// Detect card profile: try gen2 GPPKI AID first, else gen1 MF with CLA probing.
pub fn detect_and_select(pcsc: &mut PcscConn) -> Result<CardProfile, ()> {
    if gen2::select_aid(pcsc).is_ok() {
        set_profile(CardProfile::Gen2);
        return Ok(CardProfile::Gen2);
    }
    for &try_cla in &[0x80u8, 0x00] {
        if select_mf_with_cla(pcsc, try_cla).is_ok() {
            CLA.with(|c| c.set(try_cla));
            CLA_LOCKED.with(|l| l.set(true));
            set_profile(CardProfile::Gen1);
            return Ok(CardProfile::Gen1);
        }
    }
    Err(())
}

pub fn select_mf(pcsc: &mut PcscConn) -> Result<(), ()> {
    if CLA_LOCKED.with(|l| l.get()) {
        return match profile() {
            CardProfile::Gen2 => gen2::select_aid(pcsc),
            CardProfile::Gen1 => select_mf_with_cla(pcsc, cla()),
        };
    }
    detect_and_select(pcsc).map(|_| ())
}

pub fn select_fid(pcsc: &mut PcscConn, fid: u16) -> Result<(), ()> {
    if fid == 0x7FFF && profile() == CardProfile::Gen2 {
        return gen2::select_aid(pcsc);
    }
    let mut cmd = vec![
        cla(),
        0xA4,
        0x00,
        0x00,
        0x02,
        (fid >> 8) as u8,
        (fid & 0xFF) as u8,
    ];
    if profile() == CardProfile::Gen2 {
        cmd[3] = 0x04;
        cmd.push(0x00);
    }
    let mut resp = Vec::new();
    let sw = pcsc.transmit(&cmd, &mut resp).map_err(|_| ())?;
    if sw == 0x9000 || (sw & 0xFF00) == 0x6200 {
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
        if path[i] == 0x7F && path[i + 1] == 0xFF {
            gen2::select_aid(pcsc)?;
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

/// Dispatch PIN VERIFY to the active card profile.
pub fn verify_pin(pcsc: &mut PcscConn, pin_ref: u8, pin: &[u8]) -> PinResult {
    match profile() {
        CardProfile::Gen1 => gen1::verify_pin(pcsc, pin_ref, pin),
        CardProfile::Gen2 => gen2::verify_pin(pcsc, pin_ref, pin),
    }
}

/// Clear card-profile auth caches (gen2 SCP/PIN) on logout.
pub fn clear_auth_state() {
    if profile() == CardProfile::Gen2 {
        gen2::clear_auth_state();
    }
}

/// Dispatch RSA sign to the active card profile.
pub fn sign(
    pcsc: &mut PcscConn,
    key_ref: u8,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, ()> {
    match profile() {
        CardProfile::Gen1 => gen1::sign(pcsc, key_ref, data, out),
        CardProfile::Gen2 => gen2::sign(pcsc, key_ref, data, out),
    }
}

/// Dispatch RSA decrypt (`CKM_RSA_PKCS`) to the active card profile.
///
/// HiCOS uses the same proprietary `EA`/`C1` private op as sign (not ISO MSE/PSO),
/// then host-side PKCS#1 v1.5 type-2 unpadding.
pub fn decrypt(
    pcsc: &mut PcscConn,
    key_ref: u8,
    cipher: &[u8],
    out: &mut [u8],
) -> Result<usize, ()> {
    match profile() {
        CardProfile::Gen1 => gen1::decrypt(pcsc, key_ref, cipher, out),
        CardProfile::Gen2 => gen2::decrypt(pcsc, key_ref, cipher, out),
    }
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

/// READ RECORD with P2=0x00 (gen1 key EF style).
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

//! APDU layer for HiCOS smart cards.

use crate::pcsc::PcscConn;
use std::cell::Cell;

pub const PIN_MAX: usize = 10;
pub const CHUNK: usize = 0xC8;

pub const AID_PKCS15: &[u8] = &[
    0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35,
];
pub const AID_PKI: &[u8] = &[
    0xA0, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00, 0x06, 0x22, 0x01, 0x00, 0x01,
];

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

pub fn select_aid(pcsc: &mut PcscConn, aid: &[u8]) -> Result<(), ()> {
    if aid.is_empty() || aid.len() > 16 {
        return Err(());
    }
    for &p2 in &[0x0Cu8, 0x00] {
        let mut cmd = vec![cla(), 0xA4, 0x04, p2, aid.len() as u8];
        cmd.extend_from_slice(aid);
        let mut resp = Vec::new();
        if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? == 0x9000 {
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

pub fn verify_pin(pcsc: &mut PcscConn, pin_ref: u8, pin: &[u8]) -> PinResult {
    if pin.is_empty() {
        return PinResult::Error;
    }
    let mut pinbuf = [0xFFu8; PIN_MAX];
    let n = pin.len().min(PIN_MAX);
    pinbuf[..n].copy_from_slice(&pin[..n]);
    let mut cmd = vec![cla(), 0x20, 0x00, pin_ref, PIN_MAX as u8];
    cmd.extend_from_slice(&pinbuf);
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

pub fn read_binary(
    pcsc: &mut PcscConn,
    offset: u32,
    buf: &mut [u8],
) -> Result<usize, ()> {
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

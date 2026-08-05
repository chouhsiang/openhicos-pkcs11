//! Gen2 — 二代卡 APDU helpers (GPPKI applet).
//!
//! - SELECT by AID, then CLA `0x00` SELECT FID with P2=`04`+Le
//! - Public-key components via CLA `0x80` READ RECORD (`P2` = `03`/`04`)
//! - Login via card-key Diverse + SCP03 + SM VERIFY
//! - Sign via SM-wrapped `EA` / `C1` RSA private operation

use super::{PinResult, PIN_MAX};
use crate::pcsc::PcscConn;
use aes::Aes128;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use cmac::{Cmac, Mac};
use std::cell::RefCell;

/// Gen2 GPPKI applet AID (16 bytes).
pub const AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00, 0x06, 0x22, 0x01, 0x69, 0x64, 0x00, 0x01, 0x01, 0x01,
];

const ISD_CM_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x02, 0x83, 0xFF, 0x08, 0x86, 0x92, 0x53, 0x53, 0x89, 0xC0, 0x00, 0x14,
];
const ISD_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];

/// Static AES-wrapped master key material for 16-byte card keys (from official module).
const MASTER_ENC_BLOB_16: [u8; 16] = [
    0xee, 0xe7, 0x65, 0x09, 0x9e, 0x9b, 0x8d, 0x52, 0xa3, 0x37, 0x34, 0x76, 0x0d, 0xd0, 0x30, 0x5e,
];
const DIVERSE_KEK: &[u8; 16] = b"CHT HiCOSPKCS#11";

const RSA_BLOCK_LEN: usize = 256;
const RSA_CHUNK_LEN: usize = 128;

struct Scp03Session {
    s_enc: [u8; 16],
    s_mac: [u8; 16],
    mcv: [u8; 16],
    enc_counter: u32,
    open: bool,
}

impl Scp03Session {
    fn closed() -> Self {
        Self {
            s_enc: [0; 16],
            s_mac: [0; 16],
            mcv: [0; 16],
            enc_counter: 1,
            open: false,
        }
    }
}

thread_local! {
    static SCP: RefCell<Scp03Session> = RefCell::new(Scp03Session::closed());
    /// Cached after successful login; official re-VERIFYs before each sign.
    static CACHED_PIN: RefCell<Option<Vec<u8>>> = RefCell::new(None);
    static STATIC_KEYS: RefCell<Option<([u8; 16], [u8; 16])>> = RefCell::new(None);
}

/// Drop SCP session and cached PIN/keys (logout / failed auth).
pub fn clear_auth_state() {
    SCP.with(|s| *s.borrow_mut() = Scp03Session::closed());
    CACHED_PIN.with(|p| *p.borrow_mut() = None);
    STATIC_KEYS.with(|k| *k.borrow_mut() = None);
}

fn aes_ecb_encrypt(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(key).expect("aes-128 key");
    let mut b = *block;
    cipher.encrypt_block((&mut b).into());
    b
}

fn aes_ecb_decrypt(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(key).expect("aes-128 key");
    let mut b = *block;
    cipher.decrypt_block((&mut b).into());
    b
}

fn aes_cmac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key).expect("cmac key");
    mac.update(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    debug_assert!(data.len() % 16 == 0);
    let cipher = Aes128::new_from_slice(key).expect("aes-128 key");
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev[i];
        }
        cipher.encrypt_block((&mut block).into());
        prev = block;
        out.extend_from_slice(&block);
    }
    out
}

fn pad80(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.extend_from_slice(data);
    out.push(0x80);
    while out.len() % 16 != 0 {
        out.push(0x00);
    }
    out
}

fn scp03_kdf(key: &[u8], constant: u8, context: &[u8], out_bits: u16) -> Vec<u8> {
    let out_len = ((out_bits as usize) + 7) / 8;
    let mut result = Vec::new();
    let mut counter = 1u8;
    while result.len() < out_len {
        let mut block = vec![0u8; 11];
        block.push(constant);
        block.push(0x00);
        block.push((out_bits >> 8) as u8);
        block.push((out_bits & 0xff) as u8);
        block.push(counter);
        block.extend_from_slice(context);
        result.extend_from_slice(&aes_cmac(key, &block));
        counter = counter.wrapping_add(1);
    }
    result.truncate(out_len);
    result
}

fn counter_block(counter: u32) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[12..].copy_from_slice(&counter.to_be_bytes());
    block
}

fn select_aid_raw(pcsc: &mut PcscConn, aid: &[u8], with_le: Option<u8>) -> Result<(), ()> {
    let mut cmd = Vec::with_capacity(6 + aid.len());
    cmd.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00, aid.len() as u8]);
    cmd.extend_from_slice(aid);
    if let Some(le) = with_le {
        cmd.push(le);
    }
    let mut resp = Vec::new();
    let sw = pcsc.transmit(&cmd, &mut resp).map_err(|_| ())?;
    if sw == 0x9000 || (sw & 0xFF00) == 0x6200 {
        Ok(())
    } else {
        Err(())
    }
}

fn get_data(pcsc: &mut PcscConn, tag: u8) -> Result<Vec<u8>, ()> {
    let cmd = [0x80, 0xCA, 0x00, tag, 0x00];
    let mut resp = Vec::new();
    if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? != 0x9000 {
        return Err(());
    }
    Ok(resp)
}

/// Derive static SCP keys (K-ENC / K-MAC) via official Diverse scheme.
fn diverse_static_keys(pcsc: &mut PcscConn) -> Result<([u8; 16], [u8; 16]), ()> {
    if let Some(keys) = STATIC_KEYS.with(|k| k.borrow().clone()) {
        return Ok(keys);
    }
    // AID itself ends with `00 14` (15 bytes); no separate Le.
    select_aid_raw(pcsc, ISD_CM_AID, None)?;
    let e0 = get_data(pcsc, 0xE0)?;
    // E0 12 C0 04 vv kk 88 ll ...
    if e0.len() < 8 || e0[0] != 0xE0 {
        return Err(());
    }
    let key_len = e0[7] as usize;
    if key_len != 16 {
        // Only the 16-byte master blob is implemented; other lengths need more samples.
        return Err(());
    }

    select_aid_raw(pcsc, ISD_AID, None)?;
    let tag45 = get_data(pcsc, 0x45)?;
    // 45 0A <10-byte card id>
    if tag45.len() < 12 || tag45[0] != 0x45 || tag45[1] != 0x0A {
        return Err(());
    }
    let card_id = &tag45[2..12];

    let master = aes_ecb_decrypt(DIVERSE_KEK, &MASTER_ENC_BLOB_16);
    let k_enc = derive_key(&master, 0x04, card_id, ISD_CM_AID, key_len)?;
    let k_mac = derive_key(&master, 0x06, card_id, ISD_CM_AID, key_len)?;
    STATIC_KEYS.with(|k| *k.borrow_mut() = Some((k_enc, k_mac)));
    Ok((k_enc, k_mac))
}

fn sm_verify(pcsc: &mut PcscConn, pin: &[u8]) -> PinResult {
    let mut pinbuf = [0xFFu8; PIN_MAX];
    pinbuf[..pin.len()].copy_from_slice(pin);
    let (sw, _) = match transmit_sm(pcsc, 0x00, 0x20, 0x00, 0x01, &pinbuf, None, true) {
        Ok(v) => v,
        Err(()) => return PinResult::Error,
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

/// Official sign path re-opens SCP and VERIFY, then SM-SELECT key DF.
fn prepare_for_private_op(pcsc: &mut PcscConn) -> Result<(), ()> {
    let pin = CACHED_PIN.with(|p| p.borrow().clone()).ok_or(())?;
    let (k_enc, k_mac) = diverse_static_keys(pcsc)?;
    SCP.with(|s| *s.borrow_mut() = Scp03Session::closed());
    open_scp03(pcsc, &k_enc, &k_mac)?;
    match sm_verify(pcsc, &pin) {
        PinResult::Ok => {}
        _ => {
            SCP.with(|s| *s.borrow_mut() = Scp03Session::closed());
            return Err(());
        }
    }
    sm_select_fid(pcsc, 0x5030)?;
    sm_select_fid(pcsc, 0x0810)?;
    Ok(())
}

fn sm_select_fid(pcsc: &mut PcscConn, fid: u16) -> Result<(), ()> {
    let data = [(fid >> 8) as u8, (fid & 0xFF) as u8];
    let (sw, _) = transmit_sm(pcsc, 0x00, 0xA4, 0x00, 0x04, &data, None, true)?;
    if sw == 0x9000 || (sw & 0xFF00) == 0x6200 {
        Ok(())
    } else {
        Err(())
    }
}

fn derive_key(
    master: &[u8; 16],
    constant: u8,
    card_id: &[u8],
    aid: &[u8],
    key_len: usize,
) -> Result<[u8; 16], ()> {
    if card_id.len() != 10 || aid.len() < 15 || key_len != 16 {
        return Err(());
    }
    let type_byte = match constant {
        0x04 => 1,
        0x06 => 2,
        0x0C => 3,
        _ => return Err(()),
    };
    let mut scheme = vec![0u8; key_len + 0x10];
    scheme[0x10] = type_byte;
    scheme[0x11..0x19].copy_from_slice(&card_id[..8]);
    scheme[0x19..0x1B].copy_from_slice(&card_id[8..10]);
    let copy_len = key_len - 11;
    let aid_off = 0x1A - key_len;
    scheme[0x1B..0x1B + copy_len].copy_from_slice(&aid[aid_off..aid_off + copy_len]);
    scheme[0x0B] = constant;
    scheme[0x0D] = (key_len >> 5) as u8;
    let bit_len = (key_len << 3) as u8;
    scheme[0x0E] = bit_len;
    scheme[0x0F] = if (key_len << 3) < 0x81 { 1 } else { 2 };
    Ok(aes_cmac(master, &scheme))
}

fn open_scp03(pcsc: &mut PcscConn, k_enc: &[u8; 16], k_mac: &[u8; 16]) -> Result<(), ()> {
    select_aid(pcsc)?;

    let mut host_challenge = [0u8; 8];
    getrandom::fill(&mut host_challenge).map_err(|_| ())?;

    let mut cmd = vec![0x80, 0x50, 0x01, 0x00, 0x08];
    cmd.extend_from_slice(&host_challenge);
    cmd.push(0x00);
    let mut iu = Vec::new();
    if pcsc.transmit(&cmd, &mut iu).map_err(|_| ())? != 0x9000 || iu.len() < 29 {
        return Err(());
    }
    // key_data(10) || key_info(3) || card_challenge(8) || card_cryptogram(8)
    if iu[11] != 0x03 {
        return Err(()); // SCP03
    }
    let card_challenge = &iu[13..21];
    let card_cryptogram = &iu[21..29];

    let mut context = Vec::with_capacity(16);
    context.extend_from_slice(&host_challenge);
    context.extend_from_slice(card_challenge);

    let s_mac = scp03_kdf(k_mac, 0x06, &context, 0x80);
    let s_enc = scp03_kdf(k_enc, 0x04, &context, 0x80);
    let host_crypto = scp03_kdf(&s_mac, 0x01, &context, 0x40);
    let card_calc = scp03_kdf(&s_mac, 0x00, &context, 0x40);
    if card_calc.as_slice() != card_cryptogram {
        return Err(());
    }

    // EXTERNAL AUTHENTICATE, security level 3 (C-MAC | C-DECRYPTION), MCV = 0
    let mut mac_input = vec![0u8; 16];
    mac_input.extend_from_slice(&[0x84, 0x82, 0x03, 0x00, 0x10]);
    mac_input.extend_from_slice(&host_crypto);
    let full_mac = aes_cmac(&s_mac, &mac_input);

    let mut ea = vec![0x84, 0x82, 0x03, 0x00, 0x10];
    ea.extend_from_slice(&host_crypto);
    ea.extend_from_slice(&full_mac[..8]);
    let mut resp = Vec::new();
    if pcsc.transmit(&ea, &mut resp).map_err(|_| ())? != 0x9000 {
        return Err(());
    }

    SCP.with(|s| {
        let mut sess = s.borrow_mut();
        sess.s_enc.copy_from_slice(&s_enc);
        sess.s_mac.copy_from_slice(&s_mac);
        sess.mcv = full_mac;
        sess.enc_counter = 1;
        sess.open = true;
    });
    Ok(())
}

fn wrap_command(
    sess: &mut Scp03Session,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    le: Option<u8>,
    encrypt: bool,
) -> Vec<u8> {
    let sm_cla = cla | 0x04;
    let ciphertext = if encrypt && !data.is_empty() {
        let iv = aes_ecb_encrypt(&sess.s_enc, &counter_block(sess.enc_counter));
        sess.enc_counter = sess.enc_counter.wrapping_add(1);
        aes_cbc_encrypt(&sess.s_enc, &iv, &pad80(data))
    } else {
        Vec::new()
    };

    let lc = (ciphertext.len() + 8) as u8;
    let mut mac_input = sess.mcv.to_vec();
    mac_input.extend_from_slice(&[sm_cla, ins, p1, p2, lc]);
    mac_input.extend_from_slice(&ciphertext);
    let full_mac = aes_cmac(&sess.s_mac, &mac_input);
    sess.mcv = full_mac;

    let mut cmd = vec![sm_cla, ins, p1, p2, lc];
    cmd.extend_from_slice(&ciphertext);
    cmd.extend_from_slice(&full_mac[..8]);
    if let Some(le) = le {
        cmd.push(le);
    }
    cmd
}

fn transmit_sm(
    pcsc: &mut PcscConn,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    le: Option<u8>,
    encrypt: bool,
) -> Result<(u16, Vec<u8>), ()> {
    SCP.with(|s| {
        let mut sess = s.borrow_mut();
        if !sess.open {
            return Err(());
        }
        let cmd = wrap_command(&mut sess, cla, ins, p1, p2, data, le, encrypt);
        drop(sess);
        let mut resp = Vec::new();
        let sw = pcsc.transmit(&cmd, &mut resp).map_err(|_| ())?;
        Ok((sw, resp))
    })
}

/// SELECT the gen2 GPPKI applet by AID.
pub fn select_aid(pcsc: &mut PcscConn) -> Result<(), ()> {
    let mut cmd = Vec::with_capacity(6 + AID.len());
    cmd.extend_from_slice(&[0x00, 0xA4, 0x04, 0x0C, AID.len() as u8]);
    cmd.extend_from_slice(AID);
    cmd.push(0x00); // Le (matches official module)
    let mut resp = Vec::new();
    if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? == 0x9000 {
        Ok(())
    } else {
        Err(())
    }
}

/// Key-container READ RECORD: CLA `0x80`, P1 = keyRef, P2 = component
/// (`03`/`04` = modulus halves). Response is a raw 128-byte block.
pub fn read_pubkey_component(
    pcsc: &mut PcscConn,
    key_ref: u8,
    component: u8,
) -> Result<Vec<u8>, ()> {
    let cmd = [0x80, 0xB2, key_ref, component, 0x00];
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

/// Gen2 login: Diverse → SCP03 → SM VERIFY (`04 20`).
/// Official module uses P2=`01` for the user PIN (AODF pin_ref not trusted yet).
pub fn verify_pin(pcsc: &mut PcscConn, _pin_ref: u8, pin: &[u8]) -> PinResult {
    if pin.is_empty() || pin.len() > PIN_MAX {
        return PinResult::Error;
    }
    SCP.with(|s| *s.borrow_mut() = Scp03Session::closed());
    CACHED_PIN.with(|p| *p.borrow_mut() = None);

    let (k_enc, k_mac) = match diverse_static_keys(pcsc) {
        Ok(keys) => keys,
        Err(()) => return PinResult::Error,
    };
    if open_scp03(pcsc, &k_enc, &k_mac).is_err() {
        return PinResult::Error;
    }

    match sm_verify(pcsc, pin) {
        PinResult::Ok => {
            CACHED_PIN.with(|p| *p.borrow_mut() = Some(pin.to_vec()));
            PinResult::Ok
        }
        other => {
            SCP.with(|s| *s.borrow_mut() = Scp03Session::closed());
            other
        }
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
    // PS must be at least 8 bytes (indices 2..i).
    if i < 10 || i >= block.len() {
        return Err(());
    }
    Ok(&block[i + 1..])
}

/// Raw RSA private op under SCP03: `84 EA` / `84 C1` (same path as sign).
fn rsa_private(
    pcsc: &mut PcscConn,
    key_ref: u8,
    input: &[u8; RSA_BLOCK_LEN],
    out: &mut [u8; RSA_BLOCK_LEN],
) -> Result<(), ()> {
    prepare_for_private_op(pcsc)?;

    let mut result = Vec::with_capacity(RSA_BLOCK_LEN);
    let chunks: Vec<&[u8]> = input.chunks_exact(RSA_CHUNK_LEN).collect();
    for (index, chunk) in chunks.iter().enumerate() {
        let more = index + 1 < chunks.len();
        let p1 = if more { 0x82 } else { 0x02 };
        let le = if more { None } else { Some(0x80) };
        let (sw, resp) = transmit_sm(pcsc, 0x80, 0xEA, p1, key_ref, chunk, le, true)?;
        if sw != 0x9000 {
            return Err(());
        }
        result.extend_from_slice(&resp);
    }

    while result.len() < RSA_BLOCK_LEN {
        // Case-2 APDU `80 C1 00 80` + Le, MAC-only (no C-ENC on empty body).
        let (sw, resp) = transmit_sm(pcsc, 0x80, 0xC1, 0x00, 0x80, &[], Some(0x80), false)?;
        if sw != 0x9000 || resp.is_empty() {
            return Err(());
        }
        result.extend_from_slice(&resp);
        if result.len() > RSA_BLOCK_LEN {
            return Err(());
        }
    }

    out.copy_from_slice(&result[..RSA_BLOCK_LEN]);
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

/// Gen2 RSA sign: re-auth under SCP03, SM-SELECT key DF, then `84 EA` / `84 C1`.
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

/// Gen2 RSA decrypt (CKM_RSA_PKCS): same `84 EA`/`84 C1` as sign, then type-2 unpad.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs1_type2_unpad_extracts_message() {
        let mut block = [0xAAu8; RSA_BLOCK_LEN];
        block[0] = 0x00;
        block[1] = 0x02;
        let msg = b"openhicos-decrypt-test";
        let separator = RSA_BLOCK_LEN - msg.len() - 1;
        block[separator] = 0x00;
        block[separator + 1..].copy_from_slice(msg);
        assert_eq!(pkcs1_v15_unpad_type2(&block).unwrap(), msg);
    }

    #[test]
    fn diverse_matches_known_card_keys() {
        let card_id = [0x24, 0x05, 0x69, 0x64, 0x13, 0x00, 0x01, 0x90, 0x39, 0x57];
        let master = aes_ecb_decrypt(DIVERSE_KEK, &MASTER_ENC_BLOB_16);
        let enc = derive_key(&master, 0x04, &card_id, ISD_CM_AID, 16).unwrap();
        let mac = derive_key(&master, 0x06, &card_id, ISD_CM_AID, 16).unwrap();
        assert_eq!(
            enc,
            [
                0xab, 0x9c, 0x3c, 0x08, 0x3f, 0xe6, 0x3f, 0x48, 0x37, 0x57, 0xda, 0x8e, 0x4f, 0xea,
                0xf1, 0xbb
            ]
        );
        assert_eq!(
            mac,
            [
                0x32, 0x76, 0x2e, 0x98, 0x42, 0x30, 0x9b, 0x5a, 0x3a, 0xc3, 0x7c, 0xc3, 0x4f, 0x20,
                0x77, 0x59
            ]
        );
    }

    #[test]
    fn scp03_verify_wrap_matches_trace() {
        let k_enc = [
            0xab, 0x9c, 0x3c, 0x08, 0x3f, 0xe6, 0x3f, 0x48, 0x37, 0x57, 0xda, 0x8e, 0x4f, 0xea,
            0xf1, 0xbb,
        ];
        let k_mac = [
            0x32, 0x76, 0x2e, 0x98, 0x42, 0x30, 0x9b, 0x5a, 0x3a, 0xc3, 0x7c, 0xc3, 0x4f, 0x20,
            0x77, 0x59,
        ];
        let host = [0xD4, 0x05, 0xEC, 0x4C, 0xDC, 0x43, 0xCF, 0x8D];
        let card_chal = [0x03, 0x61, 0xBB, 0x15, 0xA8, 0xB6, 0x8C, 0x2E];
        let mut context = Vec::new();
        context.extend_from_slice(&host);
        context.extend_from_slice(&card_chal);
        let s_mac = scp03_kdf(&k_mac, 0x06, &context, 0x80);
        let s_enc = scp03_kdf(&k_enc, 0x04, &context, 0x80);
        let host_crypto = scp03_kdf(&s_mac, 0x01, &context, 0x40);
        let mut mac_input = vec![0u8; 16];
        mac_input.extend_from_slice(&[0x84, 0x82, 0x03, 0x00, 0x10]);
        mac_input.extend_from_slice(&host_crypto);
        let mcv = aes_cmac(&s_mac, &mac_input);

        let mut sess = Scp03Session {
            s_enc: s_enc.try_into().unwrap(),
            s_mac: s_mac.try_into().unwrap(),
            mcv,
            enc_counter: 1,
            open: true,
        };
        let mut pin = b"000000".to_vec();
        while pin.len() < 10 {
            pin.push(0xff);
        }
        let cmd = wrap_command(&mut sess, 0x00, 0x20, 0x00, 0x01, &pin, None, true);
        assert_eq!(
            &cmd[5..],
            &[
                0xC5, 0xB3, 0xBE, 0x9F, 0x58, 0x3A, 0x7E, 0xED, 0xC0, 0xA3, 0x11, 0x12, 0x43, 0x89,
                0xA4, 0x97, 0xE6, 0xEB, 0x39, 0x52, 0xA4, 0x0B, 0xC3, 0x0D
            ]
        );
    }
}

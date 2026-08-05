//! APDU layer for HiCOS smart cards.

use crate::pcsc::PcscConn;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use des::TdesEde2;
use std::cell::Cell;

pub const PIN_MAX: usize = 10;
pub const CHUNK: usize = 0xC8;
const HICOS_V3_KEY: &[u8; 16] = b"CHTTL8f0HiCardV2";
const RSA_BLOCK_LEN: usize = 256;
const RSA_CHUNK_LEN: usize = 128;
const GPPKI_ID_V1_AID: &[u8; 16] = &[
    0xA0, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00, 0x06, 0x22, 0x01, 0x69, 0x64, 0x00, 0x01, 0x01, 0x01,
];
const GP_MANAGEMENT_AID: &[u8; 15] = &[
    0xA0, 0x00, 0x00, 0x02, 0x83, 0xFF, 0x08, 0x86, 0x92, 0x53, 0x53, 0x89, 0xC0, 0x00, 0x14,
];
const GP_ISD_AID: &[u8; 7] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];
const GPPKI_USER_PIN_REF: u8 = 0x01;
const GPPKI_V1_ROOT_KEY: &[u8; 16] = &[
    0xDC, 0x4B, 0xAD, 0x21, 0xCF, 0x18, 0x42, 0xD5, 0xBE, 0x3E, 0x80, 0x7A, 0x56, 0x9F, 0x62, 0xA2,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardProfile {
    Unknown,
    DirectHicos,
    GpPkiIdV1,
}

thread_local! {
    static CLA: Cell<u8> = Cell::new(0x80);
    static CLA_LOCKED: Cell<bool> = Cell::new(false);
    static PROFILE: Cell<CardProfile> = Cell::new(CardProfile::Unknown);
}

pub fn reset_cla() {
    CLA.with(|c| c.set(0x80));
    CLA_LOCKED.with(|l| l.set(false));
    PROFILE.with(|p| p.set(CardProfile::Unknown));
}

pub fn card_profile() -> CardProfile {
    PROFILE.with(|p| p.get())
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

fn select_gppki_id_v1_applet(pcsc: &mut PcscConn) -> Result<(), ()> {
    let mut cmd = vec![0x00, 0xA4, 0x04, 0x0C, GPPKI_ID_V1_AID.len() as u8];
    cmd.extend_from_slice(GPPKI_ID_V1_AID);
    cmd.push(0x00);
    let mut resp = Vec::new();
    if pcsc.transmit(&cmd, &mut resp).map_err(|_| ())? == 0x9000 {
        Ok(())
    } else {
        Err(())
    }
}

pub fn select_mf(pcsc: &mut PcscConn) -> Result<(), ()> {
    if card_profile() == CardProfile::GpPkiIdV1 {
        return select_gppki_id_v1_applet(pcsc);
    }
    if CLA_LOCKED.with(|l| l.get()) {
        return select_mf_with_cla(pcsc, cla());
    }
    for &try_cla in &[0x80u8, 0x00] {
        if select_mf_with_cla(pcsc, try_cla).is_ok() {
            CLA.with(|c| c.set(try_cla));
            CLA_LOCKED.with(|l| l.set(true));
            PROFILE.with(|p| p.set(CardProfile::DirectHicos));
            return Ok(());
        }
    }
    if select_gppki_id_v1_applet(pcsc).is_ok() {
        CLA.with(|c| c.set(0x00));
        CLA_LOCKED.with(|l| l.set(true));
        PROFILE.with(|p| p.set(CardProfile::GpPkiIdV1));
        return Ok(());
    }
    Err(())
}

pub fn select_fid(pcsc: &mut PcscConn, fid: u16) -> Result<(), ()> {
    let cmd = if card_profile() == CardProfile::GpPkiIdV1 {
        vec![
            0x00,
            0xA4,
            0x00,
            0x04,
            0x02,
            (fid >> 8) as u8,
            (fid & 0xFF) as u8,
            0x00,
        ]
    } else {
        vec![
            cla(),
            0xA4,
            0x00,
            0x00,
            0x02,
            (fid >> 8) as u8,
            (fid & 0xFF) as u8,
        ]
    };
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

#[derive(Clone)]
struct Scp03Session {
    encryption_key: [u8; 16],
    mac_key: [u8; 16],
    mac_chaining_value: [u8; 16],
    encryption_counter: [u8; 16],
}

fn aes_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) -> Result<(), ()> {
    let cipher = Aes128::new_from_slice(key).map_err(|_| ())?;
    cipher.encrypt_block(block.into());
    Ok(())
}

fn shift_left_128(input: &[u8; 16]) -> [u8; 16] {
    let mut output = [0u8; 16];
    let mut carry = 0u8;
    for index in (0..16).rev() {
        output[index] = (input[index] << 1) | carry;
        carry = input[index] >> 7;
    }
    output
}

fn aes_cmac(key: &[u8; 16], data: &[u8]) -> Result<[u8; 16], ()> {
    let mut zero = [0u8; 16];
    aes_encrypt_block(key, &mut zero)?;
    let mut subkey1 = shift_left_128(&zero);
    if zero[0] & 0x80 != 0 {
        subkey1[15] ^= 0x87;
    }
    let mut subkey2 = shift_left_128(&subkey1);
    if subkey1[0] & 0x80 != 0 {
        subkey2[15] ^= 0x87;
    }

    let block_count = if data.is_empty() {
        1
    } else {
        data.len().div_ceil(16)
    };
    let complete_last_block = !data.is_empty() && data.len() % 16 == 0;
    let mut last = [0u8; 16];
    if complete_last_block {
        last.copy_from_slice(&data[(block_count - 1) * 16..block_count * 16]);
        for index in 0..16 {
            last[index] ^= subkey1[index];
        }
    } else {
        let start = (block_count - 1) * 16;
        let remainder = data.len().saturating_sub(start);
        last[..remainder].copy_from_slice(&data[start..]);
        last[remainder] = 0x80;
        for index in 0..16 {
            last[index] ^= subkey2[index];
        }
    }

    let mut state = [0u8; 16];
    for block_index in 0..block_count - 1 {
        let block = &data[block_index * 16..(block_index + 1) * 16];
        for index in 0..16 {
            state[index] ^= block[index];
        }
        aes_encrypt_block(key, &mut state)?;
    }
    for index in 0..16 {
        state[index] ^= last[index];
    }
    aes_encrypt_block(key, &mut state)?;
    Ok(state)
}

fn aes_cbc_encrypt_iso7816(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, ()> {
    let padded_length = (data.len() + 1).div_ceil(16) * 16;
    let mut output = vec![0u8; padded_length];
    output[..data.len()].copy_from_slice(data);
    output[data.len()] = 0x80;
    let mut previous = *iv;
    for chunk in output.chunks_exact_mut(16) {
        for index in 0..16 {
            chunk[index] ^= previous[index];
        }
        let block: &mut [u8; 16] = chunk.try_into().map_err(|_| ())?;
        aes_encrypt_block(key, block)?;
        previous.copy_from_slice(block);
    }
    Ok(output)
}

fn select_aid(pcsc: &mut PcscConn, aid: &[u8], p2: u8, le: bool) -> Result<(), ()> {
    if aid.is_empty() || aid.len() > u8::MAX as usize {
        return Err(());
    }
    let mut command = vec![0x00, 0xA4, 0x04, p2, aid.len() as u8];
    command.extend_from_slice(aid);
    if le {
        command.push(0x00);
    }
    let mut response = Vec::new();
    if pcsc.transmit(&command, &mut response).map_err(|_| ())? == 0x9000 {
        Ok(())
    } else {
        Err(())
    }
}

fn gp_get_data(pcsc: &mut PcscConn, tag: u8) -> Result<Vec<u8>, ()> {
    let command = [0x80, 0xCA, 0x00, tag, 0x00];
    let mut response = Vec::new();
    if pcsc.transmit(&command, &mut response).map_err(|_| ())? == 0x9000 {
        Ok(response)
    } else {
        Err(())
    }
}

fn diversify_gppki_keys(diversification_data: &[u8; 10]) -> Result<[[u8; 16]; 3], ()> {
    let mut keys = [[0u8; 16]; 3];
    for (index, purpose) in [0x04u8, 0x06, 0x0C].iter().copied().enumerate() {
        let mut derivation = [0u8; 32];
        derivation[11] = purpose;
        derivation[14] = 0x80;
        derivation[15] = 0x01;
        derivation[16] = index as u8 + 1;
        derivation[17..27].copy_from_slice(diversification_data);
        derivation[27..32].copy_from_slice(&GP_MANAGEMENT_AID[10..]);
        keys[index] = aes_cmac(GPPKI_V1_ROOT_KEY, &derivation)?;
    }
    Ok(keys)
}

fn scp03_derive(
    purpose: u8,
    output_bits: u8,
    key: &[u8; 16],
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> Result<[u8; 16], ()> {
    let mut derivation = [0u8; 32];
    derivation[11] = purpose;
    derivation[14] = output_bits;
    derivation[15] = 0x01;
    derivation[16..24].copy_from_slice(host_challenge);
    derivation[24..32].copy_from_slice(card_challenge);
    aes_cmac(key, &derivation)
}

fn gppki_static_keys(pcsc: &mut PcscConn) -> Result<(u8, [[u8; 16]; 3]), ()> {
    select_aid(pcsc, GP_MANAGEMENT_AID, 0x00, false)?;
    let key_information = gp_get_data(pcsc, 0xE0)?;
    let key_template = key_information
        .windows(6)
        .find(|window| window[0] == 0xC0 && window[1] == 0x04)
        .ok_or(())?;
    let key_version = key_template[3];
    if key_template[4] != 0x88 || key_template[5] != 0x10 {
        return Err(());
    }

    select_aid(pcsc, GP_ISD_AID, 0x00, false)?;
    let card_data = gp_get_data(pcsc, 0x45)?;
    if card_data.len() != 12 || card_data[0] != 0x45 || card_data[1] != 0x0A {
        return Err(());
    }
    let diversification_data: &[u8; 10] = card_data[2..12].try_into().map_err(|_| ())?;
    Ok((key_version, diversify_gppki_keys(diversification_data)?))
}

fn open_gppki_secure_channel(pcsc: &mut PcscConn) -> Result<Scp03Session, ()> {
    let (key_version, static_keys) = gppki_static_keys(pcsc)?;
    select_aid(pcsc, GPPKI_ID_V1_AID, 0x0C, true)?;

    let mut host_challenge = [0u8; 8];
    getrandom::fill(&mut host_challenge).map_err(|_| ())?;
    let mut initialize = vec![0x80, 0x50, key_version, 0x00, 0x08];
    initialize.extend_from_slice(&host_challenge);
    initialize.push(0x00);
    let mut response = Vec::new();
    if pcsc.transmit(&initialize, &mut response).map_err(|_| ())? != 0x9000
        || response.len() != 29
        || response[10] != key_version
        || response[11] != 0x03
    {
        return Err(());
    }
    let card_challenge: &[u8; 8] = response[13..21].try_into().map_err(|_| ())?;
    let session_encryption =
        scp03_derive(0x04, 0x80, &static_keys[0], &host_challenge, card_challenge)?;
    let session_mac = scp03_derive(0x06, 0x80, &static_keys[1], &host_challenge, card_challenge)?;
    let card_cryptogram = scp03_derive(0x00, 0x40, &session_mac, &host_challenge, card_challenge)?;
    if card_cryptogram[..8] != response[21..29] {
        return Err(());
    }
    let host_cryptogram = scp03_derive(0x01, 0x40, &session_mac, &host_challenge, card_challenge)?;

    let mut external_authenticate = vec![0x84, 0x82, 0x03, 0x00, 0x10];
    external_authenticate.extend_from_slice(&host_cryptogram[..8]);
    let mut mac_input = vec![0u8; 16];
    mac_input.extend_from_slice(&external_authenticate);
    let mac_chaining_value = aes_cmac(&session_mac, &mac_input)?;
    external_authenticate.extend_from_slice(&mac_chaining_value[..8]);
    response.clear();
    if pcsc
        .transmit(&external_authenticate, &mut response)
        .map_err(|_| ())?
        != 0x9000
    {
        return Err(());
    }

    let mut encryption_counter = [0u8; 16];
    encryption_counter[15] = 1;
    Ok(Scp03Session {
        encryption_key: session_encryption,
        mac_key: session_mac,
        mac_chaining_value,
        encryption_counter,
    })
}

fn wrap_gppki_verify(session: &mut Scp03Session, pin_ref: u8, pin: &[u8]) -> Result<Vec<u8>, ()> {
    if pin.is_empty() || pin.len() > PIN_MAX {
        return Err(());
    }
    let mut pin_field = [0xFFu8; PIN_MAX];
    pin_field[..pin.len()].copy_from_slice(pin);
    let mut encryption_iv = session.encryption_counter;
    aes_encrypt_block(&session.encryption_key, &mut encryption_iv)?;
    let encrypted = aes_cbc_encrypt_iso7816(&session.encryption_key, &encryption_iv, &pin_field)?;
    let wrapped_length = encrypted.len().checked_add(8).ok_or(())?;
    if wrapped_length > u8::MAX as usize {
        return Err(());
    }
    let mut command = vec![0x04, 0x20, 0x00, pin_ref, wrapped_length as u8];
    command.extend_from_slice(&encrypted);
    let mut mac_input = session.mac_chaining_value.to_vec();
    mac_input.extend_from_slice(&command);
    session.mac_chaining_value = aes_cmac(&session.mac_key, &mac_input)?;
    command.extend_from_slice(&session.mac_chaining_value[..8]);
    Ok(command)
}

fn verify_gppki_pin(pcsc: &mut PcscConn, pin: &[u8]) -> PinResult {
    if !(6..=8).contains(&pin.len()) {
        return PinResult::Error;
    }
    let mut session = match open_gppki_secure_channel(pcsc) {
        Ok(session) => session,
        Err(_) => return PinResult::Error,
    };
    let command = match wrap_gppki_verify(&mut session, GPPKI_USER_PIN_REF, pin) {
        Ok(command) => command,
        Err(_) => return PinResult::Error,
    };
    let mut response = Vec::new();
    let sw = match pcsc.transmit(&command, &mut response) {
        Ok(sw) => sw,
        Err(_) => return PinResult::Error,
    };
    if std::env::var_os("OPENHICOS_DEBUG").is_some() {
        eprintln!("openhicos: GPKI VERIFY status={sw:04X}, pin_ref=01");
    }
    match sw {
        0x9000 => PinResult::Ok,
        0x6983 => PinResult::Locked,
        sw if sw & 0xFFF0 == 0x63C0 => PinResult::Incorrect,
        _ => PinResult::Error,
    }
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
    if card_profile() == CardProfile::GpPkiIdV1 {
        return verify_gppki_pin(pcsc, pin);
    }
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
    fn aes_cmac_matches_nist_vectors() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        assert_eq!(
            aes_cmac(&key, &[]).unwrap(),
            [
                0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28, 0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75,
                0x67, 0x46,
            ]
        );
        assert_eq!(
            aes_cmac(
                &key,
                &[
                    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73,
                    0x93, 0x17, 0x2A,
                ],
            )
            .unwrap(),
            [
                0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44, 0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A,
                0x28, 0x7C,
            ]
        );
    }

    #[test]
    fn gppki_scp03_matches_synthetic_regression_vector() {
        let diversification_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let keys = diversify_gppki_keys(&diversification_data).unwrap();
        assert_eq!(
            keys[0],
            [
                0xE7, 0x45, 0x71, 0xCB, 0x8A, 0xDB, 0xD4, 0x6A, 0x9C, 0x28, 0x7E, 0x19, 0x4B, 0xEE,
                0xE3, 0x45,
            ]
        );
        assert_eq!(
            keys[1],
            [
                0x95, 0x15, 0x40, 0x55, 0x15, 0x43, 0x04, 0x81, 0x22, 0xE4, 0x4A, 0x61, 0x23, 0x77,
                0x03, 0x82,
            ]
        );
        assert_eq!(
            keys[2],
            [
                0xFE, 0x58, 0x23, 0x03, 0x6F, 0x2B, 0xC2, 0x36, 0x08, 0x9A, 0x15, 0x86, 0x98, 0xF9,
                0x6F, 0xBF,
            ]
        );

        let host = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let card = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27];
        let session_encryption = scp03_derive(0x04, 0x80, &keys[0], &host, &card).unwrap();
        let session_mac = scp03_derive(0x06, 0x80, &keys[1], &host, &card).unwrap();
        assert_eq!(
            session_encryption,
            [
                0x46, 0x77, 0xA0, 0x96, 0xBD, 0x26, 0xA9, 0x7A, 0xB1, 0x8A, 0xF8, 0x2D, 0xB2, 0x81,
                0x5C, 0x9A,
            ]
        );
        assert_eq!(
            session_mac,
            [
                0x95, 0xA1, 0x10, 0x33, 0x70, 0x93, 0xB9, 0x97, 0x6B, 0x21, 0x77, 0xE9, 0x0D, 0x9E,
                0xFA, 0x3E,
            ]
        );
        let card_cryptogram = scp03_derive(0x00, 0x40, &session_mac, &host, &card).unwrap();
        let host_cryptogram = scp03_derive(0x01, 0x40, &session_mac, &host, &card).unwrap();
        assert_eq!(
            &card_cryptogram[..8],
            &[0xEA, 0x24, 0x0C, 0x98, 0xD4, 0xB4, 0xC8, 0xB7]
        );
        assert_eq!(
            &host_cryptogram[..8],
            &[0xBF, 0x6D, 0x8B, 0x63, 0xA4, 0x57, 0x8B, 0xC8]
        );

        let mut external_mac_input = vec![0u8; 16];
        external_mac_input.extend_from_slice(&[0x84, 0x82, 0x03, 0x00, 0x10]);
        external_mac_input.extend_from_slice(&host_cryptogram[..8]);
        let external_mac = aes_cmac(&session_mac, &external_mac_input).unwrap();
        assert_eq!(
            &external_mac[..8],
            &[0xB5, 0x62, 0x33, 0x57, 0x31, 0xE2, 0x58, 0x53]
        );

        let mut counter = [0u8; 16];
        counter[15] = 1;
        let mut session = Scp03Session {
            encryption_key: session_encryption,
            mac_key: session_mac,
            mac_chaining_value: external_mac,
            encryption_counter: counter,
        };
        let wrapped = wrap_gppki_verify(&mut session, 1, b"123456").unwrap();
        assert_eq!(
            wrapped,
            [
                0x04, 0x20, 0x00, 0x01, 0x18, 0x43, 0x29, 0x27, 0x2E, 0x26, 0x50, 0x7A, 0x3A, 0xB2,
                0xB3, 0x24, 0x63, 0xBD, 0x97, 0x23, 0xA3, 0xEC, 0x4A, 0x43, 0xFB, 0xD5, 0xD8, 0x9C,
                0x7B,
            ]
        );
    }

    #[test]
    #[ignore = "requires a connected GPKI ID v1 smart card"]
    fn live_gppki_secure_channel_opens_without_verifying_pin() {
        let mut pcsc = PcscConn::new().unwrap();
        let reader = pcsc.list_readers().unwrap().into_iter().next().unwrap();
        pcsc.connect(&reader).unwrap();
        reset_cla();
        select_mf(&mut pcsc).unwrap();
        assert_eq!(card_profile(), CardProfile::GpPkiIdV1);
        open_gppki_secure_channel(&mut pcsc).unwrap();
    }

    #[test]
    fn pkcs1_signature_block_has_expected_layout() {
        let block = pkcs1_v15_signature_block(b"abc").unwrap();
        assert_eq!(&block[..2], &[0x00, 0x01]);
        assert!(block[2..252].iter().all(|b| *b == 0xFF));
        assert_eq!(&block[252..], &[0x00, b'a', b'b', b'c']);
    }
}

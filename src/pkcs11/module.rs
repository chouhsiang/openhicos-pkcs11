//! PKCS#11 Cryptoki implementation.

use crate::apdu::{self, PinResult};
use crate::p15::{self, ObjClass, Token, MAX_OBJS};
use crate::pcsc::PcscConn;
use crate::pkcs11::types::*;
use num_bigint::BigUint;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::sync::Mutex;

const MAX_SLOTS: usize = 8;
const MAX_SESSIONS: usize = 16;
const PIN_MAX: u64 = 10;
const RSA_MODULUS_LEN: usize = 256;

enum DigestCtx {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

struct Session {
    in_use: bool,
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    state: CK_STATE,
    logged_in: bool,
    find_active: bool,
    find_handles: Vec<CK_OBJECT_HANDLE>,
    find_pos: usize,
    sign_active: bool,
    sign_key: CK_OBJECT_HANDLE,
    sign_mech: CK_MECHANISM_TYPE,
    sign_buf: Vec<u8>,
    decrypt_active: bool,
    decrypt_key: CK_OBJECT_HANDLE,
    decrypt_mech: CK_MECHANISM_TYPE,
    decrypt_buf: Vec<u8>,
    decrypt_plain: Option<Vec<u8>>,
    decrypt_oaep_hash: CK_MECHANISM_TYPE,
    decrypt_oaep_label: Vec<u8>,
    verify_active: bool,
    verify_key: CK_OBJECT_HANDLE,
    verify_mech: CK_MECHANISM_TYPE,
    verify_buf: Vec<u8>,
    digest_active: bool,
    digest_ctx: Option<DigestCtx>,
    encrypt_active: bool,
    encrypt_key: CK_OBJECT_HANDLE,
    encrypt_mech: CK_MECHANISM_TYPE,
    encrypt_buf: Vec<u8>,
    encrypt_cipher: Option<Vec<u8>>,
    encrypt_oaep_hash: CK_MECHANISM_TYPE,
    encrypt_oaep_label: Vec<u8>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            in_use: false,
            slot: 0,
            flags: 0,
            state: CKS_RO_PUBLIC_SESSION,
            logged_in: false,
            find_active: false,
            find_handles: Vec::new(),
            find_pos: 0,
            sign_active: false,
            sign_key: 0,
            sign_mech: 0,
            sign_buf: Vec::new(),
            decrypt_active: false,
            decrypt_key: 0,
            decrypt_mech: 0,
            decrypt_buf: Vec::new(),
            decrypt_plain: None,
            decrypt_oaep_hash: CKM_SHA256,
            decrypt_oaep_label: Vec::new(),
            verify_active: false,
            verify_key: 0,
            verify_mech: 0,
            verify_buf: Vec::new(),
            digest_active: false,
            digest_ctx: None,
            encrypt_active: false,
            encrypt_key: 0,
            encrypt_mech: 0,
            encrypt_buf: Vec::new(),
            encrypt_cipher: None,
            encrypt_oaep_hash: CKM_SHA256,
            encrypt_oaep_label: Vec::new(),
        }
    }
}

struct Slot {
    present: bool,
    logged_in: bool,
    reader: String,
    pcsc: PcscConn,
    token: Token,
}

struct State {
    initialized: bool,
    slots: Vec<Slot>,
    sessions: [Session; MAX_SESSIONS],
}

impl State {
    fn new() -> Self {
        Self {
            initialized: false,
            slots: Vec::new(),
            sessions: std::array::from_fn(|_| Session::default()),
        }
    }
}

static GLOBAL: Mutex<Option<State>> = Mutex::new(None);

fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    let mut guard = GLOBAL.lock().unwrap();
    if guard.is_none() {
        *guard = Some(State::new());
    }
    f(guard.as_mut().unwrap())
}

fn session_get(state: &State, h: CK_SESSION_HANDLE) -> Option<&Session> {
    if h == 0 || h as usize > MAX_SESSIONS {
        return None;
    }
    let s = &state.sessions[h as usize - 1];
    if s.in_use {
        Some(s)
    } else {
        None
    }
}

fn session_get_mut(state: &mut State, h: CK_SESSION_HANDLE) -> Option<&mut Session> {
    if h == 0 || h as usize > MAX_SESSIONS {
        return None;
    }
    let s = &mut state.sessions[h as usize - 1];
    if s.in_use {
        Some(s)
    } else {
        None
    }
}

fn session_state(flags: CK_FLAGS, logged_in: bool) -> CK_STATE {
    match (flags & CKF_RW_SESSION != 0, logged_in) {
        (true, true) => CKS_RW_USER_FUNCTIONS,
        (true, false) => CKS_RW_PUBLIC_SESSION,
        (false, true) => CKS_RO_USER_FUNCTIONS,
        (false, false) => CKS_RO_PUBLIC_SESSION,
    }
}

fn set_slot_sessions_login_state(sessions: &mut [Session], slot_id: CK_SLOT_ID, logged_in: bool) {
    for session in sessions {
        if session.in_use && session.slot == slot_id {
            session.logged_in = logged_in;
            session.state = session_state(session.flags, logged_in);
        }
    }
}

fn ensure_card(state: &mut State, slot_id: CK_SLOT_ID) -> CK_RV {
    if slot_id as usize >= state.slots.len() {
        return CKR_SLOT_ID_INVALID;
    }
    let slot = &mut state.slots[slot_id as usize];
    if !slot.present {
        return CKR_TOKEN_NOT_PRESENT;
    }
    if !slot.pcsc.is_connected() {
        apdu::reset_cla();
        if slot.pcsc.connect(&slot.reader).is_err() {
            return CKR_DEVICE_ERROR;
        }
        let _ = p15::bind(&mut slot.pcsc, &mut slot.token);
    } else if !slot.token.bound {
        let _ = p15::bind(&mut slot.pcsc, &mut slot.token);
    }
    CKR_OK
}

fn object_class(o: &p15::TokenObject) -> CK_ULONG {
    match o.cls {
        ObjClass::PrivKey => CKO_PRIVATE_KEY,
        ObjClass::PubKey => CKO_PUBLIC_KEY,
        ObjClass::Cert => CKO_CERTIFICATE,
        ObjClass::Data => CKO_DATA,
    }
}

fn attr_match(o: &p15::TokenObject, tmpl: &[CK_ATTRIBUTE]) -> bool {
    for t in tmpl {
        unsafe {
            match t.type_ {
                CKA_CLASS if !t.pValue.is_null() && t.ulValueLen == 8 => {
                    if *(t.pValue as *const CK_ULONG) != object_class(o) {
                        return false;
                    }
                }
                CKA_ID if !t.pValue.is_null() => {
                    let slice =
                        std::slice::from_raw_parts(t.pValue as *const u8, t.ulValueLen as usize);
                    if slice.len() != o.id.len() || slice != o.id.as_slice() {
                        return false;
                    }
                }
                CKA_LABEL if !t.pValue.is_null() => {
                    let slice =
                        std::slice::from_raw_parts(t.pValue as *const u8, t.ulValueLen as usize);
                    if slice.len() != o.label.len() || slice != o.label.as_bytes() {
                        return false;
                    }
                }
                CKA_VALUE if !t.pValue.is_null() => {
                    let slice =
                        std::slice::from_raw_parts(t.pValue as *const u8, t.ulValueLen as usize);
                    if slice.len() != o.data.len() || slice != o.data.as_slice() {
                        return false;
                    }
                }
                CKA_SIGN if !t.pValue.is_null() && t.ulValueLen == 1 => {
                    if *(t.pValue as *const CK_BBOOL) != CK_FALSE && !o.can_sign {
                        return false;
                    }
                }
                CKA_DECRYPT if !t.pValue.is_null() && t.ulValueLen == 1 => {
                    if *(t.pValue as *const CK_BBOOL) != CK_FALSE && !o.can_decrypt {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }
    true
}

unsafe fn set_attr(attr: &mut CK_ATTRIBUTE, data: &[u8]) -> CK_RV {
    if attr.pValue.is_null() {
        attr.ulValueLen = data.len() as CK_ULONG;
        return CKR_OK;
    }
    if attr.ulValueLen < data.len() as CK_ULONG {
        attr.ulValueLen = data.len() as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), attr.pValue as *mut u8, data.len());
    attr.ulValueLen = data.len() as CK_ULONG;
    CKR_OK
}

fn build_digestinfo_md5(hash: &[u8; 16]) -> [u8; 34] {
    let prefix: [u8; 18] = [
        0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05,
        0x00, 0x04, 0x10,
    ];
    let mut out = [0u8; 34];
    out[..18].copy_from_slice(&prefix);
    out[18..].copy_from_slice(hash);
    out
}

fn build_digestinfo_sha1(hash: &[u8; 20]) -> [u8; 35] {
    let prefix: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    let mut out = [0u8; 35];
    out[..15].copy_from_slice(&prefix);
    out[15..].copy_from_slice(hash);
    out
}

fn build_digestinfo_sha256(hash: &[u8; 32]) -> [u8; 51] {
    let prefix: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let mut out = [0u8; 51];
    out[..19].copy_from_slice(&prefix);
    out[19..].copy_from_slice(hash);
    out
}

fn build_digestinfo_sha384(hash: &[u8; 48]) -> [u8; 67] {
    let prefix: [u8; 19] = [
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    let mut out = [0u8; 67];
    out[..19].copy_from_slice(&prefix);
    out[19..].copy_from_slice(hash);
    out
}

fn build_digestinfo_sha512(hash: &[u8; 64]) -> [u8; 83] {
    let prefix: [u8; 19] = [
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];
    let mut out = [0u8; 83];
    out[..19].copy_from_slice(&prefix);
    out[19..].copy_from_slice(hash);
    out
}

fn digest_info_for_hash_mech(mech: CK_MECHANISM_TYPE, data: &[u8]) -> Result<Vec<u8>, CK_RV> {
    Ok(match mech {
        CKM_MD5_RSA_PKCS => {
            let hash = Md5::digest(data);
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&hash);
            build_digestinfo_md5(&arr).to_vec()
        }
        CKM_SHA1_RSA_PKCS => {
            let hash = Sha1::digest(data);
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&hash);
            build_digestinfo_sha1(&arr).to_vec()
        }
        CKM_SHA256_RSA_PKCS => {
            let hash = Sha256::digest(data);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            build_digestinfo_sha256(&arr).to_vec()
        }
        CKM_SHA384_RSA_PKCS => {
            let hash = Sha384::digest(data);
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&hash);
            build_digestinfo_sha384(&arr).to_vec()
        }
        CKM_SHA512_RSA_PKCS => {
            let hash = Sha512::digest(data);
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&hash);
            build_digestinfo_sha512(&arr).to_vec()
        }
        _ => return Err(CKR_MECHANISM_INVALID),
    })
}

fn is_hash_rsa_pkcs(mech: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mech,
        CKM_MD5_RSA_PKCS
            | CKM_SHA1_RSA_PKCS
            | CKM_SHA256_RSA_PKCS
            | CKM_SHA384_RSA_PKCS
            | CKM_SHA512_RSA_PKCS
    )
}

fn hash_oaep(hash_alg: CK_MECHANISM_TYPE, data: &[u8]) -> Result<Vec<u8>, CK_RV> {
    Ok(match hash_alg {
        CKM_SHA_1 => Sha1::digest(data).to_vec(),
        CKM_SHA256 => Sha256::digest(data).to_vec(),
        CKM_SHA384 => Sha384::digest(data).to_vec(),
        CKM_SHA512 => Sha512::digest(data).to_vec(),
        _ => return Err(CKR_MECHANISM_INVALID),
    })
}

fn mgf1(hash_alg: CK_MECHANISM_TYPE, seed: &[u8], length: usize) -> Result<Vec<u8>, CK_RV> {
    let mut out = Vec::with_capacity(length);
    let mut counter = 0u32;
    while out.len() < length {
        let mut block = Vec::with_capacity(seed.len() + 4);
        block.extend_from_slice(seed);
        block.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&hash_oaep(hash_alg, &block)?);
        counter = counter.checked_add(1).ok_or(CKR_FUNCTION_FAILED)?;
    }
    out.truncate(length);
    Ok(out)
}

fn oaep_encode(
    hash_alg: CK_MECHANISM_TYPE,
    label: &[u8],
    modulus_len: usize,
    message: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let h_len = hash_oaep(hash_alg, b"")?.len();
    if message.len() + 2 * h_len + 2 > modulus_len {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let lhash = hash_oaep(hash_alg, label)?;
    let ps_len = modulus_len - message.len() - 2 * h_len - 2;
    let mut db = Vec::with_capacity(modulus_len - h_len - 1);
    db.extend_from_slice(&lhash);
    db.extend(std::iter::repeat_n(0u8, ps_len));
    db.push(0x01);
    db.extend_from_slice(message);
    let mut seed = vec![0u8; h_len];
    getrandom::fill(&mut seed).map_err(|_| CKR_DEVICE_ERROR)?;
    let db_mask = mgf1(hash_alg, &seed, db.len())?;
    let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    let seed_mask = mgf1(hash_alg, &masked_db, h_len)?;
    let masked_seed: Vec<u8> = seed
        .iter()
        .zip(seed_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let mut em = Vec::with_capacity(modulus_len);
    em.push(0x00);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);
    Ok(em)
}

fn oaep_decode(
    hash_alg: CK_MECHANISM_TYPE,
    label: &[u8],
    em: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let h_len = hash_oaep(hash_alg, b"")?.len();
    if em.len() < 2 * h_len + 2 || em[0] != 0x00 {
        return Err(CKR_ENCRYPTED_DATA_INVALID);
    }
    let masked_seed = &em[1..1 + h_len];
    let masked_db = &em[1 + h_len..];
    let seed_mask = mgf1(hash_alg, masked_db, h_len)?;
    let seed: Vec<u8> = masked_seed
        .iter()
        .zip(seed_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let db_mask = mgf1(hash_alg, &seed, masked_db.len())?;
    let db: Vec<u8> = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let lhash = hash_oaep(hash_alg, label)?;
    if db.len() < h_len || db[..h_len] != lhash[..] {
        return Err(CKR_ENCRYPTED_DATA_INVALID);
    }
    let mut i = h_len;
    while i < db.len() && db[i] == 0 {
        i += 1;
    }
    if i >= db.len() || db[i] != 0x01 {
        return Err(CKR_ENCRYPTED_DATA_INVALID);
    }
    Ok(db[i + 1..].to_vec())
}

fn parse_oaep_params(mech: &CK_MECHANISM) -> Result<(CK_MECHANISM_TYPE, Vec<u8>), CK_RV> {
    if mech.pParameter.is_null() || mech.ulParameterLen == 0 {
        return Ok((CKM_SHA256, Vec::new()));
    }
    if mech.ulParameterLen as usize != std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let params = unsafe { &*(mech.pParameter as *const CK_RSA_PKCS_OAEP_PARAMS) };
    let expected_mgf = match params.hashAlg {
        CKM_SHA_1 => CKG_MGF1_SHA1,
        CKM_SHA256 => CKG_MGF1_SHA256,
        CKM_SHA384 => CKG_MGF1_SHA384,
        CKM_SHA512 => CKG_MGF1_SHA512,
        _ => return Err(CKR_MECHANISM_INVALID),
    };
    if params.mgf != expected_mgf {
        return Err(CKR_MECHANISM_INVALID);
    }
    let label = if params.source == CKZ_DATA_SPECIFIED
        && params.ulSourceDataLen > 0
        && !params.pSourceData.is_null()
    {
        unsafe {
            std::slice::from_raw_parts(
                params.pSourceData as *const u8,
                params.ulSourceDataLen as usize,
            )
        }
        .to_vec()
    } else {
        Vec::new()
    };
    Ok((params.hashAlg, label))
}

macro_rules! not_supported {
    () => {
        CKR_FUNCTION_NOT_SUPPORTED
    };
}

pub unsafe extern "C" fn c_initialize(_p: *mut core::ffi::c_void) -> CK_RV {
    with_state(|state| {
        if state.initialized {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        let probe = match PcscConn::new() {
            Ok(p) => p,
            Err(_) => return CKR_DEVICE_ERROR,
        };
        let readers = probe.list_readers().unwrap_or_default();
        state.slots.clear();
        for reader in readers.into_iter().take(MAX_SLOTS) {
            let pcsc = PcscConn::new().unwrap_or_else(|_| PcscConn::new().expect("PC/SC"));
            state.slots.push(Slot {
                present: true,
                logged_in: false,
                reader,
                pcsc,
                token: Token::default(),
            });
        }
        state.initialized = true;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_finalize(_p: *mut core::ffi::c_void) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        for s in &mut state.sessions {
            s.in_use = false;
        }
        state.slots.clear();
        state.initialized = false;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_info(p_info: *mut CK_INFO) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let info = &mut *p_info;
        info.cryptokiVersion = CK_VERSION {
            major: 2,
            minor: 40,
        };
        fill_blank(&mut info.manufacturerID, "openhicos");
        fill_blank(&mut info.libraryDescription, "openhicos PKCS#11");
        info.libraryVersion = CK_VERSION { major: 0, minor: 2 };
        info.flags = 0;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_slot_list(
    token_present: CK_BBOOL,
    p_slot_list: *mut CK_SLOT_ID,
    pul_count: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut n = 0u64;
        for (i, slot) in state.slots.iter().enumerate() {
            if token_present != CK_FALSE && !slot.present {
                continue;
            }
            if !p_slot_list.is_null() {
                if n >= *pul_count {
                    return CKR_BUFFER_TOO_SMALL;
                }
                *p_slot_list.add(n as usize) = i as CK_SLOT_ID;
            }
            n += 1;
        }
        *pul_count = n;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_slot_info(slot_id: CK_SLOT_ID, p_info: *mut CK_SLOT_INFO) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if slot_id as usize >= state.slots.len() || p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let slot = &state.slots[slot_id as usize];
        let info = &mut *p_info;
        fill_blank(&mut info.slotDescription, &slot.reader);
        fill_blank(&mut info.manufacturerID, "PC/SC");
        info.flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;
        if slot.present {
            info.flags |= CKF_TOKEN_PRESENT;
        }
        info.hardwareVersion = CK_VERSION { major: 0, minor: 0 };
        info.firmwareVersion = CK_VERSION { major: 0, minor: 0 };
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_token_info(
    slot_id: CK_SLOT_ID,
    p_info: *mut CK_TOKEN_INFO,
) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if slot_id as usize >= state.slots.len() || p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if !state.slots[slot_id as usize].present {
            return CKR_TOKEN_NOT_PRESENT;
        }
        let rv = ensure_card(state, slot_id);
        if rv != CKR_OK {
            return rv;
        }
        let slot = &state.slots[slot_id as usize];
        let info = &mut *p_info;
        fill_blank(&mut info.label, &slot.token.label);
        fill_blank(&mut info.manufacturerID, &slot.token.manufacturer);
        fill_blank(&mut info.model, &slot.token.model);
        fill_blank(&mut info.serialNumber, &slot.token.serial);
        info.flags =
            CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
        info.ulMaxPinLen = if slot.token.max_pin != 0 {
            slot.token.max_pin
        } else {
            PIN_MAX
        };
        info.ulMinPinLen = if slot.token.min_pin != 0 {
            slot.token.min_pin
        } else {
            6
        };
        info.ulMaxSessionCount = MAX_SESSIONS as CK_ULONG;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = MAX_SESSIONS as CK_ULONG;
        info.ulRwSessionCount = 0;
        info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
        info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
        info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
        info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
        info.hardwareVersion = CK_VERSION { major: 1, minor: 0 };
        info.firmwareVersion = CK_VERSION { major: 1, minor: 0 };
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_mechanism_list(
    _slot: CK_SLOT_ID,
    p_list: *mut CK_MECHANISM_TYPE,
    pul_count: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mechs = [
            CKM_RSA_PKCS,
            CKM_RSA_X_509,
            CKM_RSA_PKCS_OAEP,
            CKM_MD5_RSA_PKCS,
            CKM_SHA1_RSA_PKCS,
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
            CKM_MD5,
            CKM_SHA_1,
            CKM_SHA256,
            CKM_SHA384,
            CKM_SHA512,
        ];
        if !p_list.is_null() {
            if (*pul_count as usize) < mechs.len() {
                return CKR_BUFFER_TOO_SMALL;
            }
            for (i, &m) in mechs.iter().enumerate() {
                unsafe {
                    *p_list.add(i) = m;
                }
            }
        }
        unsafe {
            *pul_count = mechs.len() as CK_ULONG;
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    p_info: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if slot_id as usize >= state.slots.len() {
            return CKR_SLOT_ID_INVALID;
        }
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let (min_key, max_key, flags) = match mechanism {
            CKM_RSA_PKCS | CKM_RSA_X_509 => (
                2048,
                2048,
                CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY,
            ),
            CKM_RSA_PKCS_OAEP => (1024, 2048, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT),
            CKM_MD5_RSA_PKCS
            | CKM_SHA1_RSA_PKCS
            | CKM_SHA256_RSA_PKCS
            | CKM_SHA384_RSA_PKCS
            | CKM_SHA512_RSA_PKCS => (2048, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY),
            CKM_MD5 | CKM_SHA_1 | CKM_SHA256 | CKM_SHA384 | CKM_SHA512 => (0, 0, CKF_DIGEST),
            _ => return CKR_MECHANISM_INVALID,
        };
        unsafe {
            *p_info = CK_MECHANISM_INFO {
                ulMinKeySize: min_key,
                ulMaxKeySize: max_key,
                flags,
            };
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn c_init_token(
    _s: CK_SLOT_ID,
    _a: *mut CK_UTF8CHAR,
    _b: CK_ULONG,
    _c: *mut CK_UTF8CHAR,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_init_pin(
    _h: CK_SESSION_HANDLE,
    _p: *mut CK_UTF8CHAR,
    _n: CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_set_pin(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_UTF8CHAR,
    _b: CK_ULONG,
    _c: *mut CK_UTF8CHAR,
    _d: CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _app: *mut core::ffi::c_void,
    _notify: Option<unsafe extern "C" fn(CK_ULONG, CK_ULONG, *mut core::ffi::c_void)>,
    ph_session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if ph_session.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if flags & CKF_SERIAL_SESSION == 0 {
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        }
        let rv = ensure_card(state, slot_id);
        if rv != CKR_OK {
            return rv;
        }
        let logged_in = state.slots[slot_id as usize].logged_in;
        for (i, s) in state.sessions.iter_mut().enumerate() {
            if !s.in_use {
                *s = Session {
                    in_use: true,
                    slot: slot_id,
                    flags,
                    state: session_state(flags, logged_in),
                    logged_in,
                    ..Default::default()
                };
                *ph_session = (i + 1) as CK_SESSION_HANDLE;
                return CKR_OK;
            }
        }
        CKR_SESSION_COUNT
    })
}

pub unsafe extern "C" fn c_close_session(h: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        let Some(slot_id) = session_get(state, h).map(|s| s.slot) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        session_get_mut(state, h).unwrap().in_use = false;
        let remaining = state
            .sessions
            .iter()
            .filter(|s| s.in_use && s.slot == slot_id)
            .count();
        if remaining == 0 {
            state.slots[slot_id as usize].logged_in = false;
            apdu::clear_auth_state();
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        if slot_id as usize >= state.slots.len() {
            return CKR_SLOT_ID_INVALID;
        }
        for s in &mut state.sessions {
            if s.in_use && s.slot == slot_id {
                s.in_use = false;
            }
        }
        state.slots[slot_id as usize].logged_in = false;
        apdu::clear_auth_state();
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_session_info(
    h: CK_SESSION_HANDLE,
    p_info: *mut CK_SESSION_INFO,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if p_info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let info = &mut *p_info;
        info.slotID = sess.slot;
        info.state = sess.state;
        info.flags = sess.flags;
        info.ulDeviceError = 0;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_operation_state(
    _h: CK_SESSION_HANDLE,
    _p: *mut CK_BYTE,
    _n: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_set_operation_state(
    _h: CK_SESSION_HANDLE,
    _p: *mut CK_BYTE,
    _n: CK_ULONG,
    _a: CK_OBJECT_HANDLE,
    _b: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_login(
    h: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: *mut CK_UTF8CHAR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if user_type != CKU_USER {
            return CKR_USER_TYPE_INVALID;
        }
        let slot_id = sess.slot;
        if state.slots[slot_id as usize].logged_in {
            return CKR_USER_ALREADY_LOGGED_IN;
        }
        if p_pin.is_null() || ul_pin_len == 0 {
            return CKR_ARGUMENTS_BAD;
        }
        let pin = std::slice::from_raw_parts(p_pin, ul_pin_len as usize);
        let pin_ref = state.slots[slot_id as usize].token.pin_ref;
        let slot = &mut state.slots[slot_id as usize];
        match apdu::verify_pin(&mut slot.pcsc, pin_ref, pin) {
            PinResult::Ok => {}
            PinResult::Locked => return CKR_PIN_LOCKED,
            PinResult::Incorrect => return CKR_PIN_INCORRECT,
            PinResult::Error => return CKR_DEVICE_ERROR,
        }
        state.slots[slot_id as usize].logged_in = true;
        set_slot_sessions_login_state(&mut state.sessions, slot_id, true);
        CKR_OK
    })
}

pub unsafe extern "C" fn c_logout(h: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let slot_id = sess.slot;
        if !state.slots[slot_id as usize].logged_in {
            return CKR_USER_NOT_LOGGED_IN;
        }
        state.slots[slot_id as usize].logged_in = false;
        set_slot_sessions_login_state(&mut state.sessions, slot_id, false);
        apdu::clear_auth_state();
        CKR_OK
    })
}

pub unsafe extern "C" fn c_create_object(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_ATTRIBUTE,
    _n: CK_ULONG,
    _o: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_copy_object(
    _h: CK_SESSION_HANDLE,
    _o: CK_OBJECT_HANDLE,
    _a: *mut CK_ATTRIBUTE,
    _n: CK_ULONG,
    _p: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_destroy_object(_h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_get_object_size(
    _h: CK_SESSION_HANDLE,
    _o: CK_OBJECT_HANDLE,
    _n: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_get_attribute_value(
    h: CK_SESSION_HANDLE,
    h_object: CK_OBJECT_HANDLE,
    p_template: *mut CK_ATTRIBUTE,
    ul_count: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if p_template.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let slot = &state.slots[sess.slot as usize];
        let Some(obj) = p15::find(&slot.token, h_object) else {
            return CKR_OBJECT_HANDLE_INVALID;
        };
        let tmpl = std::slice::from_raw_parts_mut(p_template, ul_count as usize);
        let mut rv = CKR_OK;
        let btrue = CK_TRUE;
        let bfalse = CK_FALSE;
        let kt = CKK_RSA.to_le_bytes();
        let ct = CKC_X_509.to_le_bytes();
        let is_key = matches!(obj.cls, ObjClass::PrivKey | ObjClass::PubKey);
        let is_private_key = obj.cls == ObjClass::PrivKey;
        let bool_attr = |attr: &mut CK_ATTRIBUTE, value: bool| {
            set_attr(attr, &[if value { btrue } else { bfalse }])
        };
        for attr in tmpl {
            let r = match attr.type_ {
                CKA_CLASS => set_attr(attr, &object_class(obj).to_le_bytes()),
                CKA_TOKEN => bool_attr(attr, true),
                CKA_PRIVATE => bool_attr(attr, obj.private),
                CKA_MODIFIABLE => bool_attr(attr, obj.modifiable),
                CKA_LOCAL if !is_key => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_LOCAL => bool_attr(attr, obj.local),
                CKA_LABEL => set_attr(attr, obj.label.as_bytes()),
                CKA_ID => set_attr(attr, &obj.id),
                CKA_KEY_TYPE if !is_key => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_KEY_TYPE => set_attr(attr, &kt),
                CKA_CERTIFICATE_TYPE if obj.cls != ObjClass::Cert => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_CERTIFICATE_TYPE => set_attr(attr, &ct),
                CKA_SUBJECT if obj.subject.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_SUBJECT => set_attr(attr, &obj.subject),
                CKA_ISSUER if obj.issuer.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_ISSUER => set_attr(attr, &obj.issuer),
                CKA_SERIAL_NUMBER if obj.serial.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_SERIAL_NUMBER => set_attr(attr, &obj.serial),
                CKA_APPLICATION if obj.application.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_APPLICATION => set_attr(attr, obj.application.as_bytes()),
                CKA_OBJECT_ID if obj.app_oid.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_OBJECT_ID => set_attr(attr, &obj.app_oid),
                CKA_VALUE if obj.data.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_VALUE => set_attr(attr, &obj.data),
                CKA_MODULUS if obj.modulus.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_MODULUS => set_attr(attr, &obj.modulus),
                CKA_MODULUS_BITS if obj.modulus_bits == 0 || !is_key => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_MODULUS_BITS => set_attr(attr, &obj.modulus_bits.to_le_bytes()),
                CKA_PUBLIC_EXPONENT if obj.pubexp.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_PUBLIC_EXPONENT => set_attr(attr, &obj.pubexp),
                CKA_SIGN => bool_attr(attr, obj.can_sign),
                CKA_SIGN_RECOVER | CKA_VERIFY_RECOVER | CKA_DERIVE => bool_attr(attr, false),
                CKA_DECRYPT => bool_attr(attr, obj.can_decrypt),
                CKA_VERIFY => bool_attr(attr, obj.can_verify),
                CKA_ENCRYPT => bool_attr(attr, obj.can_encrypt),
                CKA_WRAP => bool_attr(attr, obj.can_wrap),
                CKA_UNWRAP => bool_attr(attr, obj.can_unwrap),
                CKA_SENSITIVE | CKA_ALWAYS_SENSITIVE | CKA_NEVER_EXTRACTABLE => {
                    bool_attr(attr, is_private_key)
                }
                CKA_EXTRACTABLE => bool_attr(attr, false),
                CKA_ALWAYS_AUTHENTICATE => bool_attr(attr, false),
                _ => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
            };
            if r == CKR_BUFFER_TOO_SMALL {
                rv = CKR_BUFFER_TOO_SMALL;
            } else if r != CKR_OK && rv == CKR_OK {
                rv = r;
            }
        }
        rv
    })
}

pub unsafe extern "C" fn c_set_attribute_value(
    _h: CK_SESSION_HANDLE,
    _o: CK_OBJECT_HANDLE,
    _a: *mut CK_ATTRIBUTE,
    _n: CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_find_objects_init(
    h: CK_SESSION_HANDLE,
    p_template: *mut CK_ATTRIBUTE,
    ul_count: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let (slot_id, logged_in) = {
            let Some(sess) = session_get(state, h) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            (sess.slot, sess.logged_in)
        };
        let tmpl = if p_template.is_null() || ul_count == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(p_template, ul_count as usize)
        };
        let objs: Vec<_> = state.slots[slot_id as usize]
            .token
            .objs
            .iter()
            .filter(|obj| {
                if (obj.private || obj.cls == ObjClass::PrivKey) && !logged_in {
                    return false;
                }
                attr_match(obj, tmpl)
            })
            .take(MAX_OBJS)
            .map(|o| o.handle)
            .collect();
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        sess.find_active = true;
        sess.find_pos = 0;
        sess.find_handles = objs;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_find_objects(
    h: CK_SESSION_HANDLE,
    ph_object: *mut CK_OBJECT_HANDLE,
    ul_max: CK_ULONG,
    pul_count: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if !sess.find_active || pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut n = 0u64;
        while sess.find_pos < sess.find_handles.len() && n < ul_max {
            if !ph_object.is_null() {
                *ph_object.add(n as usize) = sess.find_handles[sess.find_pos];
            }
            sess.find_pos += 1;
            n += 1;
        }
        *pul_count = n;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_find_objects_final(h: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        sess.find_active = false;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_encrypt_init(
    h: CK_SESSION_HANDLE,
    p_mech: *mut CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if p_mech.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech = unsafe { &*p_mech };
        if mech.mechanism != CKM_RSA_PKCS
            && mech.mechanism != CKM_RSA_X_509
            && mech.mechanism != CKM_RSA_PKCS_OAEP
        {
            return CKR_MECHANISM_INVALID;
        }
        let (oaep_hash, oaep_label) = if mech.mechanism == CKM_RSA_PKCS_OAEP {
            match parse_oaep_params(mech) {
                Ok(v) => v,
                Err(rv) => return rv,
            }
        } else {
            (CKM_SHA256, Vec::new())
        };
        let slot_id = sess.slot;
        let rv = ensure_card(state, slot_id);
        if rv != CKR_OK {
            return rv;
        }
        let Some(obj) = p15::find(&state.slots[slot_id as usize].token, h_key) else {
            return CKR_KEY_HANDLE_INVALID;
        };
        if obj.cls != ObjClass::PubKey || !obj.can_encrypt {
            return CKR_KEY_HANDLE_INVALID;
        }
        if obj.modulus.is_empty() || obj.pubexp.is_empty() {
            return CKR_KEY_HANDLE_INVALID;
        }
        let sess = session_get_mut(state, h).unwrap();
        sess.encrypt_active = true;
        sess.encrypt_key = h_key;
        sess.encrypt_mech = mech.mechanism;
        sess.encrypt_buf.clear();
        sess.encrypt_cipher = None;
        sess.encrypt_oaep_hash = oaep_hash;
        sess.encrypt_oaep_label = oaep_label;
        CKR_OK
    })
}

fn pkcs1_v15_encrypt_block(modulus_len: usize, plaintext: &[u8]) -> Result<Vec<u8>, CK_RV> {
    if plaintext.len() > modulus_len.saturating_sub(11) {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let ps_len = modulus_len - plaintext.len() - 3;
    let mut ps = vec![0u8; ps_len];
    getrandom::fill(&mut ps).map_err(|_| CKR_DEVICE_ERROR)?;
    for b in &mut ps {
        while *b == 0 {
            getrandom::fill(std::slice::from_mut(b)).map_err(|_| CKR_DEVICE_ERROR)?;
        }
    }
    let mut em = Vec::with_capacity(modulus_len);
    em.push(0x00);
    em.push(0x02);
    em.extend_from_slice(&ps);
    em.push(0x00);
    em.extend_from_slice(plaintext);
    Ok(em)
}

fn rsa_public_crypt(modulus: &[u8], exponent: &[u8], input: &[u8]) -> Result<Vec<u8>, CK_RV> {
    if modulus.is_empty() || exponent.is_empty() || input.len() != modulus.len() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(exponent);
    let m = BigUint::from_bytes_be(input);
    if n == BigUint::from(0u8) || e == BigUint::from(0u8) || m >= n {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let mut out = m.modpow(&e, &n).to_bytes_be();
    if out.len() > modulus.len() {
        return Err(CKR_FUNCTION_FAILED);
    }
    if out.len() < modulus.len() {
        let mut padded = vec![0u8; modulus.len() - out.len()];
        padded.append(&mut out);
        out = padded;
    }
    Ok(out)
}

fn do_encrypt(
    state: &mut State,
    h: CK_SESSION_HANDLE,
    plaintext: &[u8],
    p_enc: *mut CK_BYTE,
    pul_enc_len: *mut CK_ULONG,
) -> CK_RV {
    let (slot_id, key) = {
        let sess = session_get(state, h).unwrap();
        (sess.slot, sess.encrypt_key)
    };
    if p_enc.is_null() {
        if let Some(cipher) = session_get(state, h).and_then(|s| s.encrypt_cipher.as_ref()) {
            unsafe {
                *pul_enc_len = cipher.len() as CK_ULONG;
            }
            return CKR_OK;
        }
        unsafe {
            *pul_enc_len = RSA_MODULUS_LEN as CK_ULONG;
        }
        return CKR_OK;
    }

    let cipher =
        if let Some(cipher) = session_get_mut(state, h).and_then(|s| s.encrypt_cipher.take()) {
            cipher
        } else {
            let (mech, oaep_hash, oaep_label) = {
                let sess = session_get(state, h).unwrap();
                (
                    sess.encrypt_mech,
                    sess.encrypt_oaep_hash,
                    sess.encrypt_oaep_label.clone(),
                )
            };
            let Some(obj) = p15::find(&state.slots[slot_id as usize].token, key) else {
                return CKR_KEY_HANDLE_INVALID;
            };
            let em = match mech {
                CKM_RSA_PKCS => match pkcs1_v15_encrypt_block(obj.modulus.len(), plaintext) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                },
                CKM_RSA_X_509 => {
                    if plaintext.len() != obj.modulus.len() {
                        return CKR_DATA_LEN_RANGE;
                    }
                    plaintext.to_vec()
                }
                CKM_RSA_PKCS_OAEP => {
                    match oaep_encode(oaep_hash, &oaep_label, obj.modulus.len(), plaintext) {
                        Ok(v) => v,
                        Err(rv) => return rv,
                    }
                }
                _ => return CKR_MECHANISM_INVALID,
            };
            match rsa_public_crypt(&obj.modulus, &obj.pubexp, &em) {
                Ok(v) => v,
                Err(rv) => return rv,
            }
        };

    unsafe {
        if *pul_enc_len < cipher.len() as CK_ULONG {
            *pul_enc_len = cipher.len() as CK_ULONG;
            if let Some(sess) = session_get_mut(state, h) {
                sess.encrypt_cipher = Some(cipher);
            }
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(cipher.as_ptr(), p_enc, cipher.len());
        *pul_enc_len = cipher.len() as CK_ULONG;
    }
    CKR_OK
}

pub unsafe extern "C" fn c_encrypt(
    h: CK_SESSION_HANDLE,
    p_data: *mut CK_BYTE,
    ul_data_len: CK_ULONG,
    p_enc: *mut CK_BYTE,
    pul_enc_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.encrypt_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pul_enc_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let data = if ul_data_len == 0 {
            &[][..]
        } else if p_data.is_null() {
            return CKR_ARGUMENTS_BAD;
        } else {
            unsafe { std::slice::from_raw_parts(p_data, ul_data_len as usize) }
        };
        let rv = do_encrypt(state, h, data, p_enc, pul_enc_len);
        if !p_enc.is_null() && rv != CKR_BUFFER_TOO_SMALL {
            let sess = session_get_mut(state, h).unwrap();
            sess.encrypt_active = false;
            sess.encrypt_buf.clear();
            if rv != CKR_OK {
                sess.encrypt_cipher = None;
            }
        }
        rv
    })
}

pub unsafe extern "C" fn c_encrypt_update(
    h: CK_SESSION_HANDLE,
    p_part: *mut CK_BYTE,
    ul_part_len: CK_ULONG,
    p_enc: *mut CK_BYTE,
    pul_enc_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.encrypt_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pul_enc_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if ul_part_len != 0 && p_part.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if sess.encrypt_buf.len() + ul_part_len as usize > RSA_MODULUS_LEN {
            return CKR_DATA_LEN_RANGE;
        }
        if ul_part_len != 0 {
            let part = unsafe { std::slice::from_raw_parts(p_part, ul_part_len as usize) };
            sess.encrypt_buf.extend_from_slice(part);
        }
        unsafe {
            *pul_enc_len = 0;
        }
        let _ = p_enc;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_encrypt_final(
    h: CK_SESSION_HANDLE,
    p_last: *mut CK_BYTE,
    pul_last_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.encrypt_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pul_last_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let plain = sess.encrypt_buf.clone();
        let rv = do_encrypt(state, h, &plain, p_last, pul_last_len);
        if !p_last.is_null() && rv != CKR_BUFFER_TOO_SMALL {
            let sess = session_get_mut(state, h).unwrap();
            sess.encrypt_active = false;
            sess.encrypt_buf.clear();
            if rv != CKR_OK {
                sess.encrypt_cipher = None;
            }
        }
        rv
    })
}

pub unsafe extern "C" fn c_decrypt_init(
    h: CK_SESSION_HANDLE,
    p_mech: *mut CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    with_state(|state| {
        let (slot_id, logged_in) = {
            let Some(sess) = session_get(state, h) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            if !sess.logged_in {
                return CKR_USER_NOT_LOGGED_IN;
            }
            (sess.slot, sess.logged_in)
        };
        if p_mech.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech = unsafe { &*p_mech };
        let Some(obj) = p15::find(&state.slots[slot_id as usize].token, h_key) else {
            return CKR_KEY_HANDLE_INVALID;
        };
        if obj.cls != ObjClass::PrivKey || !obj.can_decrypt {
            return CKR_KEY_HANDLE_INVALID;
        }
        if mech.mechanism != CKM_RSA_PKCS
            && mech.mechanism != CKM_RSA_X_509
            && mech.mechanism != CKM_RSA_PKCS_OAEP
        {
            return CKR_MECHANISM_INVALID;
        }
        let (oaep_hash, oaep_label) = if mech.mechanism == CKM_RSA_PKCS_OAEP {
            match parse_oaep_params(mech) {
                Ok(v) => v,
                Err(rv) => return rv,
            }
        } else {
            (CKM_SHA256, Vec::new())
        };
        let _ = logged_in;
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        sess.decrypt_active = true;
        sess.decrypt_key = h_key;
        sess.decrypt_mech = mech.mechanism;
        sess.decrypt_buf.clear();
        sess.decrypt_plain = None;
        sess.decrypt_oaep_hash = oaep_hash;
        sess.decrypt_oaep_label = oaep_label;
        CKR_OK
    })
}

fn do_decrypt(
    state: &mut State,
    h: CK_SESSION_HANDLE,
    cipher: &[u8],
    p_data: *mut CK_BYTE,
    pul_data_len: *mut CK_ULONG,
) -> CK_RV {
    let (slot_id, key, mech, oaep_hash, oaep_label) = {
        let sess = session_get(state, h).unwrap();
        (
            sess.slot,
            sess.decrypt_key,
            sess.decrypt_mech,
            sess.decrypt_oaep_hash,
            sess.decrypt_oaep_label.clone(),
        )
    };
    let key_ref = match p15::find(&state.slots[slot_id as usize].token, key) {
        Some(o) => o.key_ref as u8,
        None => return CKR_KEY_HANDLE_INVALID,
    };

    // Size probe without touching the card when we already have plaintext cached
    // (multipart Final after Update decrypted early), or when p_data is null and
    // we only need an upper bound for RSA-PKCS.
    if p_data.is_null() {
        if let Some(plain) = session_get(state, h).and_then(|s| s.decrypt_plain.as_ref()) {
            unsafe {
                *pul_data_len = plain.len() as CK_ULONG;
            }
            return CKR_OK;
        }
        // RSA-PKCS plaintext is at most modulus-11 bytes; report cipher len as bound.
        unsafe {
            *pul_data_len = cipher.len() as CK_ULONG;
        }
        return CKR_OK;
    }

    let plain = if let Some(plain) = session_get_mut(state, h).and_then(|s| s.decrypt_plain.take())
    {
        plain
    } else {
        let slot = &mut state.slots[slot_id as usize];
        match mech {
            CKM_RSA_PKCS => {
                let mut out = [0u8; 512];
                match apdu::decrypt(&mut slot.pcsc, key_ref, cipher, &mut out) {
                    Ok(n) => out[..n].to_vec(),
                    Err(_) => return CKR_FUNCTION_FAILED,
                }
            }
            CKM_RSA_X_509 => {
                if cipher.len() != RSA_MODULUS_LEN {
                    return CKR_DATA_LEN_RANGE;
                }
                let mut raw = [0u8; RSA_MODULUS_LEN];
                if apdu::rsa_private_op(&mut slot.pcsc, key_ref, cipher, &mut raw).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                raw.to_vec()
            }
            CKM_RSA_PKCS_OAEP => {
                let mut raw = [0u8; RSA_MODULUS_LEN];
                if apdu::rsa_private_op(&mut slot.pcsc, key_ref, cipher, &mut raw).is_err() {
                    return CKR_FUNCTION_FAILED;
                }
                match oaep_decode(oaep_hash, &oaep_label, &raw) {
                    Ok(v) => v,
                    Err(rv) => return rv,
                }
            }
            _ => return CKR_MECHANISM_INVALID,
        }
    };

    unsafe {
        if *pul_data_len < plain.len() as CK_ULONG {
            *pul_data_len = plain.len() as CK_ULONG;
            // Keep plaintext for a retry with a larger buffer.
            if let Some(sess) = session_get_mut(state, h) {
                sess.decrypt_plain = Some(plain);
            }
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(plain.as_ptr(), p_data, plain.len());
        *pul_data_len = plain.len() as CK_ULONG;
    }
    CKR_OK
}

pub unsafe extern "C" fn c_decrypt(
    h: CK_SESSION_HANDLE,
    p_enc: *mut CK_BYTE,
    ul_enc_len: CK_ULONG,
    p_data: *mut CK_BYTE,
    pul_data_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.decrypt_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pul_data_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let cipher = unsafe { std::slice::from_raw_parts(p_enc, ul_enc_len as usize) };
        let rv = do_decrypt(state, h, cipher, p_data, pul_data_len);
        // Keep operation active on size probe / buffer-too-small so the caller can retry.
        if !p_data.is_null() && rv != CKR_BUFFER_TOO_SMALL {
            let sess = session_get_mut(state, h).unwrap();
            sess.decrypt_active = false;
            sess.decrypt_buf.clear();
            if rv != CKR_OK {
                sess.decrypt_plain = None;
            }
        }
        rv
    })
}

pub unsafe extern "C" fn c_decrypt_update(
    h: CK_SESSION_HANDLE,
    p_part: *mut CK_BYTE,
    ul_part_len: CK_ULONG,
    p_decrypted: *mut CK_BYTE,
    pul_decrypted_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.decrypt_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pul_decrypted_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let part = unsafe { std::slice::from_raw_parts(p_part, ul_part_len as usize) };
        if sess.decrypt_buf.len() + part.len() > 512 {
            return CKR_DATA_LEN_RANGE;
        }
        sess.decrypt_buf.extend_from_slice(part);
        // RSA-PKCS is single-part on the card; emit nothing until Final.
        if p_decrypted.is_null() {
            unsafe {
                *pul_decrypted_len = 0;
            }
            return CKR_OK;
        }
        unsafe {
            *pul_decrypted_len = 0;
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn c_decrypt_final(
    h: CK_SESSION_HANDLE,
    p_last: *mut CK_BYTE,
    pul_last_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.decrypt_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pul_last_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let cipher = sess.decrypt_buf.clone();
        let rv = do_decrypt(state, h, &cipher, p_last, pul_last_len);
        if !p_last.is_null() && rv != CKR_BUFFER_TOO_SMALL {
            let sess = session_get_mut(state, h).unwrap();
            sess.decrypt_active = false;
            sess.decrypt_buf.clear();
            if rv != CKR_OK {
                sess.decrypt_plain = None;
            }
        }
        rv
    })
}

pub unsafe extern "C" fn c_digest_init(h: CK_SESSION_HANDLE, p_mech: *mut CK_MECHANISM) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if p_mech.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mechanism = unsafe { (*p_mech).mechanism };
        let ctx = match mechanism {
            CKM_MD5 => DigestCtx::Md5(Md5::new()),
            CKM_SHA_1 => DigestCtx::Sha1(Sha1::new()),
            CKM_SHA256 => DigestCtx::Sha256(Sha256::new()),
            CKM_SHA384 => DigestCtx::Sha384(Sha384::new()),
            CKM_SHA512 => DigestCtx::Sha512(Sha512::new()),
            _ => return CKR_MECHANISM_INVALID,
        };
        sess.digest_active = true;
        sess.digest_ctx = Some(ctx);
        CKR_OK
    })
}

fn digest_update_ctx(ctx: &mut DigestCtx, data: &[u8]) {
    match ctx {
        DigestCtx::Md5(d) => d.update(data),
        DigestCtx::Sha1(d) => d.update(data),
        DigestCtx::Sha256(d) => d.update(data),
        DigestCtx::Sha384(d) => d.update(data),
        DigestCtx::Sha512(d) => d.update(data),
    }
}

fn digest_finalize_ctx(ctx: DigestCtx) -> Vec<u8> {
    match ctx {
        DigestCtx::Md5(d) => d.finalize().to_vec(),
        DigestCtx::Sha1(d) => d.finalize().to_vec(),
        DigestCtx::Sha256(d) => d.finalize().to_vec(),
        DigestCtx::Sha384(d) => d.finalize().to_vec(),
        DigestCtx::Sha512(d) => d.finalize().to_vec(),
    }
}

fn digest_output_len(ctx: &DigestCtx) -> usize {
    match ctx {
        DigestCtx::Md5(_) => 16,
        DigestCtx::Sha1(_) => 20,
        DigestCtx::Sha256(_) => 32,
        DigestCtx::Sha384(_) => 48,
        DigestCtx::Sha512(_) => 64,
    }
}

pub unsafe extern "C" fn c_digest(
    h: CK_SESSION_HANDLE,
    p_data: *mut CK_BYTE,
    ul_data_len: CK_ULONG,
    p_digest: *mut CK_BYTE,
    pul_digest_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.digest_active || sess.digest_ctx.is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pul_digest_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let need = digest_output_len(sess.digest_ctx.as_ref().unwrap());
        if p_digest.is_null() {
            unsafe {
                *pul_digest_len = need as CK_ULONG;
            }
            return CKR_OK;
        }
        if ul_data_len != 0 && p_data.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        unsafe {
            if *pul_digest_len < need as CK_ULONG {
                *pul_digest_len = need as CK_ULONG;
                return CKR_BUFFER_TOO_SMALL;
            }
        }
        let data = if ul_data_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(p_data, ul_data_len as usize) }
        };
        let mut ctx = sess.digest_ctx.take().unwrap();
        digest_update_ctx(&mut ctx, data);
        let out = digest_finalize_ctx(ctx);
        sess.digest_active = false;
        unsafe {
            std::ptr::copy_nonoverlapping(out.as_ptr(), p_digest, out.len());
            *pul_digest_len = out.len() as CK_ULONG;
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn c_digest_update(
    h: CK_SESSION_HANDLE,
    p_part: *mut CK_BYTE,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.digest_active || sess.digest_ctx.is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if ul_part_len != 0 && p_part.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if ul_part_len != 0 {
            let part = unsafe { std::slice::from_raw_parts(p_part, ul_part_len as usize) };
            digest_update_ctx(sess.digest_ctx.as_mut().unwrap(), part);
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn c_digest_key(_h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_digest_final(
    h: CK_SESSION_HANDLE,
    p_digest: *mut CK_BYTE,
    pul_digest_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.digest_active || sess.digest_ctx.is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pul_digest_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let need = digest_output_len(sess.digest_ctx.as_ref().unwrap());
        if p_digest.is_null() {
            unsafe {
                *pul_digest_len = need as CK_ULONG;
            }
            return CKR_OK;
        }
        unsafe {
            if *pul_digest_len < need as CK_ULONG {
                *pul_digest_len = need as CK_ULONG;
                return CKR_BUFFER_TOO_SMALL;
            }
        }
        let ctx = sess.digest_ctx.take().unwrap();
        let out = digest_finalize_ctx(ctx);
        sess.digest_active = false;
        unsafe {
            std::ptr::copy_nonoverlapping(out.as_ptr(), p_digest, out.len());
            *pul_digest_len = out.len() as CK_ULONG;
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn c_sign_init(
    h: CK_SESSION_HANDLE,
    p_mech: *mut CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if !sess.logged_in {
            return CKR_USER_NOT_LOGGED_IN;
        }
        if p_mech.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech = &*p_mech;
        let slot_id = sess.slot;
        let Some(obj) = p15::find(&state.slots[slot_id as usize].token, h_key) else {
            return CKR_KEY_HANDLE_INVALID;
        };
        if obj.cls != ObjClass::PrivKey || !obj.can_sign {
            return CKR_KEY_HANDLE_INVALID;
        }
        if mech.mechanism != CKM_RSA_PKCS
            && mech.mechanism != CKM_RSA_X_509
            && !is_hash_rsa_pkcs(mech.mechanism)
        {
            return CKR_MECHANISM_INVALID;
        }
        let sess = session_get_mut(state, h).unwrap();
        sess.sign_active = true;
        sess.sign_key = h_key;
        sess.sign_mech = mech.mechanism;
        sess.sign_buf.clear();
        CKR_OK
    })
}

fn do_sign(
    state: &mut State,
    h: CK_SESSION_HANDLE,
    data: &[u8],
    p_sig: *mut CK_BYTE,
    pul_sig_len: *mut CK_ULONG,
) -> CK_RV {
    let (slot_id, sign_key, sign_mech) = {
        let sess = session_get(state, h).unwrap();
        (sess.slot, sess.sign_key, sess.sign_mech)
    };
    let key_ref = match p15::find(&state.slots[slot_id as usize].token, sign_key) {
        Some(o) => o.key_ref as u8,
        None => return CKR_KEY_HANDLE_INVALID,
    };
    let mut dig_buf: Option<Vec<u8>> = None;
    let to_sign: &[u8] = if is_hash_rsa_pkcs(sign_mech) {
        match digest_info_for_hash_mech(sign_mech, data) {
            Ok(v) => {
                dig_buf = Some(v);
                dig_buf.as_ref().unwrap().as_slice()
            }
            Err(rv) => return rv,
        }
    } else {
        data
    };
    const SIGNATURE_LEN: usize = 256;
    if p_sig.is_null() {
        unsafe {
            *pul_sig_len = SIGNATURE_LEN as CK_ULONG;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_sig_len < SIGNATURE_LEN as CK_ULONG {
            *pul_sig_len = SIGNATURE_LEN as CK_ULONG;
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    let slot = &mut state.slots[slot_id as usize];
    let mut out = [0u8; 512];
    let n = match sign_mech {
        CKM_RSA_X_509 => {
            if to_sign.len() != RSA_MODULUS_LEN {
                return CKR_DATA_LEN_RANGE;
            }
            match apdu::rsa_private_op(&mut slot.pcsc, key_ref, to_sign, &mut out[..RSA_MODULUS_LEN])
            {
                Ok(n) => n,
                Err(_) => return CKR_FUNCTION_FAILED,
            }
        }
        _ => match apdu::sign(&mut slot.pcsc, key_ref, to_sign, &mut out) {
            Ok(n) => n,
            Err(_) => return CKR_FUNCTION_FAILED,
        },
    };
    let _ = dig_buf;
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), p_sig, n);
        *pul_sig_len = n as CK_ULONG;
    }
    CKR_OK
}

pub unsafe extern "C" fn c_sign(
    h: CK_SESSION_HANDLE,
    p_data: *mut CK_BYTE,
    ul_data_len: CK_ULONG,
    p_sig: *mut CK_BYTE,
    pul_sig_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.sign_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if pul_sig_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let data = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let rv = do_sign(state, h, data, p_sig, pul_sig_len);
        if !p_sig.is_null() || rv != CKR_OK {
            session_get_mut(state, h).unwrap().sign_active = false;
        }
        rv
    })
}

pub unsafe extern "C" fn c_sign_update(
    h: CK_SESSION_HANDLE,
    p_part: *mut CK_BYTE,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.sign_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        let part = std::slice::from_raw_parts(p_part, ul_part_len as usize);
        if sess.sign_buf.len() + part.len() > 8192 {
            return CKR_DATA_LEN_RANGE;
        }
        sess.sign_buf.extend_from_slice(part);
        CKR_OK
    })
}

pub unsafe extern "C" fn c_sign_final(
    h: CK_SESSION_HANDLE,
    p_sig: *mut CK_BYTE,
    pul_sig_len: *mut CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        if !sess.sign_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        let buf = sess.sign_buf.clone();
        let rv = do_sign(state, h, &buf, p_sig, pul_sig_len);
        if !p_sig.is_null() || rv != CKR_OK {
            session_get_mut(state, h).unwrap().sign_active = false;
        }
        rv
    })
}

pub unsafe extern "C" fn c_sign_recover_init(
    _h: CK_SESSION_HANDLE,
    _m: *mut CK_MECHANISM,
    _o: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_sign_recover(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_verify_init(
    h: CK_SESSION_HANDLE,
    p_mech: *mut CK_MECHANISM,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if p_mech.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mechanism = unsafe { (*p_mech).mechanism };
        if mechanism != CKM_RSA_PKCS
            && mechanism != CKM_RSA_X_509
            && !is_hash_rsa_pkcs(mechanism)
        {
            return CKR_MECHANISM_INVALID;
        }
        let slot_id = sess.slot;
        let Some(obj) = p15::find(&state.slots[slot_id as usize].token, h_key) else {
            return CKR_KEY_HANDLE_INVALID;
        };
        if obj.cls != ObjClass::PubKey {
            return CKR_KEY_HANDLE_INVALID;
        }
        if !obj.can_verify {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        if obj.modulus.is_empty() || obj.pubexp.is_empty() {
            return CKR_KEY_HANDLE_INVALID;
        }
        let sess = session_get_mut(state, h).unwrap();
        sess.verify_active = true;
        sess.verify_key = h_key;
        sess.verify_mech = mechanism;
        sess.verify_buf.clear();
        CKR_OK
    })
}

fn emsa_pkcs1_v15(payload: &[u8], modulus_len: usize) -> Result<Vec<u8>, CK_RV> {
    if payload.len() > modulus_len.saturating_sub(11) {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let padding_len = modulus_len - payload.len() - 3;
    let mut encoded = Vec::with_capacity(modulus_len);
    encoded.extend_from_slice(&[0x00, 0x01]);
    encoded.resize(2 + padding_len, 0xFF);
    encoded.push(0x00);
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn verify_rsa_pkcs1_v15(
    modulus: &[u8],
    exponent: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> CK_RV {
    let modulus_len = modulus.len();
    if signature.len() != modulus_len {
        return CKR_SIGNATURE_LEN_RANGE;
    }
    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(exponent);
    let s = BigUint::from_bytes_be(signature);
    if n == BigUint::from(0u8) || e == BigUint::from(0u8) || s >= n {
        return CKR_SIGNATURE_INVALID;
    }
    let recovered = s.modpow(&e, &n).to_bytes_be();
    if recovered.len() > modulus_len {
        return CKR_SIGNATURE_INVALID;
    }
    let mut encoded = vec![0u8; modulus_len - recovered.len()];
    encoded.extend_from_slice(&recovered);
    let expected = match emsa_pkcs1_v15(payload, modulus_len) {
        Ok(v) => v,
        Err(rv) => return rv,
    };
    if encoded == expected {
        CKR_OK
    } else {
        CKR_SIGNATURE_INVALID
    }
}

fn verify_rsa_x509(modulus: &[u8], exponent: &[u8], data: &[u8], signature: &[u8]) -> CK_RV {
    let modulus_len = modulus.len();
    if data.len() != modulus_len {
        return CKR_DATA_LEN_RANGE;
    }
    if signature.len() != modulus_len {
        return CKR_SIGNATURE_LEN_RANGE;
    }
    match rsa_public_crypt(modulus, exponent, signature) {
        Ok(recovered) if recovered.as_slice() == data => CKR_OK,
        Ok(_) => CKR_SIGNATURE_INVALID,
        Err(rv) => rv,
    }
}

fn do_verify(state: &mut State, h: CK_SESSION_HANDLE, data: &[u8], signature: &[u8]) -> CK_RV {
    let (slot_id, key, mechanism) = {
        let sess = session_get(state, h).unwrap();
        (sess.slot, sess.verify_key, sess.verify_mech)
    };
    let Some(obj) = p15::find(&state.slots[slot_id as usize].token, key) else {
        return CKR_KEY_HANDLE_INVALID;
    };

    if mechanism == CKM_RSA_X_509 {
        return verify_rsa_x509(&obj.modulus, &obj.pubexp, data, signature);
    }

    let digest_info;
    let payload = if is_hash_rsa_pkcs(mechanism) {
        match digest_info_for_hash_mech(mechanism, data) {
            Ok(v) => {
                digest_info = v;
                digest_info.as_slice()
            }
            Err(rv) => return rv,
        }
    } else if mechanism == CKM_RSA_PKCS {
        data
    } else {
        return CKR_MECHANISM_INVALID;
    };
    verify_rsa_pkcs1_v15(&obj.modulus, &obj.pubexp, payload, signature)
}

pub unsafe extern "C" fn c_verify(
    h: CK_SESSION_HANDLE,
    p_data: *mut CK_BYTE,
    ul_data_len: CK_ULONG,
    p_signature: *mut CK_BYTE,
    ul_signature_len: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if !sess.verify_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if (ul_data_len != 0 && p_data.is_null())
            || (ul_signature_len != 0 && p_signature.is_null())
        {
            return CKR_ARGUMENTS_BAD;
        }
        let data = if ul_data_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(p_data, ul_data_len as usize) }
        };
        let signature = if ul_signature_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(p_signature, ul_signature_len as usize) }
        };
        let rv = do_verify(state, h, data, signature);
        let sess = session_get_mut(state, h).unwrap();
        sess.verify_active = false;
        sess.verify_buf.clear();
        rv
    })
}

pub unsafe extern "C" fn c_verify_update(
    h: CK_SESSION_HANDLE,
    p_part: *mut CK_BYTE,
    ul_part_len: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if !sess.verify_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if ul_part_len != 0 && p_part.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if sess.verify_buf.len() + ul_part_len as usize > 8192 {
            return CKR_DATA_LEN_RANGE;
        }
        if ul_part_len != 0 {
            let part = unsafe { std::slice::from_raw_parts(p_part, ul_part_len as usize) };
            sess.verify_buf.extend_from_slice(part);
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn c_verify_final(
    h: CK_SESSION_HANDLE,
    p_signature: *mut CK_BYTE,
    ul_signature_len: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if !sess.verify_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        if ul_signature_len != 0 && p_signature.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let data = sess.verify_buf.clone();
        let signature = if ul_signature_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(p_signature, ul_signature_len as usize) }
        };
        let rv = do_verify(state, h, &data, signature);
        let sess = session_get_mut(state, h).unwrap();
        sess.verify_active = false;
        sess.verify_buf.clear();
        rv
    })
}

pub unsafe extern "C" fn c_verify_recover_init(
    _h: CK_SESSION_HANDLE,
    _m: *mut CK_MECHANISM,
    _o: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_verify_recover(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_digest_encrypt_update(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_decrypt_digest_update(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_sign_encrypt_update(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_decrypt_verify_update(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_generate_key(
    _h: CK_SESSION_HANDLE,
    _m: *mut CK_MECHANISM,
    _a: *mut CK_ATTRIBUTE,
    _n: CK_ULONG,
    _o: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_generate_key_pair(
    _h: CK_SESSION_HANDLE,
    _m: *mut CK_MECHANISM,
    _a: *mut CK_ATTRIBUTE,
    _b: CK_ULONG,
    _c: *mut CK_ATTRIBUTE,
    _d: CK_ULONG,
    _e: *mut CK_OBJECT_HANDLE,
    _f: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_wrap_key(
    _h: CK_SESSION_HANDLE,
    _m: *mut CK_MECHANISM,
    _a: CK_OBJECT_HANDLE,
    _b: CK_OBJECT_HANDLE,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_unwrap_key(
    _h: CK_SESSION_HANDLE,
    _m: *mut CK_MECHANISM,
    _a: CK_OBJECT_HANDLE,
    _b: *mut CK_BYTE,
    _c: CK_ULONG,
    _d: *mut CK_ATTRIBUTE,
    _e: CK_ULONG,
    _f: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_derive_key(
    _h: CK_SESSION_HANDLE,
    _m: *mut CK_MECHANISM,
    _a: CK_OBJECT_HANDLE,
    _b: *mut CK_ATTRIBUTE,
    _c: CK_ULONG,
    _d: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_seed_random(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_generate_random(
    h: CK_SESSION_HANDLE,
    p_random: *mut CK_BYTE,
    ul_random_len: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        if session_get(state, h).is_none() {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if ul_random_len == 0 {
            return CKR_OK;
        }
        if p_random.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let out = unsafe { std::slice::from_raw_parts_mut(p_random, ul_random_len as usize) };
        match getrandom::fill(out) {
            Ok(()) => CKR_OK,
            Err(_) => CKR_DEVICE_ERROR,
        }
    })
}

pub unsafe extern "C" fn c_get_function_status(_h: CK_SESSION_HANDLE) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_cancel_function(_h: CK_SESSION_HANDLE) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_wait_for_slot_event(
    _f: CK_FLAGS,
    _s: *mut CK_SLOT_ID,
    _p: *mut core::ffi::c_void,
) -> CK_RV {
    not_supported!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emsa_pkcs1_v15_has_type1_padding() {
        let encoded = emsa_pkcs1_v15(b"abc", 16).unwrap();
        assert_eq!(&encoded[..2], &[0x00, 0x01]);
        assert!(encoded[2..12].iter().all(|&b| b == 0xFF));
        assert_eq!(&encoded[12..], &[0x00, b'a', b'b', b'c']);
    }

    #[test]
    fn oaep_sha256_roundtrip() {
        let msg = b"openhicos-oaep";
        let em = oaep_encode(CKM_SHA256, b"", 256, msg).unwrap();
        assert_eq!(em.len(), 256);
        assert_eq!(em[0], 0x00);
        assert_eq!(oaep_decode(CKM_SHA256, b"", &em).unwrap(), msg);
    }

    #[test]
    fn pkcs1_v15_encrypt_block_layout() {
        let msg = b"hello";
        let em = pkcs1_v15_encrypt_block(256, msg).unwrap();
        assert_eq!(em.len(), 256);
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x02);
        assert_eq!(&em[em.len() - msg.len()..], msg);
        assert_eq!(em[em.len() - msg.len() - 1], 0x00);
        assert!(em[2..em.len() - msg.len() - 1].iter().all(|&b| b != 0));
    }

    #[test]
    fn login_state_is_shared_by_all_sessions_on_a_slot() {
        let mut sessions: [Session; 3] = std::array::from_fn(|_| Session::default());
        sessions[0] = Session {
            in_use: true,
            slot: 0,
            flags: CKF_SERIAL_SESSION,
            ..Default::default()
        };
        sessions[1] = Session {
            in_use: true,
            slot: 0,
            flags: CKF_SERIAL_SESSION | CKF_RW_SESSION,
            ..Default::default()
        };
        sessions[2] = Session {
            in_use: true,
            slot: 1,
            flags: CKF_SERIAL_SESSION,
            ..Default::default()
        };

        set_slot_sessions_login_state(&mut sessions, 0, true);

        assert!(sessions[0].logged_in);
        assert_eq!(sessions[0].state, CKS_RO_USER_FUNCTIONS);
        assert!(sessions[1].logged_in);
        assert_eq!(sessions[1].state, CKS_RW_USER_FUNCTIONS);
        assert!(!sessions[2].logged_in);
        assert_eq!(sessions[2].state, CKS_RO_PUBLIC_SESSION);

        set_slot_sessions_login_state(&mut sessions, 0, false);

        assert!(!sessions[0].logged_in);
        assert_eq!(sessions[0].state, CKS_RO_PUBLIC_SESSION);
        assert!(!sessions[1].logged_in);
        assert_eq!(sessions[1].state, CKS_RW_PUBLIC_SESSION);
    }

    #[test]
    fn find_template_matches_certificate_value_exactly() {
        let object = p15::TokenObject {
            data: vec![0x30, 0x03, 0x01, 0x02, 0x03],
            ..Default::default()
        };
        let mut matching_value: Vec<u8> = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let matching_template = CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: matching_value.as_mut_ptr().cast(),
            ulValueLen: matching_value.len() as CK_ULONG,
        };
        assert!(attr_match(&object, &[matching_template]));

        let mut different_value: Vec<u8> = vec![0x30, 0x03, 0x01, 0x02, 0x04];
        let different_template = CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: different_value.as_mut_ptr().cast(),
            ulValueLen: different_value.len() as CK_ULONG,
        };
        assert!(!attr_match(&object, &[different_template]));
    }
}

pub static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: c_initialize,
    C_Finalize: c_finalize,
    C_GetInfo: c_get_info,
    C_GetFunctionList: crate::C_GetFunctionList,
    C_GetSlotList: c_get_slot_list,
    C_GetSlotInfo: c_get_slot_info,
    C_GetTokenInfo: c_get_token_info,
    C_GetMechanismList: c_get_mechanism_list,
    C_GetMechanismInfo: c_get_mechanism_info,
    C_InitToken: c_init_token,
    C_InitPIN: c_init_pin,
    C_SetPIN: c_set_pin,
    C_OpenSession: c_open_session,
    C_CloseSession: c_close_session,
    C_CloseAllSessions: c_close_all_sessions,
    C_GetSessionInfo: c_get_session_info,
    C_GetOperationState: c_get_operation_state,
    C_SetOperationState: c_set_operation_state,
    C_Login: c_login,
    C_Logout: c_logout,
    C_CreateObject: c_create_object,
    C_CopyObject: c_copy_object,
    C_DestroyObject: c_destroy_object,
    C_GetObjectSize: c_get_object_size,
    C_GetAttributeValue: c_get_attribute_value,
    C_SetAttributeValue: c_set_attribute_value,
    C_FindObjectsInit: c_find_objects_init,
    C_FindObjects: c_find_objects,
    C_FindObjectsFinal: c_find_objects_final,
    C_EncryptInit: c_encrypt_init,
    C_Encrypt: c_encrypt,
    C_EncryptUpdate: c_encrypt_update,
    C_EncryptFinal: c_encrypt_final,
    C_DecryptInit: c_decrypt_init,
    C_Decrypt: c_decrypt,
    C_DecryptUpdate: c_decrypt_update,
    C_DecryptFinal: c_decrypt_final,
    C_DigestInit: c_digest_init,
    C_Digest: c_digest,
    C_DigestUpdate: c_digest_update,
    C_DigestKey: c_digest_key,
    C_DigestFinal: c_digest_final,
    C_SignInit: c_sign_init,
    C_Sign: c_sign,
    C_SignUpdate: c_sign_update,
    C_SignFinal: c_sign_final,
    C_SignRecoverInit: c_sign_recover_init,
    C_SignRecover: c_sign_recover,
    C_VerifyInit: c_verify_init,
    C_Verify: c_verify,
    C_VerifyUpdate: c_verify_update,
    C_VerifyFinal: c_verify_final,
    C_VerifyRecoverInit: c_verify_recover_init,
    C_VerifyRecover: c_verify_recover,
    C_DigestEncryptUpdate: c_digest_encrypt_update,
    C_DecryptDigestUpdate: c_decrypt_digest_update,
    C_SignEncryptUpdate: c_sign_encrypt_update,
    C_DecryptVerifyUpdate: c_decrypt_verify_update,
    C_GenerateKey: c_generate_key,
    C_GenerateKeyPair: c_generate_key_pair,
    C_WrapKey: c_wrap_key,
    C_UnwrapKey: c_unwrap_key,
    C_DeriveKey: c_derive_key,
    C_SeedRandom: c_seed_random,
    C_GenerateRandom: c_generate_random,
    C_GetFunctionStatus: c_get_function_status,
    C_CancelFunction: c_cancel_function,
    C_WaitForSlotEvent: c_wait_for_slot_event,
};

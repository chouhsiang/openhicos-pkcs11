//! PKCS#11 Cryptoki implementation.

use crate::apdu::{self, PinResult};
use crate::p15::{self, ObjClass, Token, MAX_OBJS};
use crate::pcsc::PcscConn;
use crate::pkcs11::types::*;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha256Digest, Sha256};
use std::sync::Mutex;

const MAX_SLOTS: usize = 8;
const MAX_SESSIONS: usize = 16;
const PIN_MAX: u64 = 10;

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
        }
    }
}

struct Slot {
    present: bool,
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

fn attr_match(o: &p15::TokenObject, tmpl: &[CK_ATTRIBUTE]) -> bool {
    for t in tmpl {
        unsafe {
            match t.type_ {
                CKA_CLASS if !t.pValue.is_null() && t.ulValueLen == 8 => {
                    let cls = *(t.pValue as *const CK_ULONG);
                    let have = match o.cls {
                        ObjClass::PrivKey => CKO_PRIVATE_KEY,
                        ObjClass::PubKey => CKO_PUBLIC_KEY,
                        ObjClass::Cert => CKO_CERTIFICATE,
                    };
                    if cls != have {
                        return false;
                    }
                }
                CKA_ID if !t.pValue.is_null() => {
                    let slice = std::slice::from_raw_parts(t.pValue as *const u8, t.ulValueLen as usize);
                    if slice.len() != o.id.len() || slice != o.id.as_slice() {
                        return false;
                    }
                }
                CKA_LABEL if !t.pValue.is_null() => {
                    let slice = std::slice::from_raw_parts(t.pValue as *const u8, t.ulValueLen as usize);
                    if slice.len() != o.label.len() || slice != o.label.as_bytes() {
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
        info.cryptokiVersion = CK_VERSION { major: 2, minor: 40 };
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

pub unsafe extern "C" fn c_get_token_info(slot_id: CK_SLOT_ID, p_info: *mut CK_TOKEN_INFO) -> CK_RV {
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
        info.flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
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
        info.hardwareVersion = CK_VERSION { major: 0, minor: 0 };
        info.firmwareVersion = CK_VERSION { major: 0, minor: 0 };
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
        let mechs = [CKM_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS];
        if !p_list.is_null() {
            if *pul_count < 3 {
                return CKR_BUFFER_TOO_SMALL;
            }
            for (i, &m) in mechs.iter().enumerate() {
                *p_list.add(i) = m;
            }
        }
        *pul_count = 3;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_mechanism_info(
    _s: CK_SLOT_ID,
    _m: CK_MECHANISM_TYPE,
    _i: *mut core::ffi::c_void,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_init_token(
    _s: CK_SLOT_ID,
    _a: *mut CK_UTF8CHAR,
    _b: CK_ULONG,
    _c: *mut CK_UTF8CHAR,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_init_pin(_h: CK_SESSION_HANDLE, _p: *mut CK_UTF8CHAR, _n: CK_ULONG) -> CK_RV {
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
        for (i, s) in state.sessions.iter_mut().enumerate() {
            if !s.in_use {
                *s = Session {
                    in_use: true,
                    slot: slot_id,
                    flags,
                    state: if flags & CKF_RW_SESSION != 0 {
                        CKS_RW_PUBLIC_SESSION
                    } else {
                        CKS_RO_PUBLIC_SESSION
                    },
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
        if let Some(s) = session_get_mut(state, h) {
            s.in_use = false;
            CKR_OK
        } else {
            CKR_SESSION_HANDLE_INVALID
        }
    })
}

pub unsafe extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        for s in &mut state.sessions {
            if s.in_use && s.slot == slot_id {
                s.in_use = false;
            }
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_session_info(h: CK_SESSION_HANDLE, p_info: *mut CK_SESSION_INFO) -> CK_RV {
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
        if sess.logged_in {
            return CKR_USER_ALREADY_LOGGED_IN;
        }
        if p_pin.is_null() || ul_pin_len == 0 {
            return CKR_ARGUMENTS_BAD;
        }
        let pin = std::slice::from_raw_parts(p_pin, ul_pin_len as usize);
        let slot_id = sess.slot;
        let pin_ref = state.slots[slot_id as usize].token.pin_ref;
        let mut refs = vec![pin_ref];
        if pin_ref != 0x00 {
            refs.push(0x00);
        }
        if pin_ref != 0x01 {
            refs.push(0x01);
        }
        refs.push(0x8C);
        let slot = &mut state.slots[slot_id as usize];
        let mut ok = false;
        for r in refs {
            match apdu::verify_pin(&mut slot.pcsc, r, pin) {
                PinResult::Ok => {
                    slot.token.pin_ref = r;
                    ok = true;
                    break;
                }
                PinResult::Locked => return CKR_PIN_LOCKED,
                PinResult::Incorrect => {}
                PinResult::Error => {}
            }
        }
        if !ok {
            return CKR_PIN_INCORRECT;
        }
        let sess = session_get_mut(state, h).unwrap();
        sess.logged_in = true;
        sess.state = if sess.flags & CKF_RW_SESSION != 0 {
            CKS_RW_USER_FUNCTIONS
        } else {
            CKS_RO_USER_FUNCTIONS
        };
        CKR_OK
    })
}

pub unsafe extern "C" fn c_logout(h: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if !sess.logged_in {
            return CKR_USER_NOT_LOGGED_IN;
        }
        sess.logged_in = false;
        sess.state = if sess.flags & CKF_RW_SESSION != 0 {
            CKS_RW_PUBLIC_SESSION
        } else {
            CKS_RO_PUBLIC_SESSION
        };
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
        for attr in tmpl {
            let r = match attr.type_ {
                CKA_CLASS => {
                    let ul = match obj.cls {
                        ObjClass::PrivKey => CKO_PRIVATE_KEY,
                        ObjClass::PubKey => CKO_PUBLIC_KEY,
                        ObjClass::Cert => CKO_CERTIFICATE,
                    };
                    set_attr(attr, &ul.to_le_bytes())
                }
                CKA_TOKEN => set_attr(attr, &[btrue]),
                CKA_PRIVATE => {
                    let b = if obj.cls == ObjClass::PrivKey {
                        CK_TRUE
                    } else {
                        CK_FALSE
                    };
                    set_attr(attr, &[b])
                }
                CKA_LABEL => set_attr(attr, obj.label.as_bytes()),
                CKA_ID => set_attr(attr, &obj.id),
                CKA_KEY_TYPE if obj.cls == ObjClass::Cert => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_KEY_TYPE => set_attr(attr, &kt),
                CKA_CERTIFICATE_TYPE if obj.cls != ObjClass::Cert => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_CERTIFICATE_TYPE => set_attr(attr, &ct),
                CKA_VALUE if obj.cls != ObjClass::Cert || obj.data.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_VALUE => set_attr(attr, &obj.data),
                CKA_MODULUS if obj.modulus.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_MODULUS => set_attr(attr, &obj.modulus),
                CKA_MODULUS_BITS if obj.modulus_bits == 0 => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_MODULUS_BITS => set_attr(attr, &obj.modulus_bits.to_le_bytes()),
                CKA_PUBLIC_EXPONENT if obj.pubexp.is_empty() => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
                CKA_PUBLIC_EXPONENT => set_attr(attr, &obj.pubexp),
                CKA_SIGN => {
                    let b = if obj.can_sign { CK_TRUE } else { CK_FALSE };
                    set_attr(attr, &[b])
                }
                CKA_DECRYPT => {
                    let b = if obj.can_decrypt { CK_TRUE } else { CK_FALSE };
                    set_attr(attr, &[b])
                }
                CKA_VERIFY => {
                    let b = if obj.can_verify { CK_TRUE } else { CK_FALSE };
                    set_attr(attr, &[b])
                }
                CKA_ENCRYPT | CKA_SENSITIVE => {
                    let b = if attr.type_ == CKA_SENSITIVE { CK_TRUE } else { CK_FALSE };
                    set_attr(attr, &[b])
                }
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
                if obj.cls == ObjClass::PrivKey && !logged_in {
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
    _h: CK_SESSION_HANDLE,
    _m: *mut CK_MECHANISM,
    _o: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_encrypt(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_encrypt_update(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_encrypt_final(_h: CK_SESSION_HANDLE, _a: *mut CK_BYTE, _b: *mut CK_ULONG) -> CK_RV {
    not_supported!()
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
        if mech.mechanism != CKM_RSA_PKCS {
            return CKR_MECHANISM_INVALID;
        }
        let _ = logged_in;
        let Some(sess) = session_get_mut(state, h) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        sess.decrypt_active = true;
        sess.decrypt_key = h_key;
        CKR_OK
    })
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
        let slot_id = sess.slot;
        let key = sess.decrypt_key;
        let key_ref = p15::find(&state.slots[slot_id as usize].token, key)
            .map(|o| o.key_ref as u8);
        let Some(key_ref) = key_ref else {
            return CKR_KEY_HANDLE_INVALID;
        };
        let cipher = std::slice::from_raw_parts(p_enc, ul_enc_len as usize);
        let slot = &mut state.slots[slot_id as usize];
        if apdu::mse_set_decipher(&mut slot.pcsc, key_ref).is_err() {
            session_get_mut(state, h).unwrap().decrypt_active = false;
            return CKR_DEVICE_ERROR;
        }
        let mut out = [0u8; 512];
        let n = match apdu::pso_decipher(&mut slot.pcsc, cipher, &mut out) {
            Ok(n) => n,
            Err(_) => {
                session_get_mut(state, h).unwrap().decrypt_active = false;
                return CKR_FUNCTION_FAILED;
            }
        };
        session_get_mut(state, h).unwrap().decrypt_active = false;
        if p_data.is_null() {
            *pul_data_len = n as CK_ULONG;
            return CKR_OK;
        }
        if *pul_data_len < n as CK_ULONG {
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(out.as_ptr(), p_data, n);
        *pul_data_len = n as CK_ULONG;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_decrypt_update(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_decrypt_final(_h: CK_SESSION_HANDLE, _a: *mut CK_BYTE, _b: *mut CK_ULONG) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_digest_init(_h: CK_SESSION_HANDLE, _m: *mut CK_MECHANISM) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_digest(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: *mut CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_digest_update(_h: CK_SESSION_HANDLE, _a: *mut CK_BYTE, _b: CK_ULONG) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_digest_key(_h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_digest_final(_h: CK_SESSION_HANDLE, _a: *mut CK_BYTE, _b: *mut CK_ULONG) -> CK_RV {
    not_supported!()
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
            && mech.mechanism != CKM_SHA1_RSA_PKCS
            && mech.mechanism != CKM_SHA256_RSA_PKCS
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
    let to_sign = match sign_mech {
        CKM_SHA1_RSA_PKCS => {
            let hash = Sha1::digest(data);
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&hash);
            dig_buf = Some(build_digestinfo_sha1(&arr).to_vec());
            dig_buf.as_ref().unwrap().as_slice()
        }
        CKM_SHA256_RSA_PKCS => {
            let hash = Sha256::digest(data);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            dig_buf = Some(build_digestinfo_sha256(&arr).to_vec());
            dig_buf.as_ref().unwrap().as_slice()
        }
        _ => data,
    };
    let _ = dig_buf;
    let slot = &mut state.slots[slot_id as usize];
    if apdu::mse_set_dst(&mut slot.pcsc, key_ref).is_err() {
        return CKR_DEVICE_ERROR;
    }
    let mut out = [0u8; 512];
    let n = match apdu::pso_cds(&mut slot.pcsc, to_sign, &mut out) {
        Ok(n) => n,
        Err(_) => return CKR_FUNCTION_FAILED,
    };
    if p_sig.is_null() {
        unsafe {
            *pul_sig_len = n as CK_ULONG;
        }
        return CKR_OK;
    }
    unsafe {
        if *pul_sig_len < n as CK_ULONG {
            return CKR_BUFFER_TOO_SMALL;
        }
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

pub unsafe extern "C" fn c_sign_update(h: CK_SESSION_HANDLE, p_part: *mut CK_BYTE, ul_part_len: CK_ULONG) -> CK_RV {
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
    _h: CK_SESSION_HANDLE,
    _m: *mut CK_MECHANISM,
    _o: CK_OBJECT_HANDLE,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_verify(
    _h: CK_SESSION_HANDLE,
    _a: *mut CK_BYTE,
    _b: CK_ULONG,
    _c: *mut CK_BYTE,
    _d: CK_ULONG,
) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_verify_update(_h: CK_SESSION_HANDLE, _a: *mut CK_BYTE, _b: CK_ULONG) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_verify_final(_h: CK_SESSION_HANDLE, _a: *mut CK_BYTE, _b: CK_ULONG) -> CK_RV {
    not_supported!()
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

pub unsafe extern "C" fn c_seed_random(_h: CK_SESSION_HANDLE, _a: *mut CK_BYTE, _b: CK_ULONG) -> CK_RV {
    not_supported!()
}

pub unsafe extern "C" fn c_generate_random(_h: CK_SESSION_HANDLE, _a: *mut CK_BYTE, _b: CK_ULONG) -> CK_RV {
    not_supported!()
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

pub static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 40 },
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

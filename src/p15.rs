//! HiCOS card binding: token info and PKCS#15 object discovery.
//!
//! HiCOS does not expose a standard PKCS#15 application: `5015` and the usual
//! ODF/PrKDF file IDs answer `6A82`. Instead the directory files live in a
//! proprietary DF under the MF and are numbered after the ODF context tags
//! (PrKDF = `[0]` → `4100`, PuKDF = `[1]` → `4101`, CDF = `[4]` → `4104`, …).

use crate::apdu;
use crate::der::{self, DerTlv};
use crate::pcsc::PcscConn;

pub const MAX_OBJS: usize = 32;
pub const MAX_PATH: usize = 32;

const FID_HICOS_DF: u16 = 0x5030;
const FID_PRKDF: u16 = 0x4100;
const FID_PUKDF: u16 = 0x4101;
const FID_CDF: u16 = 0x4104;
const FID_DODF: u16 = 0x4107;
const FID_AODF: u16 = 0x4108;

/// Public key EFs hold one 128-byte component per record, prefixed by the
/// record number.
const PUBKEY_RECORD_LEN: usize = 129;
const PUBKEY_COMPONENT_LEN: usize = PUBKEY_RECORD_LEN - 1;
/// Offset from a key reference to the first record holding modulus bytes.
const PUBKEY_MODULUS_RECORD: u8 = 2;

// PKCS#15 keyUsageFlags bit positions.
const USAGE_ENCRYPT: u32 = 1 << 0;
const USAGE_DECRYPT: u32 = 1 << 1;
const USAGE_SIGN: u32 = 1 << 2;
const USAGE_SIGN_RECOVER: u32 = 1 << 3;
const USAGE_WRAP: u32 = 1 << 4;
const USAGE_UNWRAP: u32 = 1 << 5;
const USAGE_VERIFY: u32 = 1 << 6;
const USAGE_VERIFY_RECOVER: u32 = 1 << 7;

// PKCS#15 commonObjectFlags bit positions.
const OBJ_PRIVATE: u32 = 1 << 0;
const OBJ_MODIFIABLE: u32 = 1 << 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ObjClass {
    PrivKey,
    PubKey,
    Cert,
    Data,
}

pub struct TokenObject {
    pub handle: u64,
    pub cls: ObjClass,
    pub label: String,
    pub id: Vec<u8>,
    pub key_ref: i32,
    pub private: bool,
    pub modifiable: bool,
    pub local: bool,
    pub can_sign: bool,
    pub can_decrypt: bool,
    pub can_verify: bool,
    pub can_encrypt: bool,
    pub can_wrap: bool,
    pub can_unwrap: bool,
    pub data: Vec<u8>,
    pub subject: Vec<u8>,
    pub issuer: Vec<u8>,
    pub serial: Vec<u8>,
    pub application: String,
    pub app_oid: Vec<u8>,
    pub modulus: Vec<u8>,
    pub pubexp: Vec<u8>,
    pub modulus_bits: u64,
}

impl Default for TokenObject {
    fn default() -> Self {
        Self {
            handle: 0,
            cls: ObjClass::Cert,
            label: String::new(),
            id: Vec::new(),
            key_ref: -1,
            private: false,
            modifiable: false,
            local: false,
            can_sign: false,
            can_decrypt: false,
            can_verify: false,
            can_encrypt: false,
            can_wrap: false,
            can_unwrap: false,
            data: Vec::new(),
            subject: Vec::new(),
            issuer: Vec::new(),
            serial: Vec::new(),
            application: String::new(),
            app_oid: Vec::new(),
            modulus: Vec::new(),
            pubexp: Vec::new(),
            modulus_bits: 0,
        }
    }
}

pub struct Token {
    pub bound: bool,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub min_pin: u64,
    pub max_pin: u64,
    pub pin_ref: u8,
    pub objs: Vec<TokenObject>,
}

impl Default for Token {
    fn default() -> Self {
        Self {
            bound: false,
            label: "HiCOS PKI Smart Card".into(),
            manufacturer: "Chunghwa TeleCom Co., Ltd.".into(),
            model: "HiCOS".into(),
            serial: "0000000000000000".into(),
            min_pin: 6,
            max_pin: 8,
            pin_ref: 0x00,
            objs: Vec::new(),
        }
    }
}

/// A PKCS#15 `Path`: file path plus an optional slice of that file.
#[derive(Clone, Default)]
struct PathSpec {
    bytes: Vec<u8>,
    index: u32,
    length: usize,
}

fn trim_padding(buf: &mut Vec<u8>) {
    while matches!(buf.last(), Some(&0xFF) | Some(&0x00)) {
        buf.pop();
    }
}

fn trim_leading_zeros(v: &[u8]) -> Vec<u8> {
    let start = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    v[start..].to_vec()
}

fn copy_label(raw: &[u8]) -> String {
    let end = raw
        .iter()
        .rposition(|&b| b != 0 && b != 0xFF)
        .map_or(0, |i| i + 1);
    String::from_utf8_lossy(&raw[..end])
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn be_uint(v: &[u8]) -> u64 {
    v.iter().take(8).fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

/// Expand a DER BIT STRING into a bitmask where bit *n* is the *n*-th bit as
/// numbered by ASN.1 (most significant bit of the first content byte first).
fn bitstring_bits(t: &DerTlv<'_>) -> u32 {
    let mut bits = 0u32;
    for (i, &byte) in t.val.iter().skip(1).take(4).enumerate() {
        for j in 0..8 {
            if byte & (0x80 >> j) != 0 {
                bits |= 1 << (i * 8 + j);
            }
        }
    }
    bits
}

fn select_ef(pcsc: &mut PcscConn, path: &[u8]) -> Result<(), ()> {
    if path.is_empty() {
        return Err(());
    }
    if path.len() >= 2 && path[0] == 0x3F && path[1] == 0x00 {
        apdu::select_path(pcsc, path, true)
    } else if path.len() == 2 {
        apdu::select_fid(pcsc, ((path[0] as u16) << 8) | path[1] as u16)
    } else {
        apdu::select_path(pcsc, path, false)
    }
}

fn read_ef_path(pcsc: &mut PcscConn, path: &[u8]) -> Result<Vec<u8>, ()> {
    select_ef(pcsc, path)?;
    apdu::read_ef(pcsc)
}

fn read_ef_bytes(
    pcsc: &mut PcscConn,
    path: &[u8],
    offset: u32,
    want: usize,
) -> Result<Vec<u8>, ()> {
    select_ef(pcsc, path)?;
    let mut buf = vec![0u8; want];
    let got = apdu::read_binary(pcsc, offset, &mut buf)?;
    if got < want {
        return Err(());
    }
    Ok(buf)
}

fn select_hicos_df(pcsc: &mut PcscConn) -> Result<(), ()> {
    apdu::select_mf(pcsc)?;
    apdu::select_fid(pcsc, FID_HICOS_DF)
}

/// Offset at which the record sequence ends, or `None` if `buf` is truncated
/// mid-record and more data is needed.
fn records_end(buf: &[u8]) -> Option<usize> {
    let mut off = 0;
    while off < buf.len() {
        if buf[off] == 0x00 || buf[off] == 0xFF {
            return Some(off);
        }
        match der::next(buf, off) {
            Ok((_, next)) => off = next,
            Err(_) => return None,
        }
    }
    None
}

/// Read a directory file under the HiCOS DF. The card reports no file size on
/// SELECT, so read forward until the record sequence terminates on padding.
fn read_directory_file(pcsc: &mut PcscConn, fid: u16) -> Result<Vec<u8>, ()> {
    select_hicos_df(pcsc)?;
    apdu::select_fid(pcsc, fid)?;
    let mut buf = Vec::new();
    let mut off = 0u32;
    loop {
        let mut chunk = vec![0u8; apdu::CHUNK];
        let got = apdu::read_binary(pcsc, off, &mut chunk).unwrap_or(0);
        if got == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..got]);
        off += got as u32;
        if let Some(end) = records_end(&buf) {
            buf.truncate(end);
            break;
        }
        if got < apdu::CHUNK || buf.len() > 16 * 1024 {
            break;
        }
    }
    if buf.is_empty() {
        Err(())
    } else {
        Ok(buf)
    }
}

/// Parse `Path ::= SEQUENCE { path OCTET STRING, index INTEGER OPTIONAL,
/// length [0] INTEGER OPTIONAL }`, descending through an enclosing
/// `ObjectValue` sequence when present.
fn parse_path_spec(t: &DerTlv<'_>) -> Option<PathSpec> {
    if t.tag != 0x30 {
        return None;
    }
    let (first, mut off) = der::next(t.val, 0).ok()?;
    if first.tag == 0x30 {
        return parse_path_spec(&first);
    }
    if first.tag != 0x04 || first.val.is_empty() || first.val.len() > MAX_PATH {
        return None;
    }
    let mut spec = PathSpec {
        bytes: first.val.to_vec(),
        ..Default::default()
    };
    while off < t.val.len() {
        let Ok((el, next)) = der::next(t.val, off) else {
            break;
        };
        off = next;
        match el.tag {
            0x02 => spec.index = be_uint(el.val) as u32,
            0x80 => spec.length = be_uint(el.val) as usize,
            _ => {}
        }
    }
    Some(spec)
}

/// Split a PKCS#15 object record into its common, class and type attribute
/// groups.
fn split_entry<'a>(entry: &DerTlv<'a>) -> Option<(DerTlv<'a>, DerTlv<'a>, DerTlv<'a>)> {
    let (common, off) = der::next(entry.val, 0).ok()?;
    let (class, off) = der::next(entry.val, off).ok()?;
    let (type_attrs, _) = der::next(entry.val, off).ok()?;
    Some((common, class, type_attrs))
}

fn apply_common_attrs(t: &DerTlv<'_>, obj: &mut TokenObject) {
    let mut off = 0;
    while off < t.val.len() {
        let Ok((el, next)) = der::next(t.val, off) else {
            break;
        };
        off = next;
        match el.tag {
            0x0C | 0x13 | 0x16 => obj.label = copy_label(el.val),
            0x03 => {
                let bits = bitstring_bits(&el);
                obj.private = bits & OBJ_PRIVATE != 0;
                obj.modifiable = bits & OBJ_MODIFIABLE != 0;
            }
            _ => {}
        }
    }
}

/// Path held by the `[1] typeAttributes` field of an object record.
fn type_attrs_path(t: &DerTlv<'_>) -> Option<PathSpec> {
    let inner = der::enter(t).ok()?;
    let (value, _) = der::next(inner, 0).ok()?;
    parse_path_spec(&value)
}

/// `modulusLength` sits next to the key path inside `[1] typeAttributes`.
fn type_attrs_modulus_bits(t: &DerTlv<'_>) -> Option<u64> {
    let inner = der::enter(t).ok()?;
    let (seq, _) = der::next(inner, 0).ok()?;
    let (_, mut off) = der::next(seq.val, 0).ok()?;
    while off < seq.val.len() {
        let Ok((el, next)) = der::next(seq.val, off) else {
            break;
        };
        off = next;
        if el.tag == 0x02 {
            return Some(be_uint(el.val));
        }
    }
    None
}

struct KeyAttrs {
    id: Vec<u8>,
    usage: u32,
    key_ref: i32,
    native: bool,
}

fn parse_key_attrs(t: &DerTlv<'_>) -> KeyAttrs {
    let mut out = KeyAttrs {
        id: Vec::new(),
        usage: 0,
        key_ref: -1,
        native: false,
    };
    let mut off = 0;
    while off < t.val.len() {
        let Ok((el, next)) = der::next(t.val, off) else {
            break;
        };
        off = next;
        match el.tag {
            0x04 if out.id.is_empty() => out.id = el.val.to_vec(),
            0x03 => out.usage = bitstring_bits(&el),
            0x01 => out.native = el.val.first().copied().unwrap_or(0) != 0,
            0x02 if out.key_ref < 0 => out.key_ref = be_uint(el.val) as i32,
            _ => {}
        }
    }
    out
}

fn apply_usage(usage: u32, obj: &mut TokenObject) {
    obj.can_encrypt = usage & USAGE_ENCRYPT != 0;
    obj.can_decrypt = usage & (USAGE_DECRYPT | USAGE_UNWRAP) != 0;
    obj.can_sign = usage & (USAGE_SIGN | USAGE_SIGN_RECOVER) != 0;
    obj.can_verify = usage & (USAGE_VERIFY | USAGE_VERIFY_RECOVER) != 0;
    obj.can_wrap = usage & USAGE_WRAP != 0;
    obj.can_unwrap = usage & USAGE_UNWRAP != 0;
}

fn for_each_record<F: FnMut(&DerTlv<'_>)>(buf: &[u8], mut f: F) {
    let mut off = 0;
    while off < buf.len() {
        if buf[off] == 0x00 || buf[off] == 0xFF {
            break;
        }
        let Ok((entry, next)) = der::next(buf, off) else {
            break;
        };
        off = next;
        if entry.tag == 0x30 {
            f(&entry);
        }
    }
}

fn modulus_bit_len(m: &[u8]) -> u64 {
    let m = &m[m.iter().position(|&b| b != 0).unwrap_or(m.len())..];
    if m.is_empty() {
        return 0;
    }
    let mut bits = (m.len() * 8) as u64;
    let mut b = m[0];
    while bits > 0 && b & 0x80 == 0 {
        bits -= 1;
        b <<= 1;
    }
    bits
}

/// HiCOS stores key components as 32-bit words in reverse order.
fn reverse_words(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut end = raw.len();
    while end >= 4 {
        out.extend_from_slice(&raw[end - 4..end]);
        end -= 4;
    }
    out.extend_from_slice(&raw[..end]);
    out
}

fn extract_rsa_from_spki(spki: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let (seq, _) = der::next(spki, 0)?;
    if seq.tag != 0x30 {
        return Err(());
    }
    let (_alg, off) = der::next(seq.val, 0)?;
    let (bits, _) = der::next(seq.val, off)?;
    if bits.tag != 0x03 {
        return Err(());
    }
    let (rsa, _) = der::next(der::get_bytes(&bits)?, 0)?;
    if rsa.tag != 0x30 {
        return Err(());
    }
    let (modulus, off) = der::next(rsa.val, 0)?;
    let (exponent, _) = der::next(rsa.val, off)?;
    if modulus.tag != 0x02 || exponent.tag != 0x02 {
        return Err(());
    }
    Ok((
        trim_leading_zeros(modulus.val),
        trim_leading_zeros(exponent.val),
    ))
}

/// Pull subject, issuer, serial number and RSA public key out of an X.509
/// certificate.
fn parse_cert_fields(cert: &[u8], obj: &mut TokenObject) {
    let Ok((top, _)) = der::next(cert, 0) else {
        return;
    };
    let Ok((tbs, _)) = der::next(top.val, 0) else {
        return;
    };
    if tbs.tag != 0x30 {
        return;
    }
    let body = tbs.val;
    let mut off = 0;
    if body.first() == Some(&0xA0) {
        let Ok((_, next)) = der::next(body, 0) else {
            return;
        };
        off = next;
    }
    let mut fields = Vec::with_capacity(6);
    while off < body.len() && fields.len() < 6 {
        let Ok((el, next)) = der::next(body, off) else {
            break;
        };
        fields.push(el);
        off = next;
    }
    if fields.len() < 6 {
        return;
    }
    obj.serial = fields[0].full_slice(body).to_vec();
    obj.issuer = fields[2].full_slice(body).to_vec();
    obj.subject = fields[4].full_slice(body).to_vec();
    if let Ok((modulus, exponent)) = extract_rsa_from_spki(fields[5].full_slice(body)) {
        obj.modulus_bits = modulus_bit_len(&modulus);
        obj.modulus = modulus;
        obj.pubexp = exponent;
    }
}

/// Read the slice of a file described by a PKCS#15 path and trim it to the
/// DER object it starts with.
fn read_object_value(pcsc: &mut PcscConn, spec: &PathSpec) -> Option<Vec<u8>> {
    select_ef(pcsc, &spec.bytes).ok()?;
    let want = if spec.length > 0 { spec.length } else { 4096 };
    let mut raw = apdu::read_binary_range(pcsc, spec.index, want).ok()?;
    if let Ok((t, _)) = der::next(&raw, 0) {
        raw.truncate(t.hdr_len + t.val.len());
    } else {
        trim_padding(&mut raw);
    }
    if raw.is_empty() {
        None
    } else {
        Some(raw)
    }
}

/// Read an RSA public key from the record-structured key EF. Record
/// `key_ref` holds the exponent, `key_ref + 2` onwards the modulus.
fn read_pubkey_records(
    pcsc: &mut PcscConn,
    spec: &PathSpec,
    key_ref: u8,
    modulus_bytes: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
    select_ef(pcsc, &spec.bytes).ok()?;
    let exponent_rec = apdu::read_record(pcsc, key_ref, PUBKEY_RECORD_LEN).ok()?;
    let mut raw = Vec::with_capacity(modulus_bytes);
    let mut record = key_ref.checked_add(PUBKEY_MODULUS_RECORD)?;
    while raw.len() < modulus_bytes {
        let chunk = apdu::read_record(pcsc, record, PUBKEY_RECORD_LEN).ok()?;
        if chunk.len() <= 1 {
            return None;
        }
        raw.extend_from_slice(&chunk[1..]);
        record = record.checked_add(1)?;
    }
    raw.truncate(modulus_bytes);
    let exponent = trim_leading_zeros(exponent_rec.get(1..5)?);
    if exponent.is_empty() {
        return None;
    }
    Some((reverse_words(&raw), exponent))
}

fn parse_prkdf(tok: &mut Token, buf: &[u8]) {
    for_each_record(buf, |entry| {
        if tok.objs.len() >= MAX_OBJS {
            return;
        }
        let Some((common, class, _)) = split_entry(entry) else {
            return;
        };
        let attrs = parse_key_attrs(&class);
        let mut obj = TokenObject {
            handle: (tok.objs.len() + 1) as u64,
            cls: ObjClass::PrivKey,
            id: attrs.id,
            key_ref: attrs.key_ref,
            private: true,
            local: true,
            ..Default::default()
        };
        apply_common_attrs(&common, &mut obj);
        apply_usage(attrs.usage, &mut obj);
        obj.private = true;
        tok.objs.push(obj);
    });
}

fn parse_pukdf(pcsc: &mut PcscConn, tok: &mut Token, buf: &[u8]) {
    let mut pending = Vec::new();
    for_each_record(buf, |entry| {
        if tok.objs.len() + pending.len() >= MAX_OBJS {
            return;
        }
        let Some((common, class, type_attrs)) = split_entry(entry) else {
            return;
        };
        let attrs = parse_key_attrs(&class);
        let mut obj = TokenObject {
            handle: 0,
            cls: ObjClass::PubKey,
            id: attrs.id,
            key_ref: attrs.key_ref,
            local: attrs.native,
            modulus_bits: type_attrs_modulus_bits(&type_attrs).unwrap_or(0),
            ..Default::default()
        };
        apply_common_attrs(&common, &mut obj);
        apply_usage(attrs.usage, &mut obj);
        pending.push((obj, type_attrs_path(&type_attrs)));
    });

    for (mut obj, path) in pending {
        if let (Some(spec), true) = (path, obj.key_ref >= 0) {
            let want = (obj.modulus_bits / 8) as usize;
            let want = if want == 0 {
                PUBKEY_COMPONENT_LEN * 2
            } else {
                want
            };
            if let Some((modulus, exponent)) =
                read_pubkey_records(pcsc, &spec, obj.key_ref as u8, want)
            {
                obj.modulus_bits = modulus_bit_len(&modulus);
                obj.modulus = modulus;
                obj.pubexp = exponent;
            }
        }
        obj.handle = (tok.objs.len() + 1) as u64;
        tok.objs.push(obj);
    }
}

fn parse_cdf(pcsc: &mut PcscConn, tok: &mut Token, buf: &[u8]) {
    let mut pending = Vec::new();
    for_each_record(buf, |entry| {
        if tok.objs.len() + pending.len() >= MAX_OBJS {
            return;
        }
        let Some((common, class, type_attrs)) = split_entry(entry) else {
            return;
        };
        let attrs = parse_key_attrs(&class);
        let mut obj = TokenObject {
            handle: 0,
            cls: ObjClass::Cert,
            id: attrs.id,
            ..Default::default()
        };
        apply_common_attrs(&common, &mut obj);
        pending.push((obj, type_attrs_path(&type_attrs)));
    });

    for (mut obj, path) in pending {
        if let Some(spec) = path {
            if let Some(value) = read_object_value(pcsc, &spec) {
                parse_cert_fields(&value, &mut obj);
                obj.data = value;
            }
        }
        obj.handle = (tok.objs.len() + 1) as u64;
        tok.objs.push(obj);
    }
}

fn parse_dodf(pcsc: &mut PcscConn, tok: &mut Token, buf: &[u8]) {
    let mut pending = Vec::new();
    for_each_record(buf, |entry| {
        if tok.objs.len() + pending.len() >= MAX_OBJS {
            return;
        }
        let Some((common, class, type_attrs)) = split_entry(entry) else {
            return;
        };
        let mut obj = TokenObject {
            handle: 0,
            cls: ObjClass::Data,
            ..Default::default()
        };
        apply_common_attrs(&common, &mut obj);
        let mut off = 0;
        while off < class.val.len() {
            let Ok((el, next)) = der::next(class.val, off) else {
                break;
            };
            off = next;
            match el.tag {
                0x0C | 0x13 | 0x16 => obj.application = copy_label(el.val),
                0x06 => obj.app_oid = el.val.to_vec(),
                _ => {}
            }
        }
        pending.push((obj, type_attrs_path(&type_attrs)));
    });

    for (mut obj, path) in pending {
        if let Some(spec) = path {
            if let Some(value) = read_object_value(pcsc, &spec) {
                obj.data = value;
            }
        }
        obj.handle = (tok.objs.len() + 1) as u64;
        tok.objs.push(obj);
    }
}

/// The AODF carries the PIN reference used by VERIFY.
fn parse_aodf_pin(buf: &[u8]) -> Option<u8> {
    fn walk(buf: &[u8]) -> Option<u8> {
        let mut off = 0;
        while off < buf.len() {
            if buf[off] == 0x00 || buf[off] == 0xFF {
                break;
            }
            let Ok((t, next)) = der::next(buf, off) else {
                break;
            };
            off = next;
            if t.tag == 0x02 && t.val.len() == 1 {
                return Some(t.val[0]);
            }
            if t.tag & 0x20 != 0 {
                if let Some(pin_ref) = walk(t.val) {
                    return Some(pin_ref);
                }
            }
        }
        None
    }
    walk(buf)
}

fn parse_tokeninfo(buf: &[u8], tok: &mut Token) -> Result<(), ()> {
    let (seq, _) = der::next(buf, 0)?;
    if seq.tag != 0x30 {
        return Err(());
    }
    let mut man_done = false;
    let mut lbl_done = false;
    let mut off = 0;
    while off < seq.val.len() {
        let (t, next) = der::next(seq.val, off)?;
        off = next;
        if t.tag == 0x0C || t.tag == 0x13 || t.tag == 0x16 {
            if !man_done {
                tok.manufacturer = copy_label(t.val);
                man_done = true;
            } else if !lbl_done {
                tok.label = copy_label(t.val);
                lbl_done = true;
            }
        } else if t.tag == 0x80 {
            tok.label = copy_label(t.val);
            lbl_done = true;
        }
    }
    if tok.label.is_empty() {
        tok.label = "HiCOS PKI Smart Card".into();
    }
    if tok.manufacturer.is_empty() {
        tok.manufacturer = "Chunghwa TeleCom Co., Ltd.".into();
    }
    Ok(())
}

fn read_hicos_tokeninfo_ef(pcsc: &mut PcscConn, tok: &mut Token) {
    const PATH: &[u8] = &[0x3F, 0x00, 0x50, 0x30, 0x50, 0x32];
    if let Ok(mut blob) = read_ef_path(pcsc, PATH) {
        trim_padding(&mut blob);
        let _ = parse_tokeninfo(&blob, tok);
    }
}

fn read_hicos_card_number(pcsc: &mut PcscConn, tok: &mut Token) {
    const PATH: &[u8] = &[0x3F, 0x00, 0x09, 0x00, 0x09, 0x03];
    if let Ok(buf) = read_ef_bytes(pcsc, PATH, 0, 16) {
        let serial = copy_label(&buf);
        if !serial.is_empty() {
            tok.serial = serial;
        }
    }
}

fn read_hicos_model(pcsc: &mut PcscConn, tok: &mut Token) {
    const PATH: &[u8] = &[0x3F, 0x00, 0x09, 0x00, 0x09, 0x05];
    if let Ok(buf) = read_ef_bytes(pcsc, PATH, 0, 24) {
        let version = String::from_utf8_lossy(&buf);
        tok.model = if version.contains("V32") {
            "T7S".into()
        } else {
            "HiCOS".into()
        };
    }
}

fn read_objects(pcsc: &mut PcscConn, tok: &mut Token) {
    if let Ok(buf) = read_directory_file(pcsc, FID_AODF) {
        if let Some(pin_ref) = parse_aodf_pin(&buf) {
            tok.pin_ref = pin_ref;
        }
    }
    if let Ok(buf) = read_directory_file(pcsc, FID_PRKDF) {
        parse_prkdf(tok, &buf);
    }
    if let Ok(buf) = read_directory_file(pcsc, FID_PUKDF) {
        parse_pukdf(pcsc, tok, &buf);
    }
    if let Ok(buf) = read_directory_file(pcsc, FID_CDF) {
        parse_cdf(pcsc, tok, &buf);
    }
    if let Ok(buf) = read_directory_file(pcsc, FID_DODF) {
        parse_dodf(pcsc, tok, &buf);
    }
}

/// Private keys carry no public material on the card; take it from the public
/// key or certificate sharing their identifier.
fn link_key_material(tok: &mut Token) {
    for i in 0..tok.objs.len() {
        if tok.objs[i].cls != ObjClass::PrivKey || !tok.objs[i].modulus.is_empty() {
            continue;
        }
        let id = tok.objs[i].id.clone();
        if id.is_empty() {
            continue;
        }
        let source = tok
            .objs
            .iter()
            .find(|o| {
                o.id == id
                    && !o.modulus.is_empty()
                    && matches!(o.cls, ObjClass::PubKey | ObjClass::Cert)
            })
            .map(|o| (o.modulus.clone(), o.pubexp.clone(), o.modulus_bits));
        if let Some((modulus, pubexp, bits)) = source {
            tok.objs[i].modulus = modulus;
            tok.objs[i].pubexp = pubexp;
            tok.objs[i].modulus_bits = bits;
        }
    }
}

pub fn bind(pcsc: &mut PcscConn, tok: &mut Token) -> Result<(), ()> {
    *tok = Token::default();
    let _ = apdu::select_mf(pcsc);
    read_hicos_tokeninfo_ef(pcsc, tok);
    read_hicos_card_number(pcsc, tok);
    read_hicos_model(pcsc, tok);
    read_objects(pcsc, tok);
    link_key_material(tok);
    tok.bound = true;
    Ok(())
}

pub fn find(tok: &Token, handle: u64) -> Option<&TokenObject> {
    tok.objs.iter().find(|o| o.handle == handle)
}

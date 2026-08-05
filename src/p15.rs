//! PKCS#15 bind and object discovery.

use crate::apdu::{self, AID_PKCS15, AID_PKI};
use crate::der::{self, DerTlv};
use crate::pcsc::PcscConn;

pub const MAX_OBJS: usize = 32;
pub const MAX_LABEL: usize = 64;
pub const MAX_ID: usize = 32;
pub const MAX_PATH: usize = 32;

const FID_PKCS15_DF: u16 = 0x5015;
const FID_ODF: u16 = 0x5031;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ObjClass {
    PrivKey,
    PubKey,
    Cert,
}

pub struct TokenObject {
    pub handle: u64,
    pub cls: ObjClass,
    pub label: String,
    pub id: Vec<u8>,
    pub key_ref: i32,
    pub can_sign: bool,
    pub can_decrypt: bool,
    pub can_verify: bool,
    pub data: Vec<u8>,
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
            can_sign: false,
            can_decrypt: false,
            can_verify: false,
            data: Vec::new(),
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

struct Path {
    bytes: Vec<u8>,
}

fn trim_ff(buf: &mut Vec<u8>) {
    while buf.last() == Some(&0xFF) {
        buf.pop();
    }
}

fn copy_label(raw: &[u8]) -> String {
    raw.iter()
        .filter(|&&c| c >= 0x20 || (c & 0x80) != 0)
        .map(|&c| c as char)
        .collect()
}

fn trim_label(s: &mut String) {
    while s.ends_with(' ') || s.ends_with('\t') {
        s.pop();
    }
}

fn select_ef(pcsc: &mut PcscConn, path: &Path) -> Result<(), ()> {
    if path.bytes.is_empty() {
        return Err(());
    }
    if path.bytes.len() >= 2 && path.bytes[0] == 0x3F && path.bytes[1] == 0x00 {
        apdu::select_path(pcsc, &path.bytes, true)
    } else if path.bytes.len() == 2 {
        let fid = ((path.bytes[0] as u16) << 8) | path.bytes[1] as u16;
        apdu::select_fid(pcsc, fid)
    } else {
        apdu::select_path(pcsc, &path.bytes, false)
    }
}

fn read_ef_path(pcsc: &mut PcscConn, path: &Path) -> Result<Vec<u8>, ()> {
    select_ef(pcsc, path)?;
    apdu::read_ef(pcsc)
}

fn read_ef_bytes(pcsc: &mut PcscConn, path: &[u8], offset: u32, want: usize) -> Result<Vec<u8>, ()> {
    select_ef(pcsc, &Path { bytes: path.to_vec() })?;
    let mut buf = vec![0u8; want];
    let got = apdu::read_binary(pcsc, offset, &mut buf)?;
    if got < want {
        return Err(());
    }
    Ok(buf)
}

fn parse_path_tlv(t: &DerTlv<'_>) -> Result<Path, ()> {
    if t.tag == 0x04 {
        if t.val.is_empty() || t.val.len() > MAX_PATH {
            return Err(());
        }
        return Ok(Path {
            bytes: t.val.to_vec(),
        });
    }
    if t.tag != 0x30 {
        return Err(());
    }
    let inner = der::enter(t)?;
    let (os, _) = der::next(inner, 0)?;
    if os.tag != 0x04 || os.val.is_empty() || os.val.len() > MAX_PATH {
        return Err(());
    }
    Ok(Path {
        bytes: os.val.to_vec(),
    })
}

fn parse_odf(
    buf: &[u8],
) -> Result<(Path, Path, Path, Path), ()> {
    let mut prkdf = Path { bytes: vec![] };
    let mut pukdf = Path { bytes: vec![] };
    let mut cdf = Path { bytes: vec![] };
    let mut aodf = Path { bytes: vec![] };
    let mut off = 0;
    while off < buf.len() {
        if buf[off] == 0x00 || buf[off] == 0xFF {
            break;
        }
        let (t, noff) = der::next(buf, off).map_err(|_| ())?;
        off = noff;
        if !(t.tag & 0xA0 != 0 || t.tag == 0xA0) && t.tag < 0xA0 {
            continue;
        }
        let inner = der::enter(&t).map_err(|_| ())?;
        let (inner_t, _) = der::next(inner, 0).map_err(|_| ())?;
        let path = parse_path_tlv(&inner_t).map_err(|_| ())?;
        match t.tag {
            0xA0 => prkdf = path,
            0xA1 => pukdf = path,
            0xA4 | 0xA5 | 0xA6 if cdf.bytes.is_empty() => cdf = path,
            0xA8 => aodf = path,
            _ => {}
        }
    }
    if prkdf.bytes.is_empty() && cdf.bytes.is_empty() {
        Err(())
    } else {
        Ok((prkdf, pukdf, cdf, aodf))
    }
}

fn scan_key_attrs(
    data: &[u8],
    id: &mut Vec<u8>,
    key_ref: &mut i32,
    can_sign: &mut bool,
    can_decrypt: &mut bool,
) {
    let mut off = 0;
    while off < data.len() {
        let Ok((t, noff)) = der::next(data, off) else {
            break;
        };
        off = noff;
        if t.tag == 0x30 {
            scan_key_attrs(t.val, id, key_ref, can_sign, can_decrypt);
        } else if t.tag == 0x04 && id.is_empty() && !t.val.is_empty() && t.val.len() <= MAX_ID {
            id.extend_from_slice(t.val);
        } else if t.tag == 0x02 && *key_ref < 0 && !t.val.is_empty() {
            let mut v = 0i32;
            for &b in t.val {
                v = (v << 8) | b as i32;
            }
            if (0..=0xFF).contains(&v) {
                *key_ref = v;
            }
        } else if t.tag == 0x03 && t.val.len() >= 2 {
            *can_sign = true;
            *can_decrypt = true;
        }
    }
}

fn extract_rsa_from_spki(spki: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let (seq, mut off) = der::next(spki, 0)?;
    if seq.tag != 0x30 {
        return Err(());
    }
    let end = spki.len();
    let (_, noff) = der::next(spki, off)?;
    off = noff;
    let (bits, _) = der::next(spki, off)?;
    if bits.tag != 0x03 {
        return Err(());
    }
    let bp = der::get_bytes(&bits)?;
    let (rsa, mut roff) = der::next(bp, 0)?;
    if rsa.tag != 0x30 {
        return Err(());
    }
    let (n, noff2) = der::next(rsa.val, 0)?;
    if n.tag != 0x02 {
        return Err(());
    }
    let (e, _) = der::next(rsa.val, noff2)?;
    if e.tag != 0x02 {
        return Err(());
    }
    let _ = end;
    Ok((n.val.to_vec(), e.val.to_vec()))
}

fn modulus_bit_len(m: &[u8]) -> u64 {
    let mut m = m;
    while !m.is_empty() && m[0] == 0 {
        m = &m[1..];
    }
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

fn cert_get_rsa(cert: &[u8], obj: &mut TokenObject) -> Result<(), ()> {
    let (top, mut off) = der::next(cert, 0)?;
    if top.tag != 0x30 {
        return Err(());
    }
    let (tbs, noff) = der::next(cert, off)?;
    off = noff;
    if tbs.tag != 0x30 {
        return Err(());
    }
    let mut c = tbs.val;
    let end = tbs.val.len();
    let has_ver = !c.is_empty() && c[0] == 0xA0;
    let mut idx = 0;
    let mut coff = 0;
    while coff < end {
        let (t, noff2) = der::next(c, coff)?;
        coff = noff2;
        if (!has_ver && idx == 5) || (has_ver && idx == 6) {
            let spki_start = t.val.as_ptr() as usize - cert.as_ptr() as usize - t.hdr_len;
            let spki = &cert[spki_start..spki_start + t.hdr_len + t.val.len()];
            let (modulus, exp) = extract_rsa_from_spki(spki)?;
            obj.modulus = modulus;
            obj.pubexp = exp;
            obj.modulus_bits = modulus_bit_len(&obj.modulus);
            return Ok(());
        }
        idx += 1;
    }
    let _ = off;
    Err(())
}

fn load_cert_value(pcsc: &mut PcscConn, path: &Path, obj: &mut TokenObject) -> Result<(), ()> {
    let mut raw = read_ef_path(pcsc, path)?;
    trim_ff(&mut raw);
    if let Ok((cert, _)) = der::next(&raw, 0) {
        if cert.tag == 0x30 {
            let start = cert.val.as_ptr() as usize - raw.as_ptr() as usize - cert.hdr_len;
            obj.data = raw[start..start + cert.hdr_len + cert.val.len()].to_vec();
        } else {
            obj.data = raw;
        }
    } else {
        obj.data = raw;
    }
    let data = obj.data.clone();
    let _ = cert_get_rsa(&data, obj);
    Ok(())
}

fn parse_tokeninfo(buf: &[u8], tok: &mut Token) -> Result<(), ()> {
    let (seq, _) = der::next(buf, 0)?;
    if seq.tag != 0x30 {
        return Err(());
    }
    let mut man_done = false;
    let mut lbl_done = false;
    let mut poff = 0;
    while poff < seq.val.len() {
        let (t, noff) = der::next(seq.val, poff)?;
        poff = noff;
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
    trim_label(&mut tok.label);
    trim_label(&mut tok.manufacturer);
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
    if let Ok(mut blob) = read_ef_path(pcsc, &Path { bytes: PATH.to_vec() }) {
        trim_ff(&mut blob);
        let _ = parse_tokeninfo(&blob, tok);
    }
}

fn read_hicos_card_number(pcsc: &mut PcscConn, tok: &mut Token) {
    const PATH: &[u8] = &[0x3F, 0x00, 0x09, 0x00, 0x09, 0x03];
    if let Ok(buf) = read_ef_bytes(pcsc, PATH, 0, 16) {
        let n = buf
            .iter()
            .rposition(|&b| b != 0 && b != 0xFF && b != b' ')
            .map(|i| i + 1)
            .unwrap_or(0);
        let s = copy_label(&buf[..n]);
        if !s.is_empty() {
            tok.serial = s;
        }
    }
}

fn read_hicos_model(pcsc: &mut PcscConn, tok: &mut Token) {
    const PATH: &[u8] = &[0x3F, 0x00, 0x09, 0x00, 0x09, 0x05];
    if let Ok(buf) = read_ef_bytes(pcsc, PATH, 0, 24) {
        let ver = String::from_utf8_lossy(&buf);
        tok.model = if ver.contains("V32") {
            "T7S".into()
        } else {
            "HiCOS".into()
        };
    }
}

fn parse_dir_label_path(buf: &[u8]) -> Option<Path> {
    let mut off = 0;
    while off < buf.len() {
        if buf[off] == 0xFF || buf[off] == 0x00 {
            break;
        }
        let Ok((app, noff)) = der::next(buf, off) else {
            break;
        };
        off = noff;
        if app.tag != 0x61 {
            continue;
        }
        let mut c = 0;
        let mut app_path = Path { bytes: vec![] };
        while c < app.val.len() {
            let Ok((t, cnoff)) = der::next(app.val, c) else {
                break;
            };
            c = cnoff;
            if t.tag == 0x51 && t.val.len() >= 2 && t.val.len() <= MAX_PATH {
                app_path.bytes = t.val.to_vec();
            }
        }
        if !app_path.bytes.is_empty() {
            return Some(app_path);
        }
    }
    None
}

fn ensure_pkcs15_df(pcsc: &mut PcscConn) -> Result<(), ()> {
    apdu::select_mf(pcsc)?;
    let dir_path = Path {
        bytes: vec![0x2F, 0x00],
    };
    if let Ok(mut dir) = read_ef_path(pcsc, &dir_path) {
        trim_ff(&mut dir);
        if let Some(app_path) = parse_dir_label_path(&dir) {
            if apdu::select_path(pcsc, &app_path.bytes, true).is_ok() {
                return Ok(());
            }
        }
    }
    let _ = apdu::select_mf(pcsc);
    if apdu::select_aid(pcsc, AID_PKCS15).is_ok() {
        return Ok(());
    }
    let _ = apdu::select_mf(pcsc);
    if apdu::select_fid(pcsc, FID_PKCS15_DF).is_ok() {
        return Ok(());
    }
    let _ = apdu::select_mf(pcsc);
    if apdu::select_fid(pcsc, 0x0900).is_ok() {
        return Ok(());
    }
    let _ = apdu::select_mf(pcsc);
    if apdu::select_aid(pcsc, AID_PKI).is_ok() {
        return Ok(());
    }
    apdu::select_mf(pcsc)
}

fn parse_aodf_pin(buf: &[u8]) -> u8 {
    fn walk(buf: &[u8]) -> Option<u8> {
        let mut off = 0;
        while off < buf.len() {
            if buf[off] == 0x00 || buf[off] == 0xFF {
                break;
            }
            let Ok((t, noff)) = der::next(buf, off) else {
                break;
            };
            off = noff;
            if t.tag == 0x02 && t.val.len() == 1 {
                return Some(t.val[0]);
            }
            if t.tag & 0x20 != 0 {
                if let Some(pr) = walk(t.val) {
                    return Some(pr);
                }
            }
        }
        None
    }
    walk(buf).unwrap_or(0x00)
}

fn parse_prkdf(pcsc: &mut PcscConn, tok: &mut Token, buf: &[u8]) {
    let mut off = 0;
    while off < buf.len() {
        if buf[off] == 0x00 || buf[off] == 0xFF {
            break;
        }
        let Ok((choice, noff)) = der::next(buf, off) else {
            break;
        };
        off = noff;
        let Ok(inner) = der::enter(&choice) else {
            continue;
        };
        let Ok((seq, _)) = der::next(inner, 0) else {
            continue;
        };
        if seq.tag != 0x30 {
            continue;
        }
        if tok.objs.len() >= MAX_OBJS {
            break;
        }
        let idx = tok.objs.len();
        let mut obj = TokenObject {
            handle: (idx + 1) as u64,
            cls: ObjClass::PrivKey,
            label: format!("Private Key {}", idx + 1),
            can_sign: true,
            can_decrypt: true,
            ..Default::default()
        };
        let mut q = 0;
        while q < seq.val.len() {
            let Ok((common, qnoff)) = der::next(seq.val, q) else {
                break;
            };
            q = qnoff;
            if common.tag == 0x30 {
                let mut cc = 0;
                while cc < common.val.len() {
                    let Ok((lab, cnoff)) = der::next(common.val, cc) else {
                        break;
                    };
                    cc = cnoff;
                    if lab.tag == 0x0C || lab.tag == 0x13 || lab.tag == 0x16 {
                        obj.label = copy_label(lab.val);
                    }
                }
            } else {
                let start = common.val.as_ptr() as usize - buf.as_ptr() as usize - common.hdr_len;
                scan_key_attrs(
                    &buf[start..],
                    &mut obj.id,
                    &mut obj.key_ref,
                    &mut obj.can_sign,
                    &mut obj.can_decrypt,
                );
            }
        }
        if obj.key_ref < 0 {
            obj.key_ref = if idx == 0 { 0x01 } else { 0x01 + idx as i32 };
        }
        let _ = pcsc;
        tok.objs.push(obj);
    }
}

fn parse_cdf(pcsc: &mut PcscConn, tok: &mut Token, buf: &[u8]) {
    let mut off = 0;
    while off < buf.len() {
        if buf[off] == 0x00 || buf[off] == 0xFF {
            break;
        }
        let Ok((choice, noff)) = der::next(buf, off) else {
            break;
        };
        off = noff;
        let Ok(inner) = der::enter(&choice) else {
            continue;
        };
        let Ok((seq, _)) = der::next(inner, 0) else {
            continue;
        };
        if seq.tag != 0x30 || tok.objs.len() >= MAX_OBJS {
            continue;
        }
        let idx = tok.objs.len();
        let mut obj = TokenObject {
            handle: (idx + 1) as u64,
            cls: ObjClass::Cert,
            label: format!("Certificate {}", idx + 1),
            can_verify: true,
            ..Default::default()
        };
        let mut q = 0;
        let mut have_path = None::<Path>;
        while q < seq.val.len() {
            let Ok((t, qnoff)) = der::next(seq.val, q) else {
                break;
            };
            q = qnoff;
            if t.tag == 0x30 {
                let mut cc = 0;
                while cc < t.val.len() {
                    let Ok((lab, cnoff)) = der::next(t.val, cc) else {
                        break;
                    };
                    cc = cnoff;
                    if lab.tag == 0x0C || lab.tag == 0x13 || lab.tag == 0x16 {
                        obj.label = copy_label(lab.val);
                    }
                }
            } else {
                scan_key_attrs(t.val, &mut obj.id, &mut obj.key_ref, &mut false, &mut false);
                let mut u = 0;
                while u < t.val.len() {
                    let Ok((v, vnoff)) = der::next(t.val, u) else {
                        break;
                    };
                    u = vnoff;
                    if v.tag == 0xA0 || v.tag == 0xA1 {
                        let mut x = 0;
                        if let Ok((inner, _)) = der::next(v.val, x) {
                            if let Ok(p) = parse_path_tlv(&inner) {
                                have_path = Some(p);
                            }
                        }
                    } else if v.tag == 0x30 || v.tag == 0x04 {
                        if let Ok(p) = parse_path_tlv(&v) {
                            have_path = Some(p);
                        }
                    }
                }
                if have_path.is_none() {
                    if let Ok(p) = parse_path_tlv(&t) {
                        have_path = Some(p);
                    }
                }
            }
        }
        if let Some(ref path) = have_path {
            let _ = load_cert_value(pcsc, path, &mut obj);
        }
        if !obj.modulus.is_empty() {
            let pki = tok.objs.len();
            tok.objs.push(TokenObject {
                handle: (pki + 1) as u64,
                cls: ObjClass::PubKey,
                label: format!("{} (Public Key)", obj.label),
                id: obj.id.clone(),
                can_verify: true,
                modulus: obj.modulus.clone(),
                pubexp: obj.pubexp.clone(),
                modulus_bits: obj.modulus_bits,
                ..Default::default()
            });
        }
        tok.objs.push(obj);
    }
}

pub fn bind(pcsc: &mut PcscConn, tok: &mut Token) -> Result<(), ()> {
    *tok = Token::default();
    let _ = apdu::select_mf(pcsc);
    read_hicos_tokeninfo_ef(pcsc, tok);
    read_hicos_card_number(pcsc, tok);
    read_hicos_model(pcsc, tok);
    ensure_pkcs15_df(pcsc)?;

    let odf_path = Path {
        bytes: vec![(FID_ODF >> 8) as u8, (FID_ODF & 0xFF) as u8],
    };
    let _ = ensure_pkcs15_df(pcsc);
    let mut prkdf = Path { bytes: vec![0x44, 0x02] };
    let mut cdf = Path { bytes: vec![0x44, 0x04] };
    let mut aodf = Path { bytes: vec![0x44, 0x01] };

    if let Ok(mut odf) = read_ef_path(pcsc, &odf_path) {
        trim_ff(&mut odf);
        if let Ok((pr, _, cd, ao)) = parse_odf(&odf) {
            if !pr.bytes.is_empty() {
                prkdf = pr;
            }
            if !cd.bytes.is_empty() {
                cdf = cd;
            }
            if !ao.bytes.is_empty() {
                aodf = ao;
            }
        }
    }

    if !aodf.bytes.is_empty() {
        if ensure_pkcs15_df(pcsc).is_ok() {
            if let Ok(mut blob) = read_ef_path(pcsc, &aodf) {
                trim_ff(&mut blob);
                tok.pin_ref = parse_aodf_pin(&blob);
            }
        }
    }
    if !prkdf.bytes.is_empty() {
        if ensure_pkcs15_df(pcsc).is_ok() {
            if let Ok(mut blob) = read_ef_path(pcsc, &prkdf) {
                trim_ff(&mut blob);
                parse_prkdf(pcsc, tok, &blob);
            }
        }
    }
    if !cdf.bytes.is_empty() {
        if ensure_pkcs15_df(pcsc).is_ok() {
            if let Ok(mut blob) = read_ef_path(pcsc, &cdf) {
                trim_ff(&mut blob);
                parse_cdf(pcsc, tok, &blob);
            }
        }
    }

    for i in 0..tok.objs.len() {
        if tok.objs[i].cls != ObjClass::PrivKey {
            continue;
        }
        for j in 0..tok.objs.len() {
            if tok.objs[j].cls != ObjClass::Cert {
                continue;
            }
            if !tok.objs[i].id.is_empty()
                && tok.objs[i].id == tok.objs[j].id
                && tok.objs[i].modulus.is_empty()
                && !tok.objs[j].modulus.is_empty()
            {
                tok.objs[i].modulus = tok.objs[j].modulus.clone();
                tok.objs[i].pubexp = tok.objs[j].pubexp.clone();
                tok.objs[i].modulus_bits = tok.objs[j].modulus_bits;
            }
        }
    }

    tok.bound = true;
    Ok(())
}

pub fn find(tok: &Token, handle: u64) -> Option<&TokenObject> {
    tok.objs.iter().find(|o| o.handle == handle)
}

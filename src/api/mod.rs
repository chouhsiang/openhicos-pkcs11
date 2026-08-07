//! Stable high-level Rust API for GPKI smart cards.
//!
//! Intended for in-process use from other Rust crates (path/git dependency).
//! Card APDU traffic is serialized with a process-wide mutex. PIN material is
//! never written to logs by this module.
//!
//! The PKCS#11 `cdylib` export (`C_GetFunctionList`) is unchanged and remains
//! the path for `pkcs11-tool`.

mod pad;

use crate::apdu::{self, PinResult};
use crate::p15::{self, ObjClass, Token};
use crate::pcsc::PcscConn;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use std::sync::Mutex;

/// Default signing key CKA_ID (`SIGN`).
pub const DEFAULT_SIGN_KEY_ID: &[u8] = b"SIGN";
/// Default encryption/decryption key CKA_ID (`KEYX`).
pub const DEFAULT_DECRYPT_KEY_ID: &[u8] = b"KEYX";

static CARD_LOCK: Mutex<()> = Mutex::new(());

/// Errors from the high-level API.
#[derive(Debug)]
pub enum Error {
    NoReader,
    NoToken,
    InvalidSlot(u64),
    TokenNotRecognized,
    PinIncorrect,
    PinLocked,
    PinError,
    KeyNotFound(String),
    CertNotFound(String),
    SignFailed,
    DecryptFailed,
    UnsupportedMechanism,
    InvalidLength,
    Pcsc(String),
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoReader => write!(f, "no PC/SC reader found"),
            Self::NoToken => write!(f, "no usable GPKI token present"),
            Self::InvalidSlot(id) => write!(f, "slot {id} is invalid"),
            Self::TokenNotRecognized => write!(f, "token not recognized as a GPKI card"),
            Self::PinIncorrect => write!(f, "PIN incorrect"),
            Self::PinLocked => write!(f, "PIN locked"),
            Self::PinError => write!(f, "PIN verify failed"),
            Self::KeyNotFound(id) => write!(f, "private key not found (id={id})"),
            Self::CertNotFound(id) => write!(f, "certificate not found (id={id})"),
            Self::SignFailed => write!(f, "sign operation failed"),
            Self::DecryptFailed => write!(f, "decrypt operation failed"),
            Self::UnsupportedMechanism => write!(f, "unsupported mechanism"),
            Self::InvalidLength => write!(f, "invalid input length"),
            Self::Pcsc(msg) => write!(f, "PC/SC error: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// One bound token (reader with a recognized GPKI card).
#[derive(Clone, Debug)]
pub struct TokenInfo {
    /// Stable index among PC/SC readers (same numbering as a fresh scan).
    pub slot_id: u64,
    pub reader: String,
    pub label: String,
    pub model: String,
    pub serial: String,
}

/// Certificate on the token (HiPKI-style labels for SIGN/KEYX).
#[derive(Clone, Debug)]
pub struct Certificate {
    /// PKCS#11 `CKA_ID` (e.g. `SIGN`, `KEYX`).
    pub id: Vec<u8>,
    /// Suggested label: `cert1` for SIGN, `cert2` for KEYX.
    pub label: String,
    /// X.509 certificate DER.
    pub der: Vec<u8>,
}

/// Hash / padding mode for [`sign`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignMechanism {
    /// `CKM_SHA1-RSA-PKCS` — hash `data`, wrap DigestInfo, PKCS#1 v1.5 sign.
    Sha1RsaPkcs,
    /// `CKM_SHA256-RSA-PKCS` (default).
    Sha256RsaPkcs,
    /// `CKM_SHA384-RSA-PKCS`.
    Sha384RsaPkcs,
    /// `CKM_SHA512-RSA-PKCS`.
    Sha512RsaPkcs,
    /// `CKM_MD5-RSA-PKCS`.
    Md5RsaPkcs,
    /// `CKM_RSA-PKCS` — `data` is already DigestInfo (or other digest to pad).
    RsaPkcs,
}

impl Default for SignMechanism {
    fn default() -> Self {
        Self::Sha256RsaPkcs
    }
}

/// Padding mode for [`decrypt`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecryptPadding {
    /// `CKM_RSA-PKCS` (type-2 unpad on card/host path).
    RsaPkcs,
    /// `CKM_RSA-PKCS-OAEP` with empty label; MGF1 matches the hash.
    RsaOaep {
        hash: OaepHash,
        /// Optional OAEP label (usually empty).
        label: Vec<u8>,
    },
}

impl Default for DecryptPadding {
    fn default() -> Self {
        Self::RsaPkcs
    }
}

/// Hash algorithm for OAEP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OaepHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Default for OaepHash {
    fn default() -> Self {
        Self::Sha256
    }
}

/// Parameters for [`sign`].
pub struct SignRequest<'a> {
    /// Reader/slot index from [`list_tokens`]; `None` = first usable token.
    pub slot_id: Option<u64>,
    /// User PIN (never logged by this crate).
    pub pin: &'a str,
    /// Private key `CKA_ID`; default [`DEFAULT_SIGN_KEY_ID`] (`SIGN`).
    pub key_id: Option<&'a [u8]>,
    pub mechanism: SignMechanism,
    /// Bytes to sign (TBS / message; hashed when mechanism is `*RsaPkcs` hash modes).
    pub data: &'a [u8],
    /// When true, also return the matching certificate DER.
    pub return_certificate: bool,
}

impl fmt::Debug for SignRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignRequest")
            .field("slot_id", &self.slot_id)
            .field("pin", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("mechanism", &self.mechanism)
            .field("data_len", &self.data.len())
            .field("return_certificate", &self.return_certificate)
            .finish()
    }
}

/// Result of [`sign`].
#[derive(Clone, Debug)]
pub struct SignResponse {
    pub signature: Vec<u8>,
    pub certificate_der: Option<Vec<u8>>,
}

/// Parameters for [`decrypt`].
pub struct DecryptRequest<'a> {
    pub slot_id: Option<u64>,
    pub pin: &'a str,
    /// Private key `CKA_ID`; default [`DEFAULT_DECRYPT_KEY_ID`] (`KEYX`).
    pub key_id: Option<&'a [u8]>,
    pub padding: DecryptPadding,
    pub ciphertext: &'a [u8],
    pub return_certificate: bool,
}

impl fmt::Debug for DecryptRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptRequest")
            .field("slot_id", &self.slot_id)
            .field("pin", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("padding", &self.padding)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("return_certificate", &self.return_certificate)
            .finish()
    }
}

/// Result of [`decrypt`].
#[derive(Clone, Debug)]
pub struct DecryptResponse {
    pub plaintext: Vec<u8>,
    pub certificate_der: Option<Vec<u8>>,
}

/// List readers that currently hold a recognized GPKI token.
pub fn list_tokens() -> Result<Vec<TokenInfo>> {
    with_card_lock(|| {
        let readers = list_readers()?;
        if readers.is_empty() {
            return Err(Error::NoReader);
        }
        let mut out = Vec::new();
        for (i, reader) in readers.iter().enumerate() {
            match try_bind_reader(reader) {
                Ok((_pcsc, token)) => {
                    out.push(TokenInfo {
                        slot_id: i as u64,
                        reader: reader.clone(),
                        label: token.label,
                        model: token.model,
                        serial: token.serial,
                    });
                }
                Err(Error::TokenNotRecognized) | Err(Error::Pcsc(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        if out.is_empty() {
            Err(Error::NoToken)
        } else {
            Ok(out)
        }
    })
}

/// List certificates on a token (at least SIGN / KEYX when present).
///
/// `slot_id`: `None` selects the first usable token.
pub fn list_certificates(slot_id: Option<u64>) -> Result<Vec<Certificate>> {
    with_card_lock(|| {
        let (_reader, _pcsc, token) = open_slot(slot_id)?;
        let mut certs = Vec::new();
        for obj in &token.objs {
            if obj.cls != ObjClass::Cert || obj.data.is_empty() {
                continue;
            }
            // Prefer HiPKI-relevant certs; still expose others with a sensible label.
            let label = hipki_cert_label(&obj.id);
            certs.push(Certificate {
                id: obj.id.clone(),
                label,
                der: obj.data.clone(),
            });
        }
        Ok(certs)
    })
}

/// Verify PIN and sign `data` with the selected private key.
pub fn sign(req: SignRequest<'_>) -> Result<SignResponse> {
    with_card_lock(|| {
        let key_id = req.key_id.unwrap_or(DEFAULT_SIGN_KEY_ID);
        let (_reader, mut pcsc, token) = open_slot(req.slot_id)?;
        login(&mut pcsc, &token, req.pin)?;

        let key = token
            .objs
            .iter()
            .find(|o| {
                o.cls == ObjClass::PrivKey && o.id.as_slice() == key_id && o.can_sign && o.key_ref >= 0
            })
            .ok_or_else(|| Error::KeyNotFound(id_to_string(key_id)))?;

        let to_sign = prepare_sign_payload(req.mechanism, req.data)?;
        let mut out = [0u8; 512];
        let n = apdu::sign(&mut pcsc, key.key_ref as u8, &to_sign, &mut out)
            .map_err(|_| Error::SignFailed)?;
        if n == 0 {
            return Err(Error::SignFailed);
        }

        let certificate_der = if req.return_certificate {
            Some(find_cert_der(&token, key_id)?)
        } else {
            None
        };

        apdu::clear_auth_state();
        Ok(SignResponse {
            signature: out[..n].to_vec(),
            certificate_der,
        })
    })
}

/// Verify PIN and decrypt `ciphertext` with the selected private key.
pub fn decrypt(req: DecryptRequest<'_>) -> Result<DecryptResponse> {
    with_card_lock(|| {
        let key_id = req.key_id.unwrap_or(DEFAULT_DECRYPT_KEY_ID);
        let (_reader, mut pcsc, token) = open_slot(req.slot_id)?;
        login(&mut pcsc, &token, req.pin)?;

        let key = token
            .objs
            .iter()
            .find(|o| {
                o.cls == ObjClass::PrivKey
                    && o.id.as_slice() == key_id
                    && o.can_decrypt
                    && o.key_ref >= 0
            })
            .ok_or_else(|| Error::KeyNotFound(id_to_string(key_id)))?;

        let key_ref = key.key_ref as u8;
        let plaintext = match &req.padding {
            DecryptPadding::RsaPkcs => {
                let mut out = [0u8; 512];
                let n = apdu::decrypt(&mut pcsc, key_ref, req.ciphertext, &mut out)
                    .map_err(|_| Error::DecryptFailed)?;
                out[..n].to_vec()
            }
            DecryptPadding::RsaOaep { hash, label } => {
                if req.ciphertext.len() != 256 {
                    return Err(Error::InvalidLength);
                }
                let mut raw = [0u8; 256];
                apdu::rsa_private_op(&mut pcsc, key_ref, req.ciphertext, &mut raw)
                    .map_err(|_| Error::DecryptFailed)?;
                pad::oaep_decode(*hash, label, &raw).map_err(|_| Error::DecryptFailed)?
            }
        };

        let certificate_der = if req.return_certificate {
            Some(find_cert_der(&token, key_id)?)
        } else {
            None
        };

        apdu::clear_auth_state();
        Ok(DecryptResponse {
            plaintext,
            certificate_der,
        })
    })
}

// ---- internals ------------------------------------------------------------

fn with_card_lock<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let _guard = CARD_LOCK
        .lock()
        .map_err(|_| Error::Internal("card lock poisoned".into()))?;
    f()
}

fn list_readers() -> Result<Vec<String>> {
    let probe = PcscConn::new().map_err(|e| Error::Pcsc(e.to_string()))?;
    probe.list_readers().map_err(|e| Error::Pcsc(e.to_string()))
}

fn try_bind_reader(reader: &str) -> Result<(PcscConn, Token)> {
    apdu::reset_cla();
    apdu::clear_auth_state();
    let mut pcsc = PcscConn::new().map_err(|e| Error::Pcsc(e.to_string()))?;
    pcsc.connect(reader).map_err(|e| Error::Pcsc(e.to_string()))?;
    let mut token = Token::default();
    p15::bind(&mut pcsc, &mut token).map_err(|_| Error::TokenNotRecognized)?;
    Ok((pcsc, token))
}

fn open_slot(slot_id: Option<u64>) -> Result<(String, PcscConn, Token)> {
    let readers = list_readers()?;
    if readers.is_empty() {
        return Err(Error::NoReader);
    }

    let indices: Vec<usize> = match slot_id {
        Some(id) => {
            let i = id as usize;
            if i >= readers.len() {
                return Err(Error::InvalidSlot(id));
            }
            vec![i]
        }
        None => (0..readers.len()).collect(),
    };

    let mut last_err = Error::NoToken;
    for i in indices {
        match try_bind_reader(&readers[i]) {
            Ok((pcsc, token)) => return Ok((readers[i].clone(), pcsc, token)),
            Err(e @ Error::TokenNotRecognized) | Err(e @ Error::Pcsc(_)) => {
                last_err = e;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err)
}

fn login(pcsc: &mut PcscConn, token: &Token, pin: &str) -> Result<()> {
    if pin.is_empty() {
        return Err(Error::PinError);
    }
    match apdu::verify_pin(pcsc, token.pin_ref, pin.as_bytes()) {
        PinResult::Ok => Ok(()),
        PinResult::Incorrect => Err(Error::PinIncorrect),
        PinResult::Locked => Err(Error::PinLocked),
        PinResult::Error => Err(Error::PinError),
    }
}

fn find_cert_der(token: &Token, key_id: &[u8]) -> Result<Vec<u8>> {
    token
        .objs
        .iter()
        .find(|o| o.cls == ObjClass::Cert && o.id.as_slice() == key_id && !o.data.is_empty())
        .map(|o| o.data.clone())
        .ok_or_else(|| Error::CertNotFound(id_to_string(key_id)))
}

fn hipki_cert_label(id: &[u8]) -> String {
    match id {
        b"SIGN" => "cert1".into(),
        b"KEYX" => "cert2".into(),
        b"SIGN02" => "cert3".into(),
        other => match std::str::from_utf8(other) {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => hex::encode_upper_simple(other),
        },
    }
}

fn id_to_string(id: &[u8]) -> String {
    match std::str::from_utf8(id) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => hex::encode_upper_simple(id),
    }
}

/// Tiny hex helper (avoid adding a hex crate).
mod hex {
    pub fn encode_upper_simple(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }
}

fn prepare_sign_payload(mech: SignMechanism, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match mech {
        SignMechanism::RsaPkcs => data.to_vec(),
        SignMechanism::Md5RsaPkcs => {
            let hash = Md5::digest(data);
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&hash);
            pad::digestinfo_md5(&arr).to_vec()
        }
        SignMechanism::Sha1RsaPkcs => {
            let hash = Sha1::digest(data);
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&hash);
            pad::digestinfo_sha1(&arr).to_vec()
        }
        SignMechanism::Sha256RsaPkcs => {
            let hash = Sha256::digest(data);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            pad::digestinfo_sha256(&arr).to_vec()
        }
        SignMechanism::Sha384RsaPkcs => {
            let hash = Sha384::digest(data);
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&hash);
            pad::digestinfo_sha384(&arr).to_vec()
        }
        SignMechanism::Sha512RsaPkcs => {
            let hash = Sha512::digest(data);
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&hash);
            pad::digestinfo_sha512(&arr).to_vec()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hipki_labels() {
        assert_eq!(hipki_cert_label(b"SIGN"), "cert1");
        assert_eq!(hipki_cert_label(b"KEYX"), "cert2");
        assert_eq!(hipki_cert_label(b"SIGN02"), "cert3");
    }

    #[test]
    fn sign_request_debug_redacts_pin() {
        let req = SignRequest {
            slot_id: None,
            pin: "secret-pin",
            key_id: None,
            mechanism: SignMechanism::Sha256RsaPkcs,
            data: b"hello",
            return_certificate: false,
        };
        let s = format!("{req:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("secret-pin"));
    }

    #[test]
    fn digestinfo_sha256_prefix() {
        let dig = pad::digestinfo_sha256(&[0u8; 32]);
        assert_eq!(dig.len(), 51);
        assert_eq!(&dig[..19], &pad::DIGESTINFO_SHA256_PREFIX);
    }
}

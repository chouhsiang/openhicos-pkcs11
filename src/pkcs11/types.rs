//! Minimal PKCS#11 / Cryptoki types (subset of OASIS PKCS#11 v2.40).

pub type CK_BYTE = u8;
pub type CK_CHAR = u8;
pub type CK_UTF8CHAR = u8;
pub type CK_BBOOL = u8;
pub type CK_ULONG = u64;
pub type CK_LONG = i64;
pub type CK_FLAGS = CK_ULONG;
pub type CK_RV = CK_ULONG;
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;
pub type CK_USER_TYPE = CK_ULONG;
pub type CK_STATE = CK_ULONG;
pub type CK_KEY_TYPE = CK_ULONG;
pub type CK_CERTIFICATE_TYPE = CK_ULONG;

pub const CK_TRUE: CK_BBOOL = 1;
pub const CK_FALSE: CK_BBOOL = 0;

pub const CKR_OK: CK_RV = 0x0000_0000;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x0000_0007;
pub const CKR_ATTRIBUTE_TYPE_INVALID: CK_RV = 0x0000_0012;
pub const CKR_DATA_LEN_RANGE: CK_RV = 0x0000_0021;
pub const CKR_DEVICE_ERROR: CK_RV = 0x0000_0030;
pub const CKR_ENCRYPTED_DATA_INVALID: CK_RV = 0x0000_0040;
pub const CKR_FUNCTION_FAILED: CK_RV = 0x0000_0006;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x0000_0054;
pub const CKR_KEY_HANDLE_INVALID: CK_RV = 0x0000_0060;
pub const CKR_KEY_FUNCTION_NOT_PERMITTED: CK_RV = 0x0000_0068;
pub const CKR_MECHANISM_INVALID: CK_RV = 0x0000_0070;
pub const CKR_OBJECT_HANDLE_INVALID: CK_RV = 0x0000_0082;
pub const CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x0000_0091;
pub const CKR_PIN_INCORRECT: CK_RV = 0x0000_00A0;
pub const CKR_PIN_LOCKED: CK_RV = 0x0000_00A4;
pub const CKR_SESSION_COUNT: CK_RV = 0x0000_00B1;
pub const CKR_SESSION_HANDLE_INVALID: CK_RV = 0x0000_00B3;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CK_RV = 0x0000_00B4;
pub const CKR_SIGNATURE_INVALID: CK_RV = 0x0000_00C0;
pub const CKR_SIGNATURE_LEN_RANGE: CK_RV = 0x0000_00C1;
pub const CKR_SLOT_ID_INVALID: CK_RV = 0x0000_0003;
pub const CKR_TOKEN_NOT_PRESENT: CK_RV = 0x0000_00E0;
pub const CKR_USER_ALREADY_LOGGED_IN: CK_RV = 0x0000_0100;
pub const CKR_USER_NOT_LOGGED_IN: CK_RV = 0x0000_0101;
pub const CKR_USER_TYPE_INVALID: CK_RV = 0x0000_0103;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x0000_0190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x0000_0191;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x0000_0150;
pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = CK_ULONG::MAX;

pub const CKF_TOKEN_PRESENT: CK_FLAGS = 0x0000_0001;
pub const CKF_REMOVABLE_DEVICE: CK_FLAGS = 0x0000_0002;
pub const CKF_HW_SLOT: CK_FLAGS = 0x0000_0004;
pub const CKF_RNG: CK_FLAGS = 0x0000_0001;
pub const CKF_LOGIN_REQUIRED: CK_FLAGS = 0x0000_0004;
pub const CKF_USER_PIN_INITIALIZED: CK_FLAGS = 0x0000_0008;
pub const CKF_TOKEN_INITIALIZED: CK_FLAGS = 0x0000_0400;
pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x0000_0004;
pub const CKF_RW_SESSION: CK_FLAGS = 0x0000_0002;
pub const CKF_HW: CK_FLAGS = 0x0000_0001;
pub const CKF_ENCRYPT: CK_FLAGS = 0x0000_0100;
pub const CKF_DECRYPT: CK_FLAGS = 0x0000_0200;
pub const CKF_DIGEST: CK_FLAGS = 0x0000_0400;
pub const CKF_SIGN: CK_FLAGS = 0x0000_0800;
pub const CKF_VERIFY: CK_FLAGS = 0x0000_2000;

pub const CKU_USER: CK_USER_TYPE = 1;

pub const CKS_RO_PUBLIC_SESSION: CK_STATE = 0;
pub const CKS_RO_USER_FUNCTIONS: CK_STATE = 1;
pub const CKS_RW_PUBLIC_SESSION: CK_STATE = 2;
pub const CKS_RW_USER_FUNCTIONS: CK_STATE = 3;

pub const CKM_RSA_PKCS: CK_MECHANISM_TYPE = 0x0000_0001;
pub const CKM_RSA_X_509: CK_MECHANISM_TYPE = 0x0000_0003;
pub const CKM_MD5_RSA_PKCS: CK_MECHANISM_TYPE = 0x0000_0005;
pub const CKM_SHA1_RSA_PKCS: CK_MECHANISM_TYPE = 0x0000_0006;
pub const CKM_RSA_PKCS_OAEP: CK_MECHANISM_TYPE = 0x0000_0009;
pub const CKM_SHA256_RSA_PKCS: CK_MECHANISM_TYPE = 0x0000_0040;
pub const CKM_SHA384_RSA_PKCS: CK_MECHANISM_TYPE = 0x0000_0041;
pub const CKM_SHA512_RSA_PKCS: CK_MECHANISM_TYPE = 0x0000_0042;
pub const CKM_MD5: CK_MECHANISM_TYPE = 0x0000_0210;
pub const CKM_SHA_1: CK_MECHANISM_TYPE = 0x0000_0220;
pub const CKM_SHA256: CK_MECHANISM_TYPE = 0x0000_0250;
pub const CKM_SHA384: CK_MECHANISM_TYPE = 0x0000_0260;
pub const CKM_SHA512: CK_MECHANISM_TYPE = 0x0000_0270;

pub const CKG_MGF1_SHA1: CK_ULONG = 0x0000_0001;
pub const CKG_MGF1_SHA256: CK_ULONG = 0x0000_0002;
pub const CKG_MGF1_SHA384: CK_ULONG = 0x0000_0003;
pub const CKG_MGF1_SHA512: CK_ULONG = 0x0000_0004;
pub const CKZ_DATA_SPECIFIED: CK_ULONG = 0x0000_0001;

pub const CKA_CLASS: CK_ATTRIBUTE_TYPE = 0x0000_0000;
pub const CKA_TOKEN: CK_ATTRIBUTE_TYPE = 0x0000_0001;
pub const CKA_PRIVATE: CK_ATTRIBUTE_TYPE = 0x0000_0002;
pub const CKA_LABEL: CK_ATTRIBUTE_TYPE = 0x0000_0003;
pub const CKA_APPLICATION: CK_ATTRIBUTE_TYPE = 0x0000_0010;
pub const CKA_VALUE: CK_ATTRIBUTE_TYPE = 0x0000_0011;
pub const CKA_OBJECT_ID: CK_ATTRIBUTE_TYPE = 0x0000_0012;
pub const CKA_CERTIFICATE_TYPE: CK_ATTRIBUTE_TYPE = 0x0000_0080;
pub const CKA_ISSUER: CK_ATTRIBUTE_TYPE = 0x0000_0081;
pub const CKA_SERIAL_NUMBER: CK_ATTRIBUTE_TYPE = 0x0000_0082;
pub const CKA_KEY_TYPE: CK_ATTRIBUTE_TYPE = 0x0000_0100;
pub const CKA_SUBJECT: CK_ATTRIBUTE_TYPE = 0x0000_0101;
pub const CKA_ID: CK_ATTRIBUTE_TYPE = 0x0000_0102;
pub const CKA_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x0000_0103;
pub const CKA_ENCRYPT: CK_ATTRIBUTE_TYPE = 0x0000_0104;
pub const CKA_DECRYPT: CK_ATTRIBUTE_TYPE = 0x0000_0105;
pub const CKA_WRAP: CK_ATTRIBUTE_TYPE = 0x0000_0106;
pub const CKA_UNWRAP: CK_ATTRIBUTE_TYPE = 0x0000_0107;
pub const CKA_SIGN: CK_ATTRIBUTE_TYPE = 0x0000_0108;
pub const CKA_SIGN_RECOVER: CK_ATTRIBUTE_TYPE = 0x0000_0109;
pub const CKA_VERIFY: CK_ATTRIBUTE_TYPE = 0x0000_010A;
pub const CKA_VERIFY_RECOVER: CK_ATTRIBUTE_TYPE = 0x0000_010B;
pub const CKA_DERIVE: CK_ATTRIBUTE_TYPE = 0x0000_010C;
pub const CKA_MODULUS: CK_ATTRIBUTE_TYPE = 0x0000_0120;
pub const CKA_MODULUS_BITS: CK_ATTRIBUTE_TYPE = 0x0000_0121;
pub const CKA_PUBLIC_EXPONENT: CK_ATTRIBUTE_TYPE = 0x0000_0122;
pub const CKA_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x0000_0162;
pub const CKA_LOCAL: CK_ATTRIBUTE_TYPE = 0x0000_0163;
pub const CKA_NEVER_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x0000_0164;
pub const CKA_ALWAYS_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x0000_0165;
pub const CKA_MODIFIABLE: CK_ATTRIBUTE_TYPE = 0x0000_0170;
pub const CKA_ALWAYS_AUTHENTICATE: CK_ATTRIBUTE_TYPE = 0x0000_0202;

pub const CKO_DATA: CK_ULONG = 0x0000_0000;
pub const CKO_CERTIFICATE: CK_ULONG = 0x0000_0001;
pub const CKO_PUBLIC_KEY: CK_ULONG = 0x0000_0002;
pub const CKO_PRIVATE_KEY: CK_ULONG = 0x0000_0003;

pub const CKK_RSA: CK_KEY_TYPE = 0x0000_0000;
pub const CKC_X_509: CK_CERTIFICATE_TYPE = 0x0000_0000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_INFO {
    pub cryptokiVersion: CK_VERSION,
    pub manufacturerID: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub libraryDescription: [CK_UTF8CHAR; 32],
    pub libraryVersion: CK_VERSION,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_SLOT_INFO {
    pub slotDescription: [CK_UTF8CHAR; 64],
    pub manufacturerID: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_TOKEN_INFO {
    pub label: [CK_UTF8CHAR; 32],
    pub manufacturerID: [CK_UTF8CHAR; 32],
    pub model: [CK_UTF8CHAR; 16],
    pub serialNumber: [CK_UTF8CHAR; 16],
    pub flags: CK_FLAGS,
    pub ulMaxSessionCount: CK_ULONG,
    pub ulSessionCount: CK_ULONG,
    pub ulMaxRwSessionCount: CK_ULONG,
    pub ulRwSessionCount: CK_ULONG,
    pub ulMaxPinLen: CK_ULONG,
    pub ulMinPinLen: CK_ULONG,
    pub ulTotalPublicMemory: CK_ULONG,
    pub ulFreePublicMemory: CK_ULONG,
    pub ulTotalPrivateMemory: CK_ULONG,
    pub ulFreePrivateMemory: CK_ULONG,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
    pub utcTime: [CK_CHAR; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_SESSION_INFO {
    pub slotID: CK_SLOT_ID,
    pub state: CK_STATE,
    pub flags: CK_FLAGS,
    pub ulDeviceError: CK_ULONG,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_ATTRIBUTE {
    pub type_: CK_ATTRIBUTE_TYPE,
    pub pValue: *mut core::ffi::c_void,
    pub ulValueLen: CK_ULONG,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub pParameter: *mut core::ffi::c_void,
    pub ulParameterLen: CK_ULONG,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CK_MECHANISM_INFO {
    pub ulMinKeySize: CK_ULONG,
    pub ulMaxKeySize: CK_ULONG,
    pub flags: CK_FLAGS,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_RSA_PKCS_OAEP_PARAMS {
    pub hashAlg: CK_MECHANISM_TYPE,
    pub mgf: CK_ULONG,
    pub source: CK_ULONG,
    pub pSourceData: *mut core::ffi::c_void,
    pub ulSourceDataLen: CK_ULONG,
}

pub type CK_C_Initialize = unsafe extern "C" fn(*mut core::ffi::c_void) -> CK_RV;
pub type CK_C_Finalize = unsafe extern "C" fn(*mut core::ffi::c_void) -> CK_RV;
pub type CK_C_GetInfo = unsafe extern "C" fn(*mut CK_INFO) -> CK_RV;
pub type CK_C_GetFunctionList = unsafe extern "C" fn(*mut *const CK_FUNCTION_LIST) -> CK_RV;
pub type CK_C_GetSlotList = unsafe extern "C" fn(CK_BBOOL, *mut CK_SLOT_ID, *mut CK_ULONG) -> CK_RV;
pub type CK_C_GetSlotInfo = unsafe extern "C" fn(CK_SLOT_ID, *mut CK_SLOT_INFO) -> CK_RV;
pub type CK_C_GetTokenInfo = unsafe extern "C" fn(CK_SLOT_ID, *mut CK_TOKEN_INFO) -> CK_RV;
pub type CK_C_GetMechanismList =
    unsafe extern "C" fn(CK_SLOT_ID, *mut CK_MECHANISM_TYPE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_GetMechanismInfo =
    unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut CK_MECHANISM_INFO) -> CK_RV;
pub type CK_C_InitToken =
    unsafe extern "C" fn(CK_SLOT_ID, *mut CK_UTF8CHAR, CK_ULONG, *mut CK_UTF8CHAR) -> CK_RV;
pub type CK_C_InitPIN =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_UTF8CHAR, CK_ULONG) -> CK_RV;
pub type CK_C_SetPIN = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_UTF8CHAR,
    CK_ULONG,
    *mut CK_UTF8CHAR,
    CK_ULONG,
) -> CK_RV;
pub type CK_C_OpenSession = unsafe extern "C" fn(
    CK_SLOT_ID,
    CK_FLAGS,
    *mut core::ffi::c_void,
    Option<unsafe extern "C" fn(CK_ULONG, CK_ULONG, *mut core::ffi::c_void)>,
    *mut CK_SESSION_HANDLE,
) -> CK_RV;
pub type CK_C_CloseSession = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CloseAllSessions = unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV;
pub type CK_C_GetSessionInfo =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_SESSION_INFO) -> CK_RV;
pub type CK_C_GetOperationState =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_SetOperationState = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_Login =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, *mut CK_UTF8CHAR, CK_ULONG) -> CK_RV;
pub type CK_C_Logout = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CreateObject = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_ATTRIBUTE,
    CK_ULONG,
    *mut CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_CopyObject = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    *mut CK_ATTRIBUTE,
    CK_ULONG,
    *mut CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_DestroyObject = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_GetObjectSize =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_GetAttributeValue =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV;
pub type CK_C_SetAttributeValue =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV;
pub type CK_C_FindObjectsInit =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV;
pub type CK_C_FindObjects = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_OBJECT_HANDLE,
    CK_ULONG,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_FindObjectsFinal = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_EncryptInit =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Encrypt = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_EncryptUpdate = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_EncryptFinal =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DecryptInit =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Decrypt = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_DecryptUpdate = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_DecryptFinal =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DigestInit = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM) -> CK_RV;
pub type CK_C_Digest = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_DigestUpdate =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_DigestKey = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_DigestFinal =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_SignInit =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Sign = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_SignUpdate = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_SignFinal =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_SignRecoverInit =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_SignRecover = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_VerifyInit =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Verify = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    CK_ULONG,
) -> CK_RV;
pub type CK_C_VerifyUpdate =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_VerifyFinal =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_VerifyRecoverInit =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_VerifyRecover = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_DigestEncryptUpdate = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_DecryptDigestUpdate = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_SignEncryptUpdate = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_DecryptVerifyUpdate = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_GenerateKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_MECHANISM,
    *mut CK_ATTRIBUTE,
    CK_ULONG,
    *mut CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_GenerateKeyPair = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_MECHANISM,
    *mut CK_ATTRIBUTE,
    CK_ULONG,
    *mut CK_ATTRIBUTE,
    CK_ULONG,
    *mut CK_OBJECT_HANDLE,
    *mut CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_WrapKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    *mut CK_BYTE,
    *mut CK_ULONG,
) -> CK_RV;
pub type CK_C_UnwrapKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_MECHANISM,
    CK_OBJECT_HANDLE,
    *mut CK_BYTE,
    CK_ULONG,
    *mut CK_ATTRIBUTE,
    CK_ULONG,
    *mut CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_DeriveKey = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    *mut CK_MECHANISM,
    CK_OBJECT_HANDLE,
    *mut CK_ATTRIBUTE,
    CK_ULONG,
    *mut CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_SeedRandom = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_GenerateRandom =
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_GetFunctionStatus = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CancelFunction = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_WaitForSlotEvent =
    unsafe extern "C" fn(CK_FLAGS, *mut CK_SLOT_ID, *mut core::ffi::c_void) -> CK_RV;

#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub C_Initialize: CK_C_Initialize,
    pub C_Finalize: CK_C_Finalize,
    pub C_GetInfo: CK_C_GetInfo,
    pub C_GetFunctionList: CK_C_GetFunctionList,
    pub C_GetSlotList: CK_C_GetSlotList,
    pub C_GetSlotInfo: CK_C_GetSlotInfo,
    pub C_GetTokenInfo: CK_C_GetTokenInfo,
    pub C_GetMechanismList: CK_C_GetMechanismList,
    pub C_GetMechanismInfo: CK_C_GetMechanismInfo,
    pub C_InitToken: CK_C_InitToken,
    pub C_InitPIN: CK_C_InitPIN,
    pub C_SetPIN: CK_C_SetPIN,
    pub C_OpenSession: CK_C_OpenSession,
    pub C_CloseSession: CK_C_CloseSession,
    pub C_CloseAllSessions: CK_C_CloseAllSessions,
    pub C_GetSessionInfo: CK_C_GetSessionInfo,
    pub C_GetOperationState: CK_C_GetOperationState,
    pub C_SetOperationState: CK_C_SetOperationState,
    pub C_Login: CK_C_Login,
    pub C_Logout: CK_C_Logout,
    pub C_CreateObject: CK_C_CreateObject,
    pub C_CopyObject: CK_C_CopyObject,
    pub C_DestroyObject: CK_C_DestroyObject,
    pub C_GetObjectSize: CK_C_GetObjectSize,
    pub C_GetAttributeValue: CK_C_GetAttributeValue,
    pub C_SetAttributeValue: CK_C_SetAttributeValue,
    pub C_FindObjectsInit: CK_C_FindObjectsInit,
    pub C_FindObjects: CK_C_FindObjects,
    pub C_FindObjectsFinal: CK_C_FindObjectsFinal,
    pub C_EncryptInit: CK_C_EncryptInit,
    pub C_Encrypt: CK_C_Encrypt,
    pub C_EncryptUpdate: CK_C_EncryptUpdate,
    pub C_EncryptFinal: CK_C_EncryptFinal,
    pub C_DecryptInit: CK_C_DecryptInit,
    pub C_Decrypt: CK_C_Decrypt,
    pub C_DecryptUpdate: CK_C_DecryptUpdate,
    pub C_DecryptFinal: CK_C_DecryptFinal,
    pub C_DigestInit: CK_C_DigestInit,
    pub C_Digest: CK_C_Digest,
    pub C_DigestUpdate: CK_C_DigestUpdate,
    pub C_DigestKey: CK_C_DigestKey,
    pub C_DigestFinal: CK_C_DigestFinal,
    pub C_SignInit: CK_C_SignInit,
    pub C_Sign: CK_C_Sign,
    pub C_SignUpdate: CK_C_SignUpdate,
    pub C_SignFinal: CK_C_SignFinal,
    pub C_SignRecoverInit: CK_C_SignRecoverInit,
    pub C_SignRecover: CK_C_SignRecover,
    pub C_VerifyInit: CK_C_VerifyInit,
    pub C_Verify: CK_C_Verify,
    pub C_VerifyUpdate: CK_C_VerifyUpdate,
    pub C_VerifyFinal: CK_C_VerifyFinal,
    pub C_VerifyRecoverInit: CK_C_VerifyRecoverInit,
    pub C_VerifyRecover: CK_C_VerifyRecover,
    pub C_DigestEncryptUpdate: CK_C_DigestEncryptUpdate,
    pub C_DecryptDigestUpdate: CK_C_DecryptDigestUpdate,
    pub C_SignEncryptUpdate: CK_C_SignEncryptUpdate,
    pub C_DecryptVerifyUpdate: CK_C_DecryptVerifyUpdate,
    pub C_GenerateKey: CK_C_GenerateKey,
    pub C_GenerateKeyPair: CK_C_GenerateKeyPair,
    pub C_WrapKey: CK_C_WrapKey,
    pub C_UnwrapKey: CK_C_UnwrapKey,
    pub C_DeriveKey: CK_C_DeriveKey,
    pub C_SeedRandom: CK_C_SeedRandom,
    pub C_GenerateRandom: CK_C_GenerateRandom,
    pub C_GetFunctionStatus: CK_C_GetFunctionStatus,
    pub C_CancelFunction: CK_C_CancelFunction,
    pub C_WaitForSlotEvent: CK_C_WaitForSlotEvent,
}

pub fn fill_blank(dst: &mut [CK_UTF8CHAR], src: &str) {
    let sl = src.len().min(dst.len());
    for (i, b) in dst.iter_mut().enumerate() {
        *b = if i < sl { src.as_bytes()[i] } else { b' ' };
    }
}

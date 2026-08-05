//! openhicos-pkcs11 — standalone PKCS#11 module (Rust)
//! Clean-room. Not affiliated with MOI / CHT.

mod apdu;
mod der;
mod p15;
mod pcsc;
mod pkcs11;

use pkcs11::module::FUNCTION_LIST;
use pkcs11::types::*;

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: *mut *const CK_FUNCTION_LIST) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *pp_function_list = &FUNCTION_LIST;
    CKR_OK
}

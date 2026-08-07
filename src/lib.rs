//! open-gpki-pkcs11 — standalone PKCS#11 module and Rust API.
//!
//! Unofficial; not affiliated with any government or vendor middleware.
//!
//! - **PKCS#11 cdylib**: [`C_GetFunctionList`] for `pkcs11-tool` / dlopen users.
//! - **Rust API**: [`api`] for in-process use from other crates (`rlib`).

mod apdu;
mod der;
mod p15;
mod pcsc;
mod pkcs11;

pub mod api;

use pkcs11::module::FUNCTION_LIST;
use pkcs11::types::*;

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(
    pp_function_list: *mut *const CK_FUNCTION_LIST,
) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *pp_function_list = &FUNCTION_LIST;
    CKR_OK
}

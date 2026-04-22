/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! FFI error code enum and thread-local last-error storage.

use std::cell::RefCell;
use std::ffi::{CString, c_char};
use std::ptr;

use crate::error::RbcError;

/// RBC C API error codes. `RBC_ERROR_CODE_OK` is success; any other value is a failure
/// whose Rust-side Display-formatted reason is retrievable via
/// `rbc_last_error_message()` **on the same thread**.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbcErrorCode {
    Ok = 0,
    InvalidArg = 1,
    Config = 2,
    Tls = 3,
    Provider = 4,
    Keygen = 5,
    Evidence = 6,
    Network = 7,
    Timeout = 8,
    Auth = 9,
    PolicyDenied = 10,
    ResourceNotFound = 11,
    Attest = 12,
    Server = 13,
    Encrypt = 14,
    Decrypt = 15,
    Json = 16,
    Internal = 17,
}

pub(crate) fn error_to_code(e: &RbcError) -> RbcErrorCode {
    match e {
        RbcError::InvalidInput(_)      => RbcErrorCode::InvalidArg,
        RbcError::ConfigError(_)       => RbcErrorCode::Config,
        RbcError::TlsError(_)          => RbcErrorCode::Tls,
        RbcError::ProviderError(_)     => RbcErrorCode::Provider,
        RbcError::KeyGenError(_)       => RbcErrorCode::Keygen,
        RbcError::EvidenceError(_)     => RbcErrorCode::Evidence,
        RbcError::NetworkError(_) | RbcError::HttpTransport(_) => RbcErrorCode::Network,
        RbcError::TimeoutError(_)      => RbcErrorCode::Timeout,
        RbcError::AuthError(_)         => RbcErrorCode::Auth,
        RbcError::PolicyDenied(_)      => RbcErrorCode::PolicyDenied,
        RbcError::ResourceNotFound(_)  => RbcErrorCode::ResourceNotFound,
        RbcError::AttestError(_)       => RbcErrorCode::Attest,
        RbcError::ServerError(_)       => RbcErrorCode::Server,
        RbcError::EncryptError(_)      => RbcErrorCode::Encrypt,
        RbcError::DecryptError(_)      => RbcErrorCode::Decrypt,
        RbcError::JsonError(_)         => RbcErrorCode::Json,
    }
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub(crate) fn set_last_error<S: Into<Vec<u8>>>(msg: S) {
    let c = CString::new(msg).unwrap_or_else(|_| {
        CString::new("<invalid error message: contains NUL>").unwrap()
    });
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(c));
}

pub(crate) fn record(e: &RbcError) -> RbcErrorCode {
    set_last_error(format!("{e}"));
    error_to_code(e)
}

/// Return a pointer to the last error message set on the **current thread**, or
/// NULL if no error has been recorded since the last `rbc_last_error_clear` call.
///
/// The returned pointer is valid until the next RBC API call on the same thread
/// (which may overwrite it) or the next `rbc_last_error_clear`. The caller MUST
/// NOT free it.
#[export_name = "RbcLastErrorMessage"]
pub extern "C" fn rbc_last_error_message() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|c| c.as_ptr())
            .unwrap_or(ptr::null())
    })
}

/// Clear the last error on the current thread.
#[export_name = "RbcLastErrorClear"]
pub extern "C" fn rbc_last_error_clear() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RbcError;
    use std::ffi::CStr;

    fn clear() {
        rbc_last_error_clear();
    }

    #[test]
    fn last_error_is_null_when_cleared() {
        clear();
        assert!(rbc_last_error_message().is_null());
    }

    #[test]
    fn set_last_error_makes_message_readable() {
        clear();
        set_last_error("hello ffi error");
        let ptr = rbc_last_error_message();
        assert!(!ptr.is_null());
        let msg = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(msg, "hello ffi error");
        clear();
    }

    #[test]
    fn clear_removes_previous_error() {
        set_last_error("should be gone");
        clear();
        assert!(rbc_last_error_message().is_null());
    }

    #[test]
    fn error_on_other_thread_does_not_affect_current_thread() {
        clear();
        let handle = std::thread::spawn(|| {
            set_last_error("thread-local only");
            assert!(!rbc_last_error_message().is_null());
        });
        handle.join().unwrap();
        assert!(
            rbc_last_error_message().is_null(),
            "error set in another thread must not bleed into this thread"
        );
    }

    #[test]
    fn record_sets_message_and_returns_matching_code() {
        clear();
        let code = record(&RbcError::ConfigError("bad config".into()));
        assert_eq!(code, RbcErrorCode::Config);
        let ptr = rbc_last_error_message();
        assert!(!ptr.is_null());
        let msg = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(msg.contains("bad config"));
        clear();
    }

    #[test]
    fn error_to_code_maps_all_rbc_error_variants() {
        use RbcErrorCode::*;
        assert_eq!(error_to_code(&RbcError::InvalidInput("".into())), InvalidArg);
        assert_eq!(error_to_code(&RbcError::ConfigError("".into())), Config);
        assert_eq!(error_to_code(&RbcError::TlsError("".into())), Tls);
        assert_eq!(error_to_code(&RbcError::ProviderError("".into())), Provider);
        assert_eq!(error_to_code(&RbcError::KeyGenError("".into())), Keygen);
        assert_eq!(error_to_code(&RbcError::EvidenceError("".into())), Evidence);
        assert_eq!(error_to_code(&RbcError::NetworkError("".into())), Network);
        assert_eq!(error_to_code(&RbcError::TimeoutError("".into())), Timeout);
        assert_eq!(error_to_code(&RbcError::AuthError("".into())), Auth);
        assert_eq!(error_to_code(&RbcError::PolicyDenied("".into())), PolicyDenied);
        assert_eq!(error_to_code(&RbcError::ResourceNotFound("".into())), ResourceNotFound);
        assert_eq!(error_to_code(&RbcError::AttestError("".into())), Attest);
        assert_eq!(error_to_code(&RbcError::ServerError("".into())), Server);
        assert_eq!(error_to_code(&RbcError::EncryptError("".into())), Encrypt);
        assert_eq!(error_to_code(&RbcError::DecryptError("".into())), Decrypt);
        // JsonError wraps serde_json::Error
        let json_err = serde_json::from_str::<()>("not json").unwrap_err();
        assert_eq!(error_to_code(&RbcError::JsonError(json_err)), Json);
        // HttpTransport shares the Network code path
        assert_eq!(error_to_code(&RbcError::NetworkError("".into())), Network);
    }
}
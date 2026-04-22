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

//! RBC C FFI surface.
//!
//! # Thread safety
//!
//! **This API is NOT thread-safe.** Every handle (`RbcClient`,
//! `RbcSession`, `RbcResource`) must be accessed only from the thread
//! that created it. The thread-local error slot used by
//! `rbc_last_error_message` follows the same rule.
//!
//! # Memory ownership
//!
//! - Functions with a `char **` out-parameter allocate a nul-terminated string;
//!   free with `rbc_string_free`.
//! - Functions with a `uint8_t **` out-parameter allocate a byte buffer;
//!   free with `rbc_buffer_free(ptr, len)` — `len` must be the value the
//!   producing call wrote into its `size_t *out_len`.
//! - Functions returning `const char *` or `const uint8_t *` from an
//!   `RbcResource *` lend a pointer owned by the resource. It is valid
//!   until `rbc_resource_free` is called on that resource.

pub mod client;
pub mod error;
pub mod resource;
pub mod session;
pub(crate) mod utils;

use std::ffi::{c_char, CString};
use std::slice;

pub use error::{rbc_last_error_clear, rbc_last_error_message, RbcErrorCode};
pub(crate) use utils::{cstr_to_str, opt_cstr_to_str, require_non_null};

use crate::sdk::{Client, Session};

// ─── Opaque handle types ────────────────────────────────────────────────
// `/// cbindgen:opaque` causes cbindgen to emit a forward declaration only:
//   typedef struct RbcClient;
// The C type is incomplete — sizeof and stack-allocation are rejected by the
// compiler; only pointers are valid.
// These structs are never instantiated in Rust; the actual heap allocation is
// a Box<ConcreteType> cast to *mut rbc_*_t.

/// cbindgen:opaque
pub struct RbcClient {
    _priv: std::marker::PhantomData<()>,
}

/// cbindgen:opaque
pub struct RbcSession {
    _priv: std::marker::PhantomData<()>,
}

/// cbindgen:opaque
pub struct RbcResource {
    _priv: std::marker::PhantomData<()>,
}

// ─── Handle cast helpers ────────────────────────────────────────────────

#[inline]
fn box_client_into_handle(c: Client) -> *mut RbcClient {
    Box::into_raw(Box::new(c)) as *mut RbcClient
}
#[inline]
unsafe fn client_ref<'a>(h: *const RbcClient) -> &'a Client {
    &*(h as *const Client)
}
#[inline]
unsafe fn drop_client(h: *mut RbcClient) {
    drop(Box::from_raw(h as *mut Client));
}

#[inline]
fn box_session_into_handle(s: Session) -> *mut RbcSession {
    Box::into_raw(Box::new(s)) as *mut RbcSession
}
#[inline]
unsafe fn session_ref<'a>(h: *const RbcSession) -> &'a Session {
    &*(h as *const Session)
}
#[inline]
unsafe fn drop_session(h: *mut RbcSession) {
    drop(Box::from_raw(h as *mut Session));
}

// ─── Memory-release helpers ─────────────────────────────────────────────

/// Free a nul-terminated string returned by an RBC function.
#[export_name = "RbcStringFree"]
pub extern "C" fn rbc_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

/// Free a byte buffer returned by an RBC function. `len` MUST be the value
/// the producing call wrote into its `*out_len` parameter.
#[export_name = "RbcBufferFree"]
pub extern "C" fn rbc_buffer_free(buf: *mut u8, len: usize) {
    if !buf.is_null() && len > 0 {
        unsafe {
            let s = slice::from_raw_parts_mut(buf, len);
            zeroize::Zeroize::zeroize(s);
            drop(Box::from_raw(s as *mut [u8]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn string_free_null_does_not_panic() {
        rbc_string_free(ptr::null_mut());
    }

    #[test]
    fn string_free_allocated_string_does_not_panic() {
        let raw = std::ffi::CString::new("test-string-to-free").unwrap().into_raw();
        rbc_string_free(raw);
    }

    #[test]
    fn buffer_free_null_does_not_panic() {
        rbc_buffer_free(ptr::null_mut(), 42);
    }

    #[test]
    fn buffer_free_zero_len_does_not_panic() {
        let mut dummy: u8 = 0;
        rbc_buffer_free(&mut dummy as *mut u8, 0);
    }
}

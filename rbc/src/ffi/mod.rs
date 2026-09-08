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
//! Passing a handle to another thread, or using it concurrently from multiple
//! threads, is undefined behavior.
//!
//! # Handle ownership
//!
//! `RbcClient`, `RbcSession`, `RbcResource`, and `RbcBuffer` are opaque handles
//! created only by RBC. Callers must not allocate, copy, cast between handle
//! types, or dereference them. Each non-NULL handle must be released exactly
//! once by passing the address of its caller-owned variable to the matching
//! function:
//!
//! - `RbcClient *` with `rbc_client_free(&client)`
//! - `RbcSession *` with `rbc_session_free(&session)`
//! - `RbcResource *` with `rbc_resource_free(&resource)`
//! - `RbcBuffer *` with `rbc_buffer_free(&buffer)`
//!
//! A release function sets that caller-owned variable to NULL before dropping
//! the object. Any copied aliases and all borrowed pointers obtained from the
//! handle remain invalid and must not be used after release.
//!
//! # Memory ownership
//!
//! - Functions with a `char **` out-parameter allocate a nul-terminated string;
//!   free exactly once with `rbc_string_free`.
//! - Functions with an `RbcBuffer **` out-parameter create an opaque byte
//!   buffer handle. Borrow its bytes with `rbc_buffer_data` and its length with
//!   `rbc_buffer_len`; release exactly once with `rbc_buffer_free`.
//! - Functions returning `const char *` or `const uint8_t *` from an
//!   `RbcResource *` lend a pointer owned by the resource. It is valid
//!   until `rbc_resource_free` is called on that resource.
//!
//! Do not pass non-RBC allocations or adjusted pointers to any RBC release
//! function.

pub mod client;
pub mod error;
pub mod resource;
pub mod session;
pub(crate) mod utils;

use std::ffi::{c_char, CString};
use std::ptr;

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

/// cbindgen:opaque
pub struct RbcBuffer {
    _priv: std::marker::PhantomData<()>,
}

struct RbcBufferInner {
    data: zeroize::Zeroizing<Vec<u8>>,
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

// ─── Buffer handle helpers ──────────────────────────────────────────────

#[inline]
fn box_bytes_into_handle(data: zeroize::Zeroizing<Vec<u8>>) -> *mut RbcBuffer {
    Box::into_raw(Box::new(RbcBufferInner { data })) as *mut RbcBuffer
}

#[inline]
unsafe fn buffer_ref<'a>(h: *const RbcBuffer) -> &'a RbcBufferInner {
    &*(h as *const RbcBufferInner)
}

#[inline]
unsafe fn drop_buffer(h: *mut RbcBuffer) {
    drop(Box::from_raw(h as *mut RbcBufferInner));
}

/// Replace a caller-owned handle variable with NULL and return its old value.
///
/// `slot` must be either NULL or point to writable storage containing a handle
/// of the matching type returned by RBC.
#[inline]
unsafe fn take_handle<T>(slot: *mut *mut T) -> *mut T {
    if slot.is_null() {
        return ptr::null_mut();
    }
    ptr::replace(slot, ptr::null_mut())
}

/// Free a nul-terminated string returned by an RBC function.
#[export_name = "RbcStringFree"]
pub extern "C" fn rbc_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

/// Borrow the bytes in an opaque buffer. Returns NULL for a NULL or empty
/// buffer. The pointer is valid until `RbcBufferFree` is called for
/// `buffer`.
#[export_name = "RbcBufferData"]
pub extern "C" fn rbc_buffer_data(buffer: *const RbcBuffer) -> *const u8 {
    if buffer.is_null() {
        return ptr::null();
    }
    let buffer = unsafe { buffer_ref(buffer) };
    if buffer.data.is_empty() {
        ptr::null()
    } else {
        buffer.data.as_ptr()
    }
}

/// Return the number of bytes in an opaque buffer.
#[export_name = "RbcBufferLen"]
pub extern "C" fn rbc_buffer_len(buffer: *const RbcBuffer) -> usize {
    if buffer.is_null() {
        return 0;
    }
    let buffer = unsafe { buffer_ref(buffer) };
    buffer.data.len()
}

/// Free an opaque byte buffer and set the caller's handle variable to NULL.
/// Both `buffer` and `*buffer` may be NULL.
#[export_name = "RbcBufferFree"]
pub extern "C" fn rbc_buffer_free(buffer: *mut *mut RbcBuffer) {
    let buffer = unsafe { take_handle(buffer) };
    if !buffer.is_null() {
        unsafe { drop_buffer(buffer) };
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
    fn buffer_data_null_returns_null() {
        assert!(rbc_buffer_data(ptr::null()).is_null());
    }

    #[test]
    fn buffer_len_null_returns_zero() {
        assert_eq!(rbc_buffer_len(ptr::null()), 0);
    }

    #[test]
    fn buffer_data_and_len_return_owned_content() {
        let expected = b"secret buffer";
        let mut buffer = box_bytes_into_handle(zeroize::Zeroizing::new(expected.to_vec()));

        assert_eq!(rbc_buffer_len(buffer), expected.len());
        let data = rbc_buffer_data(buffer);
        assert!(!data.is_null());
        let actual = unsafe { std::slice::from_raw_parts(data, expected.len()) };
        assert_eq!(actual, expected);

        rbc_buffer_free(&mut buffer);
        assert!(buffer.is_null());
        assert_eq!(rbc_buffer_len(buffer), 0);
        assert!(rbc_buffer_data(buffer).is_null());
    }

    #[test]
    fn buffer_empty_content_can_be_freed() {
        let mut buffer = box_bytes_into_handle(zeroize::Zeroizing::new(Vec::new()));
        assert_eq!(rbc_buffer_len(buffer), 0);
        assert!(rbc_buffer_data(buffer).is_null());
        rbc_buffer_free(&mut buffer);
        assert!(buffer.is_null());
    }

    #[test]
    fn buffer_free_null_does_not_panic() {
        rbc_buffer_free(ptr::null_mut());
    }

    #[test]
    fn buffer_free_accepts_null_handle_and_keeps_it_null() {
        let mut buffer: *mut RbcBuffer = ptr::null_mut();
        rbc_buffer_free(&mut buffer);
        assert!(buffer.is_null());
    }
}

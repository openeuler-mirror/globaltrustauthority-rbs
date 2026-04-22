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

//! Resource handle type, construction helper, and accessor FFI functions.

use std::ffi::{c_char, CString};
use std::ptr;

use super::error::set_last_error;
use super::{RbcErrorCode, RbcResource};
use crate::sdk::Resource;

// ─── Concrete resource context ──────────────────────────────────────────
// Holds CString copies of the URI and content-type so that accessor
// functions can return stable `const char*` valid until `rbc_resource_free`.

pub(super) struct ResourceCtx {
    pub(super) inner: Resource,
    pub(super) uri_c: CString,
    pub(super) content_type_c: Option<CString>,
}

// ─── Handle cast helpers ────────────────────────────────────────────────

#[inline]
pub(super) fn box_resource_into_handle(ctx: ResourceCtx) -> *mut RbcResource {
    Box::into_raw(Box::new(ctx)) as *mut RbcResource
}
#[inline]
pub(super) unsafe fn resource_ref<'a>(h: *const RbcResource) -> &'a ResourceCtx {
    &*(h as *const ResourceCtx)
}
#[inline]
unsafe fn drop_resource(h: *mut RbcResource) {
    drop(Box::from_raw(h as *mut ResourceCtx));
}

// ─── Construction helper ────────────────────────────────────────────────

pub(super) fn wrap_resource(r: Resource) -> Result<ResourceCtx, RbcErrorCode> {
    let uri_c = CString::new(r.uri.as_bytes()).map_err(|e| {
        set_last_error(format!("resource uri contains NUL: {e}"));
        RbcErrorCode::Internal
    })?;
    let content_type_c = match r.content_type.as_deref() {
        None => None,
        Some(ct) => Some(CString::new(ct.as_bytes()).map_err(|e| {
            set_last_error(format!("content_type contains NUL: {e}"));
            RbcErrorCode::Internal
        })?),
    };
    Ok(ResourceCtx { inner: r, uri_c, content_type_c })
}

// ─── Resource accessors ─────────────────────────────────────────────────

/// Borrow the URI. Valid until `RbcResourceFree`.
#[export_name = "RbcResourceGetUri"]
pub extern "C" fn rbc_resource_get_uri(resource: *const RbcResource) -> *const c_char {
    if resource.is_null() {
        return ptr::null();
    }
    unsafe { resource_ref(resource).uri_c.as_ptr() }
}

/// Borrow the content-type (may be NULL). Valid until `RbcResourceFree`.
#[export_name = "RbcResourceGetContentType"]
pub extern "C" fn rbc_resource_get_content_type(resource: *const RbcResource) -> *const c_char {
    if resource.is_null() {
        return ptr::null();
    }
    unsafe {
        match &resource_ref(resource).content_type_c {
            Some(c) => c.as_ptr(),
            None => ptr::null(),
        }
    }
}

/// Borrow the raw content bytes. Writes the length into `*out_len`. Valid
/// until `RbcResourceFree`.
#[export_name = "RbcResourceGetContent"]
pub extern "C" fn rbc_resource_get_content(resource: *const RbcResource, out_len: *mut usize) -> *const u8 {
    if resource.is_null() || out_len.is_null() {
        return ptr::null();
    }
    unsafe {
        let bytes: &[u8] = resource_ref(resource).inner.content.as_slice();
        *out_len = bytes.len();
        bytes.as_ptr()
    }
}

/// Destroy a resource handle (invalidates all borrowed pointers obtained
/// from accessors).
#[export_name = "RbcResourceFree"]
pub extern "C" fn rbc_resource_free(resource: *mut RbcResource) {
    if !resource.is_null() {
        unsafe { drop_resource(resource) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::Resource;
    use std::ffi::CStr;

    fn make_resource_handle(uri: &str, content: Vec<u8>, ct: Option<&str>) -> *mut RbcResource {
        let r = Resource { uri: uri.to_string(), content: zeroize::Zeroizing::new(content), content_type: ct.map(str::to_string) };
        box_resource_into_handle(wrap_resource(r).unwrap())
    }

    // ── rbc_resource_get_uri ──────────────────────────────────────────────

    #[test]
    fn resource_get_uri_null_handle_returns_null() {
        assert!(rbc_resource_get_uri(ptr::null()).is_null());
    }

    #[test]
    fn resource_get_uri_returns_correct_string() {
        let h = make_resource_handle("rbs://test/uri", vec![1, 2, 3], None);
        let ptr = rbc_resource_get_uri(h);
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(s, "rbs://test/uri");
        rbc_resource_free(h);
    }

    // ── rbc_resource_get_content_type ─────────────────────────────────────

    #[test]
    fn resource_get_content_type_null_handle_returns_null() {
        assert!(rbc_resource_get_content_type(ptr::null()).is_null());
    }

    #[test]
    fn resource_get_content_type_returns_null_when_absent() {
        let h = make_resource_handle("rbs://x", vec![], None);
        assert!(rbc_resource_get_content_type(h).is_null());
        rbc_resource_free(h);
    }

    #[test]
    fn resource_get_content_type_returns_value_when_present() {
        let h = make_resource_handle("rbs://x", vec![], Some("application/octet-stream"));
        let ptr = rbc_resource_get_content_type(h);
        assert!(!ptr.is_null());
        let ct = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(ct, "application/octet-stream");
        rbc_resource_free(h);
    }

    // ── rbc_resource_get_content ──────────────────────────────────────────

    #[test]
    fn resource_get_content_null_resource_returns_null() {
        let mut len: usize = 0;
        assert!(rbc_resource_get_content(ptr::null(), &mut len).is_null());
    }

    #[test]
    fn resource_get_content_null_out_len_returns_null() {
        let h = make_resource_handle("rbs://x", vec![9, 8, 7], None);
        assert!(rbc_resource_get_content(h, ptr::null_mut()).is_null());
        rbc_resource_free(h);
    }

    #[test]
    fn resource_get_content_returns_bytes_and_length() {
        let payload = vec![10u8, 20, 30, 40];
        let h = make_resource_handle("rbs://x", payload.clone(), None);
        let mut len: usize = 0;
        let ptr = rbc_resource_get_content(h, &mut len);
        assert!(!ptr.is_null());
        assert_eq!(len, 4);
        let got = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert_eq!(got, payload.as_slice());
        rbc_resource_free(h);
    }

    // ── rbc_resource_free ─────────────────────────────────────────────────

    #[test]
    fn resource_free_null_does_not_panic() {
        rbc_resource_free(ptr::null_mut());
    }
}

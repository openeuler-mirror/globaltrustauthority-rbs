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

//! FFI utility helpers: null-pointer guards and C string conversions.

use std::ffi::{c_char, CStr};

use super::error::{set_last_error, RbcErrorCode};

// Check that every listed pointer is non-null, setting the last error and
// returning `RbcErrorCode::InvalidArg` for the first null one encountered.
macro_rules! require_non_null {
    ($($ptr:expr),+ $(,)?) => {
        $(
            if $ptr.is_null() {
                $crate::ffi::error::set_last_error(concat!(stringify!($ptr), " is null"));
                return $crate::ffi::RbcErrorCode::InvalidArg;
            }
        )+
    }
}

pub(crate) use require_non_null;

pub(crate) fn cstr_to_str<'a>(p: *const c_char, arg: &'static str) -> Result<&'a str, RbcErrorCode> {
    if p.is_null() {
        set_last_error(format!("{arg} is null"));
        return Err(RbcErrorCode::InvalidArg);
    }
    unsafe { CStr::from_ptr(p) }.to_str().map_err(|e| {
        set_last_error(format!("{arg} is not valid UTF-8: {e}"));
        RbcErrorCode::InvalidArg
    })
}

pub(crate) fn opt_cstr_to_str<'a>(p: *const c_char, arg: &'static str) -> Result<Option<&'a str>, RbcErrorCode> {
    if p.is_null() {
        Ok(None)
    } else {
        cstr_to_str(p, arg).map(Some)
    }
}

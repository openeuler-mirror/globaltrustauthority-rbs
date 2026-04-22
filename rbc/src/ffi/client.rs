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

//! Client lifecycle and authentication-challenge FFI functions.

use std::ffi::{c_char, CString};

use rbs_api_types::AuthChallengeResponse;

use super::error::{record, set_last_error, RbcErrorCode};
use super::{box_client_into_handle, client_ref, cstr_to_str, drop_client, require_non_null, RbcClient};
use crate::sdk::{Client, Config};

// ─── Client lifecycle ───────────────────────────────────────────────────

/// Create a client from a YAML config file on disk.
#[export_name = "RbcClientNewFromFile"]
pub extern "C" fn rbc_client_new_from_file(
    config_path: *const c_char,
    out_client: *mut *mut RbcClient,
) -> RbcErrorCode {
    require_non_null!(out_client);
    let path = match cstr_to_str(config_path, "config_path") {
        Ok(s) => s,
        Err(e) => return e,
    };
    match Client::from_config(path) {
        Ok(c) => {
            unsafe { *out_client = box_client_into_handle(c) };
            RbcErrorCode::Ok
        },
        Err(e) => record(&e),
    }
}

/// Create a client from an in-memory YAML string.
#[export_name = "RbcClientNewFromYaml"]
pub extern "C" fn rbc_client_new_from_yaml(yaml: *const c_char, out_client: *mut *mut RbcClient) -> RbcErrorCode {
    require_non_null!(out_client);
    let yaml_str = match cstr_to_str(yaml, "yaml") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let cfg: Config = match serde_yaml::from_str(yaml_str) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("parse yaml: {e}"));
            return RbcErrorCode::Config;
        },
    };
    match Client::new(cfg) {
        Ok(c) => {
            unsafe { *out_client = box_client_into_handle(c) };
            RbcErrorCode::Ok
        },
        Err(e) => record(&e),
    }
}

/// Destroy a client handle.
#[export_name = "RbcClientFree"]
pub extern "C" fn rbc_client_free(client: *mut RbcClient) {
    if !client.is_null() {
        unsafe { drop_client(client) };
    }
}

// ─── Challenge ──────────────────────────────────────────────────────────

/// Fetch an authentication challenge. On success `*out_nonce` is a newly
/// allocated nul-terminated string owned by the caller; free with
/// `RbcStringFree`.
#[export_name = "RbcGetAuthChallenge"]
pub extern "C" fn rbc_get_auth_challenge(client: *mut RbcClient, out_nonce: *mut *mut c_char) -> RbcErrorCode {
    require_non_null!(client, out_nonce);
    let client = unsafe { client_ref(client) };
    match client.get_auth_challenge() {
        Ok(AuthChallengeResponse { nonce }) => match CString::new(nonce) {
            Ok(c) => {
                unsafe { *out_nonce = c.into_raw() };
                RbcErrorCode::Ok
            },
            Err(e) => {
                set_last_error(format!("nonce contains NUL: {e}"));
                RbcErrorCode::Internal
            },
        },
        Err(e) => record(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    fn make_no_provider_client_handle() -> *mut RbcClient {
        let yaml = CString::new("endpoint: http://localhost:9999\n").unwrap();
        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_yaml(yaml.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::Ok, "expected Ok creating no-provider client");
        out
    }

    // ── rbc_client_new_from_file ──────────────────────────────────────────

    #[test]
    fn client_new_from_file_null_path_returns_invalid_arg() {
        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_file(ptr::null(), &mut out);
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn client_new_from_file_null_out_returns_invalid_arg() {
        let path = CString::new("/tmp/does-not-matter.yaml").unwrap();
        let code = rbc_client_new_from_file(path.as_ptr(), ptr::null_mut());
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    // ── rbc_client_new_from_yaml ──────────────────────────────────────────

    #[test]
    fn client_new_from_yaml_null_yaml_returns_invalid_arg() {
        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_yaml(ptr::null(), &mut out);
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn client_new_from_yaml_null_out_returns_invalid_arg() {
        let yaml = CString::new("endpoint: http://localhost:9999\n").unwrap();
        let code = rbc_client_new_from_yaml(yaml.as_ptr(), ptr::null_mut());
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn client_new_from_yaml_bad_yaml_returns_config_error() {
        // Missing required `endpoint` field → serde_yaml deserialization fails
        let yaml = CString::new("not_endpoint_field: http://localhost:9999\n").unwrap();
        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_yaml(yaml.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::Config);
        assert!(out.is_null());
    }

    #[test]
    fn client_new_from_yaml_valid_config_returns_ok() {
        let yaml = CString::new("endpoint: http://localhost:9999\n").unwrap();
        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_yaml(yaml.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::Ok);
        assert!(!out.is_null());
        rbc_client_free(out);
    }

    // ── rbc_client_free ───────────────────────────────────────────────────

    #[test]
    fn client_free_null_does_not_panic() {
        rbc_client_free(ptr::null_mut());
    }

    // ── rbc_get_auth_challenge ────────────────────────────────────────────

    #[test]
    fn get_auth_challenge_null_client_returns_invalid_arg() {
        let mut out: *mut c_char = ptr::null_mut();
        let code = rbc_get_auth_challenge(ptr::null_mut(), &mut out);
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn get_auth_challenge_null_out_returns_invalid_arg() {
        let client = make_no_provider_client_handle();
        let code = rbc_get_auth_challenge(client, ptr::null_mut());
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_client_free(client);
    }
}

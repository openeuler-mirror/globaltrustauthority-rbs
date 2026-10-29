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
use super::{box_client_into_handle, client_ref, cstr_to_str, drop_client, require_non_null, take_handle, RbcClient};
use crate::sdk::{Client, Config};

// ─── Client lifecycle ───────────────────────────────────────────────────

/// Create a client from a YAML config file on disk.
///
/// The returned handle is single-threaded: use it only from the thread that
/// created it. See the `RbcClient` type documentation for the full contract.
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
///
/// The returned handle is single-threaded: use it only from the thread that
/// created it. See the `RbcClient` type documentation for the full contract.
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

/// Destroy a client handle and set the caller's handle variable to NULL.
/// Both `client` and `*client` may be NULL.
#[export_name = "RbcClientFree"]
pub extern "C" fn rbc_client_free(client: *mut *mut RbcClient) {
    let client = unsafe { take_handle(client) };
    if !client.is_null() {
        unsafe { drop_client(client) };
    }
}

// ─── Challenge ──────────────────────────────────────────────────────────

/// Fetch an authentication challenge. On success `*out_nonce` is a newly
/// allocated nul-terminated string owned by the caller; free with
/// `RbcStringFree`.
///
/// Single-threaded handle: `client` must be used only from the thread that
/// created it.
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
    use crate::ffi::rbc_string_free;
    use std::ffi::{CStr, CString};
    use std::path::PathBuf;
    use std::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Sequence used to keep concurrent temporary file names unique.
    static TEMP_FILE_SEQ: AtomicUsize = AtomicUsize::new(0);

    /// Temporary config file that removes itself when the test ends.
    struct TempConfigFile {
        path: PathBuf,
    }

    impl TempConfigFile {
        fn new(name: &str, contents: &str) -> Self {
            let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("rbc-ffi-client-{}-{seq}-{name}", std::process::id()));
            std::fs::write(&path, contents).expect("write temporary config");
            Self { path }
        }

        fn cstr(&self) -> CString {
            CString::new(self.path.display().to_string()).expect("utf8 config path")
        }
    }

    impl Drop for TempConfigFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Temporary path that is guaranteed not to exist.
    fn missing_path(name: &str) -> String {
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("rbc-ffi-client-missing-{}-{seq}-{name}", std::process::id()))
            .display()
            .to_string()
    }

    fn make_no_provider_client_handle() -> *mut RbcClient {
        make_client_for_base_url("http://localhost:9999")
    }

    /// Create a client handle whose config points at `base_url`.
    fn make_client_for_base_url(base_url: &str) -> *mut RbcClient {
        let yaml = CString::new(format!("rbs:\n  base_url: {base_url}\n")).unwrap();
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

    #[test]
    fn client_new_from_file_valid_config_returns_ok() {
        let config = TempConfigFile::new("rbc.yaml", "rbs:\n  base_url: http://localhost:9999\n");
        let config_path = config.cstr();

        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_file(config_path.as_ptr(), &mut out);

        assert_eq!(code, RbcErrorCode::Ok);
        assert!(!out.is_null());
        rbc_client_free(&mut out);
        assert!(out.is_null());
    }

    #[test]
    fn client_new_from_file_missing_path_returns_config_error() {
        let path = CString::new(missing_path("rbc.yaml")).unwrap();

        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_file(path.as_ptr(), &mut out);

        assert_eq!(code, RbcErrorCode::Config);
        assert!(out.is_null());
    }

    #[test]
    fn client_new_from_file_bad_yaml_returns_config_error() {
        let config = TempConfigFile::new("bad-rbc.yaml", "not_rbs: true\n");
        let config_path = config.cstr();

        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_file(config_path.as_ptr(), &mut out);

        assert_eq!(code, RbcErrorCode::Config);
        assert!(out.is_null());
    }

    #[test]
    fn client_new_from_file_non_utf8_path_returns_invalid_arg() {
        // 0xff is not valid UTF-8 but is not the NUL terminator either.
        let path = CString::new(vec![b'/', 0xff, 0xfe]).unwrap();

        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_file(path.as_ptr(), &mut out);

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
        let yaml = CString::new("rbs:\n  base_url: http://localhost:9999\n").unwrap();
        let code = rbc_client_new_from_yaml(yaml.as_ptr(), ptr::null_mut());
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn client_new_from_yaml_bad_yaml_returns_config_error() {
        // Missing required `rbs` section → serde_yaml deserialization fails
        let yaml = CString::new("not_rbs: http://localhost:9999\n").unwrap();
        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_yaml(yaml.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::Config);
        assert!(out.is_null());
    }

    #[test]
    fn client_new_from_yaml_non_utf8_returns_invalid_arg() {
        let yaml = CString::new(vec![0xff, 0xfe]).unwrap();

        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_yaml(yaml.as_ptr(), &mut out);

        assert_eq!(code, RbcErrorCode::InvalidArg);
        assert!(out.is_null());
    }

    #[test]
    fn client_new_from_yaml_valid_config_returns_ok() {
        let yaml = CString::new("rbs:\n  base_url: http://localhost:9999\n").unwrap();
        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_yaml(yaml.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::Ok);
        assert!(!out.is_null());
        rbc_client_free(&mut out);
        assert!(out.is_null());
    }

    // ── rbc_client_free ───────────────────────────────────────────────────

    #[test]
    fn client_free_null_does_not_panic() {
        rbc_client_free(ptr::null_mut());
    }

    #[test]
    fn client_free_sets_handle_to_null_and_is_repeatable() {
        let mut client = make_no_provider_client_handle();

        rbc_client_free(&mut client);
        assert!(client.is_null());
        rbc_client_free(&mut client);
        assert!(client.is_null());

        let mut nonce: *mut c_char = ptr::null_mut();
        assert_eq!(rbc_get_auth_challenge(client, &mut nonce), RbcErrorCode::InvalidArg);
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
        let mut client = make_no_provider_client_handle();
        let code = rbc_get_auth_challenge(client, ptr::null_mut());
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_client_free(&mut client);
    }

    /// Mount a challenge endpoint on a fresh mock server and return its base URL.
    async fn mock_challenge_server(nonce_json: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rbs/v0/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_string(nonce_json))
            .mount(&server)
            .await;
        server
    }

    /// Mount a challenge endpoint that always answers with `status`.
    async fn mock_challenge_status_server(status: u16, body: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rbs/v0/challenge"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_auth_challenge_returns_nonce() {
        let server = mock_challenge_server(r#"{"nonce":"nonce-from-rbs"}"#).await;
        let base_url = server.uri();

        let nonce = tokio::task::spawn_blocking(move || {
            let mut client = make_client_for_base_url(&base_url);
            let mut out: *mut c_char = ptr::null_mut();

            let code = rbc_get_auth_challenge(client, &mut out);
            assert_eq!(code, RbcErrorCode::Ok);
            assert!(!out.is_null());

            let nonce = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
            rbc_string_free(out);
            rbc_client_free(&mut client);
            nonce
        })
        .await
        .expect("blocking task should join");

        assert_eq!(nonce, "nonce-from-rbs");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_auth_challenge_nonce_with_nul_returns_internal() {
        // JSON escapes the NUL, so the parsed nonce carries a real NUL byte that
        // cannot be stored in a C string.
        let server = mock_challenge_server(r#"{"nonce":"nonce\u0000tail"}"#).await;
        let base_url = server.uri();

        let code = tokio::task::spawn_blocking(move || {
            let mut client = make_client_for_base_url(&base_url);
            let mut out: *mut c_char = ptr::null_mut();

            let code = rbc_get_auth_challenge(client, &mut out);
            assert!(out.is_null(), "no string must be handed out on failure");
            rbc_client_free(&mut client);
            code
        })
        .await
        .expect("blocking task should join");

        assert_eq!(code, RbcErrorCode::Internal);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_auth_challenge_maps_server_error() {
        let server = mock_challenge_status_server(500, "internal error").await;
        let base_url = server.uri();

        let code = tokio::task::spawn_blocking(move || {
            let mut client = make_client_for_base_url(&base_url);
            let mut out: *mut c_char = ptr::null_mut();

            let code = rbc_get_auth_challenge(client, &mut out);
            rbc_client_free(&mut client);
            code
        })
        .await
        .expect("blocking task should join");

        assert_eq!(code, RbcErrorCode::Server);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_auth_challenge_maps_unauthorized() {
        let server = mock_challenge_status_server(401, "unauthorized").await;
        let base_url = server.uri();

        let code = tokio::task::spawn_blocking(move || {
            let mut client = make_client_for_base_url(&base_url);
            let mut out: *mut c_char = ptr::null_mut();

            let code = rbc_get_auth_challenge(client, &mut out);
            rbc_client_free(&mut client);
            code
        })
        .await
        .expect("blocking task should join");

        assert_eq!(code, RbcErrorCode::Auth);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_auth_challenge_maps_transport_failure() {
        // Bind and immediately drop a listener so the port refuses connections.
        let base_url = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
            let addr = listener.local_addr().expect("read probe address");
            drop(listener);
            format!("http://{addr}")
        };

        let code = tokio::task::spawn_blocking(move || {
            let mut client = make_client_for_base_url(&base_url);
            let mut out: *mut c_char = ptr::null_mut();

            let code = rbc_get_auth_challenge(client, &mut out);
            rbc_client_free(&mut client);
            code
        })
        .await
        .expect("blocking task should join");

        assert_eq!(code, RbcErrorCode::Network);
    }
}

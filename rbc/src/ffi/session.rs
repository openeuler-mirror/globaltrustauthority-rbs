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

//! Session lifecycle, operations, and decryption FFI functions.

use std::ffi::{CString, c_char};
use serde_json::Value;
use rbs_api_types::{AttesterData, AuthChallengeResponse};

use crate::error::RbcError;
use crate::sdk::GetResourceRequest;
use super::{RbcClient, RbcResource, RbcSession,
            box_session_into_handle, client_ref, drop_session, require_non_null, session_ref};
use super::error::{RbcErrorCode, record, set_last_error};
use super::{cstr_to_str, opt_cstr_to_str};
use super::resource::{box_resource_into_handle, wrap_resource};

// ─── Session lifecycle ──────────────────────────────────────────────────

/// Begin a new session. `attester_data_json` may be NULL. If non-NULL it must
/// be a JSON object matching `AttesterData` (per `rbs_api.yaml`); if its
/// `runtime_data.tee_pubkey` is present the caller is responsible for the
/// matching private key (pass it to `RbcSessionDecryptContent`).
#[export_name = "RbcSessionNew"]
pub extern "C" fn rbc_session_new(
    client: *mut RbcClient,
    attester_data_json: *const c_char,
    out_session: *mut *mut RbcSession,
) -> RbcErrorCode {
    require_non_null!(client, out_session);
    let client = unsafe { client_ref(client) };

    let attester_data = match opt_cstr_to_str(attester_data_json, "attester_data_json") {
        Ok(None) => None,
        Ok(Some(s)) => match serde_json::from_str::<AttesterData>(s) {
            Ok(a) => Some(a),
            Err(e) => {
                set_last_error(format!("parse attester_data_json: {e}"));
                return RbcErrorCode::InvalidArg;
            }
        },
        Err(e) => return e,
    };

    match client.new_session(attester_data.as_ref()) {
        Ok(session) => {
            unsafe { *out_session = box_session_into_handle(session) };
            RbcErrorCode::Ok
        }
        Err(e) => record(&e),
    }
}

/// Free a session. The embedded ephemeral key is zeroized on drop.
#[export_name = "RbcSessionFree"]
pub extern "C" fn rbc_session_free(session: *mut RbcSession) {
    if !session.is_null() {
        unsafe { drop_session(session) };
    }
}

// ─── Session operations ─────────────────────────────────────────────────

/// Collect evidence for `nonce`. On success `*out_evidence_json` is a newly
/// allocated JSON-encoded nul-terminated string owned by the caller.
#[export_name = "RbcSessionCollectEvidence"]
pub extern "C" fn rbc_session_collect_evidence(
    session: *mut RbcSession,
    nonce: *const c_char,
    out_evidence_json: *mut *mut c_char,
) -> RbcErrorCode {
    require_non_null!(session, out_evidence_json);
    let nonce_s = match cstr_to_str(nonce, "nonce") {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let session = unsafe { session_ref(session) };
    let challenge = AuthChallengeResponse { nonce: nonce_s };
    match session.collect_evidence(&challenge) {
        Ok(v) => match serde_json::to_string(&v) {
            Ok(js) => match CString::new(js) {
                Ok(c) => {
                    unsafe { *out_evidence_json = c.into_raw() };
                    RbcErrorCode::Ok
                }
                Err(e) => {
                    set_last_error(format!("evidence JSON contains NUL: {e}"));
                    RbcErrorCode::Internal
                }
            },
            Err(e) => record(&RbcError::JsonError(e)),
        },
        Err(e) => record(&e),
    }
}

/// Exchange evidence for an attest token. `evidence_json` may be NULL (in
/// which case the session's TokenProvider must be able to produce a token
/// without one). On success `*out_token` is a newly allocated nul-terminated
/// string owned by the caller.
#[export_name = "RbcSessionAttest"]
pub extern "C" fn rbc_session_attest(
    session: *mut RbcSession,
    evidence_json: *const c_char,
    out_token: *mut *mut c_char,
) -> RbcErrorCode {
    require_non_null!(session, out_token);
    let evidence_opt = match opt_cstr_to_str(evidence_json, "evidence_json") {
        Ok(None) => None,
        Ok(Some(s)) => match serde_json::from_str::<Value>(s) {
            Ok(v) => Some(v),
            Err(e) => {
                set_last_error(format!("parse evidence_json: {e}"));
                return RbcErrorCode::InvalidArg;
            }
        },
        Err(e) => return e,
    };
    let session = unsafe { session_ref(session) };
    match session.attest(evidence_opt.as_ref()) {
        Ok(resp) => match CString::new(resp.token) {
            Ok(c) => {
                unsafe { *out_token = c.into_raw() };
                RbcErrorCode::Ok
            }
            Err(e) => {
                set_last_error(format!("token contains NUL: {e}"));
                RbcErrorCode::Internal
            }
        },
        Err(e) => record(&e),
    }
}

/// Fetch a resource using a previously-obtained attest token.
#[export_name = "RbcSessionGetResourceByToken"]
pub extern "C" fn rbc_session_get_resource_by_token(
    session: *mut RbcSession,
    uri: *const c_char,
    token: *const c_char,
    out_resource: *mut *mut RbcResource,
) -> RbcErrorCode {
    require_non_null!(session, out_resource);
    let uri_s = match cstr_to_str(uri, "uri") { Ok(s) => s, Err(e) => return e };
    let token_s = match cstr_to_str(token, "token") { Ok(s) => s, Err(e) => return e };
    let session = unsafe { session_ref(session) };
    match session.get_resource(uri_s, GetResourceRequest::ByAttestToken(token_s)) {
        Ok(r) => match wrap_resource(r) {
            Ok(ctx) => {
                unsafe { *out_resource = box_resource_into_handle(ctx) };
                RbcErrorCode::Ok
            }
            Err(code) => code,
        },
        Err(e) => record(&e),
    }
}

/// Fetch a resource using an evidence bundle (pull-by-evidence mode).
#[export_name = "RbcSessionGetResourceByEvidence"]
pub extern "C" fn rbc_session_get_resource_by_evidence(
    session: *mut RbcSession,
    uri: *const c_char,
    evidence_json: *const c_char,
    out_resource: *mut *mut RbcResource,
) -> RbcErrorCode {
    require_non_null!(session, out_resource);
    let uri_s = match cstr_to_str(uri, "uri") { Ok(s) => s, Err(e) => return e };
    let ev_s = match cstr_to_str(evidence_json, "evidence_json") { Ok(s) => s, Err(e) => return e };
    let ev: Value = match serde_json::from_str(ev_s) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("parse evidence_json: {e}"));
            return RbcErrorCode::InvalidArg;
        }
    };
    let session = unsafe { session_ref(session) };
    match session.get_resource(uri_s, GetResourceRequest::ByEvidence { value: &ev }) {
        Ok(r) => match wrap_resource(r) {
            Ok(ctx) => {
                unsafe { *out_resource = box_resource_into_handle(ctx) };
                RbcErrorCode::Ok
            }
            Err(code) => code,
        },
        Err(e) => record(&e),
    }
}

// ─── Decryption ─────────────────────────────────────────────────────────

/// Decrypt a JWE token using the session's key.
///
/// Pass `private_key_pem == NULL` to use the ephemeral key generated in
/// `RbcSessionBegin`. Pass a PEM string only when the caller supplied its own
/// `tee_pubkey` in `attester_data_json` during `RbcSessionBegin`.
///
/// On success `*out_plaintext` is a newly allocated buffer of `*out_len` bytes
/// owned by the caller; release with `RbcBufferFree(buf, len)`.
#[export_name = "RbcSessionDecryptContent"]
pub extern "C" fn rbc_session_decrypt_content(
    session: *mut RbcSession,
    jwe: *const c_char,
    private_key_pem: *const c_char,
    out_plaintext: *mut *mut u8,
    out_len: *mut usize,
) -> RbcErrorCode {
    require_non_null!(session, out_plaintext, out_len);
    let jwe_s = match cstr_to_str(jwe, "jwe") { Ok(s) => s, Err(e) => return e };
    let pem_opt = match opt_cstr_to_str(private_key_pem, "private_key_pem") {
        Ok(o) => o,
        Err(e) => return e,
    };
    let session = unsafe { session_ref(session) };
    match session.decrypt_content(jwe_s, pem_opt) {
        Ok(bytes) => {
            // Extract inner Vec without triggering Zeroizing::drop; memory
            // ownership transfers to C and is released (with zeroing) by RbcBufferFree.
            let inner: Vec<u8> = unsafe {
                let mut md = std::mem::ManuallyDrop::new(bytes);
                std::ptr::read(&mut **md)
            };
            let mut boxed: Box<[u8]> = inner.into_boxed_slice();
            let len = boxed.len();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed);
            unsafe {
                *out_plaintext = ptr;
                *out_len = len;
            }
            RbcErrorCode::Ok
        }
        Err(e) => record(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::ffi::{CStr, CString};
    use std::rc::Rc;
    use std::sync::Arc;
    use async_trait::async_trait;
    use serde_json::json;
    use rbs_api_types::{AttesterData, AuthChallengeResponse};
    use crate::client::RbsRestClient;
    use crate::error::RbcError;
    use crate::evidence::EvidenceProvider;
    use crate::sdk::{Client, ClientInner};
    use crate::token::TokenProvider;
    use crate::tools::tee_key::{KeyType, TeePublicKey};
    use super::super::{RbcClient, rbc_string_free, rbc_buffer_free};
    use super::super::client::{rbc_client_new_from_yaml, rbc_client_free};

    // ── Mock providers ──────────────────────────────────────────────────────

    struct MockEvidenceProvider {
        result: Value,
    }

    #[async_trait]
    impl EvidenceProvider for MockEvidenceProvider {
        async fn collect_evidence(
            &self,
            _challenge: &AuthChallengeResponse,
            _attester_data: Option<&AttesterData>,
        ) -> Result<Value, RbcError> {
            Ok(self.result.clone())
        }
    }

    struct MockTokenProvider {
        token: String,
    }

    #[async_trait]
    impl TokenProvider for MockTokenProvider {
        async fn get_token(
            &self,
            _evidence: Option<&Value>,
            _attester_data: Option<&AttesterData>,
        ) -> Result<String, RbcError> {
            Ok(self.token.clone())
        }
    }

    // ── Test helpers ────────────────────────────────────────────────────────

    fn make_no_provider_client_handle() -> *mut RbcClient {
        let yaml = CString::new("endpoint: http://localhost:9999\n").unwrap();
        let mut out: *mut RbcClient = ptr::null_mut();
        let code = rbc_client_new_from_yaml(yaml.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::Ok, "expected Ok creating no-provider client");
        out
    }

    fn make_mock_client() -> Client {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        Client::new_for_test(Rc::new(ClientInner {
            rest_client: RbsRestClient::new("http://localhost:9999", None, None).unwrap(),
            evidence_provider: Some(Arc::new(MockEvidenceProvider { result: json!({"mock": true}) })),
            token_provider: Some(Arc::new(MockTokenProvider { token: "mock.token".into() })),
            key_type: KeyType::Ec,
            timeout_secs: None,
            runtime,
        }))
    }

    fn make_mock_client_handle() -> *mut RbcClient {
        super::super::box_client_into_handle(make_mock_client())
    }

    unsafe fn make_mock_session_handle(client: *mut RbcClient) -> *mut RbcSession {
        let mut out: *mut RbcSession = ptr::null_mut();
        let code = rbc_session_new(client, ptr::null(), &mut out);
        assert_eq!(code, RbcErrorCode::Ok, "expected Ok creating session");
        out
    }

    // ── rbc_session_new ───────────────────────────────────────────────────

    #[test]
    fn session_new_null_client_returns_invalid_arg() {
        let mut out: *mut RbcSession = ptr::null_mut();
        let code = rbc_session_new(ptr::null_mut(), ptr::null(), &mut out);
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn session_new_null_out_returns_invalid_arg() {
        let client = make_no_provider_client_handle();
        let code = rbc_session_new(client, ptr::null(), ptr::null_mut());
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_client_free(client);
    }

    #[test]
    fn session_new_invalid_attester_data_json_returns_invalid_arg() {
        let client = make_no_provider_client_handle();
        let bad_json = CString::new("{not valid json}").unwrap();
        let mut out: *mut RbcSession = ptr::null_mut();
        let code = rbc_session_new(client, bad_json.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::InvalidArg);
        assert!(out.is_null());
        rbc_client_free(client);
    }

    #[test]
    fn session_new_null_attester_data_creates_session() {
        let client = make_no_provider_client_handle();
        let mut out: *mut RbcSession = ptr::null_mut();
        let code = rbc_session_new(client, ptr::null(), &mut out);
        assert_eq!(code, RbcErrorCode::Ok);
        assert!(!out.is_null());
        rbc_session_free(out);
        rbc_client_free(client);
    }

    // ── rbc_session_free ──────────────────────────────────────────────────

    #[test]
    fn session_free_null_does_not_panic() {
        rbc_session_free(ptr::null_mut());
    }

    // ── rbc_session_collect_evidence ──────────────────────────────────────

    #[test]
    fn session_collect_evidence_null_session_returns_invalid_arg() {
        let mut out: *mut c_char = ptr::null_mut();
        let nonce = CString::new("nonce123").unwrap();
        let code = rbc_session_collect_evidence(ptr::null_mut(), nonce.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn session_collect_evidence_null_out_returns_invalid_arg() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let nonce = CString::new("nonce123").unwrap();
        let code = rbc_session_collect_evidence(session, nonce.as_ptr(), ptr::null_mut());
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    #[test]
    fn session_collect_evidence_null_nonce_returns_invalid_arg() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let mut out: *mut c_char = ptr::null_mut();
        let code = rbc_session_collect_evidence(session, ptr::null(), &mut out);
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    #[test]
    fn session_collect_evidence_with_mock_returns_json() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let nonce = CString::new("test-nonce").unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let code = rbc_session_collect_evidence(session, nonce.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::Ok);
        assert!(!out.is_null());
        let json_str = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
        let v: Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(v["mock"], true);
        rbc_string_free(out);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    // ── rbc_session_attest ────────────────────────────────────────────────

    #[test]
    fn session_attest_null_session_returns_invalid_arg() {
        let mut out: *mut c_char = ptr::null_mut();
        let code = rbc_session_attest(ptr::null_mut(), ptr::null(), &mut out);
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn session_attest_null_out_returns_invalid_arg() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let code = rbc_session_attest(session, ptr::null(), ptr::null_mut());
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    #[test]
    fn session_attest_invalid_evidence_json_returns_invalid_arg() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let bad_json = CString::new("{bad json}").unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let code = rbc_session_attest(session, bad_json.as_ptr(), &mut out);
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    #[test]
    fn session_attest_with_mock_returns_token() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let mut out: *mut c_char = ptr::null_mut();
        let code = rbc_session_attest(session, ptr::null(), &mut out);
        assert_eq!(code, RbcErrorCode::Ok);
        assert!(!out.is_null());
        let token = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
        assert_eq!(token, "mock.token");
        rbc_string_free(out);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    // ── rbc_session_get_resource_by_token ─────────────────────────────────

    #[test]
    fn get_resource_by_token_null_session_returns_invalid_arg() {
        let uri = CString::new("rbs://res/1").unwrap();
        let token = CString::new("tok").unwrap();
        let mut out: *mut RbcResource = ptr::null_mut();
        let code = rbc_session_get_resource_by_token(
            ptr::null_mut(), uri.as_ptr(), token.as_ptr(), &mut out,
        );
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn get_resource_by_token_null_out_returns_invalid_arg() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let uri = CString::new("rbs://res/1").unwrap();
        let token = CString::new("tok").unwrap();
        let code = rbc_session_get_resource_by_token(
            session, uri.as_ptr(), token.as_ptr(), ptr::null_mut(),
        );
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    // ── rbc_session_get_resource_by_evidence ──────────────────────────────

    #[test]
    fn get_resource_by_evidence_null_session_returns_invalid_arg() {
        let uri = CString::new("rbs://res/1").unwrap();
        let ev = CString::new("{}").unwrap();
        let mut out: *mut RbcResource = ptr::null_mut();
        let code = rbc_session_get_resource_by_evidence(
            ptr::null_mut(), uri.as_ptr(), ev.as_ptr(), &mut out,
        );
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn get_resource_by_evidence_null_out_returns_invalid_arg() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let uri = CString::new("rbs://res/1").unwrap();
        let ev = CString::new("{}").unwrap();
        let code = rbc_session_get_resource_by_evidence(
            session, uri.as_ptr(), ev.as_ptr(), ptr::null_mut(),
        );
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    #[test]
    fn get_resource_by_evidence_invalid_json_returns_invalid_arg() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let uri = CString::new("rbs://res/1").unwrap();
        let bad_ev = CString::new("{not json}").unwrap();
        let mut out: *mut RbcResource = ptr::null_mut();
        let code = rbc_session_get_resource_by_evidence(
            session, uri.as_ptr(), bad_ev.as_ptr(), &mut out,
        );
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    // ── rbc_session_decrypt_content ───────────────────────────────────────

    #[test]
    fn decrypt_content_null_session_returns_invalid_arg() {
        let jwe = CString::new("a.b.c.d.e").unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;
        let code = rbc_session_decrypt_content(
            ptr::null_mut(), jwe.as_ptr(), ptr::null(), &mut out, &mut len,
        );
        assert_eq!(code, RbcErrorCode::InvalidArg);
    }

    #[test]
    fn decrypt_content_null_out_plaintext_returns_invalid_arg() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let jwe = CString::new("a.b.c.d.e").unwrap();
        let mut len: usize = 0;
        let code = rbc_session_decrypt_content(
            session, jwe.as_ptr(), ptr::null(), ptr::null_mut(), &mut len,
        );
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    #[test]
    fn decrypt_content_null_out_len_returns_invalid_arg() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };
        let jwe = CString::new("a.b.c.d.e").unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let code = rbc_session_decrypt_content(
            session, jwe.as_ptr(), ptr::null(), &mut out, ptr::null_mut(),
        );
        assert_eq!(code, RbcErrorCode::InvalidArg);
        rbc_session_free(session);
        rbc_client_free(client);
    }

    #[test]
    fn decrypt_content_roundtrip_with_ephemeral_key() {
        let client = make_mock_client_handle();
        let session = unsafe { make_mock_session_handle(client) };

        let session_inner = unsafe { session_ref(session) };
        let pubkey_json = session_inner
            .test_ephemeral_public_jwk_json()
            .expect("session must have an ephemeral key");
        let pubkey = TeePublicKey::from_jwk_json(&pubkey_json).unwrap();

        let plaintext = b"secret payload";
        let jwe = pubkey.encrypt_jwe(plaintext).unwrap();
        let jwe_c = CString::new(jwe).unwrap();

        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let code = rbc_session_decrypt_content(
            session, jwe_c.as_ptr(), ptr::null(), &mut out_ptr, &mut out_len,
        );
        assert_eq!(code, RbcErrorCode::Ok);
        assert!(!out_ptr.is_null());
        assert_eq!(out_len, plaintext.len());
        let got = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
        assert_eq!(got, plaintext.as_ref());

        rbc_buffer_free(out_ptr, out_len);
        rbc_session_free(session);
        rbc_client_free(client);
    }
}

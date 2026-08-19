/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Attest token verification tests.

use serde_json::json;

use rbs_core::auth::authn::TokenVerifier;
use rbs_core::AuthError;

use super::common::*;

const MALFORMED_TOKEN: &str = "not.a.valid.token";

// ===========================================================================
// RUST_GTA_RBS_TP_AUTH_AttestFail_017 — Attest token过期/issuer不匹配/格式非法返回401
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_AUTH_AttestFail_017
/// Expired Attest token is rejected (exp in the past).
#[tokio::test]
async fn test_attest_fail_017_expired_token_rejected() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_attest_verifier(&pub_pem, "Global Trust Authority", Some("rbs"));
    let now = now_secs();
    let claims = json!({
        "iss": "Global Trust Authority",
        "aud": "rbs",
        "exp": now - 3600,
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(AuthError::TokenExpired)));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_AttestFail_017
/// Attest token with mismatched issuer is rejected.
#[tokio::test]
async fn test_attest_fail_017_iss_mismatch_rejected() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_attest_verifier(&pub_pem, "Global Trust Authority", Some("rbs"));
    let now = now_secs();
    let claims = json!({
        "iss": "wrong-issuer",
        "aud": "rbs",
        "exp": now + 3600,
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(AuthError::TokenInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_AttestFail_017
/// Malformed (non-JWT) token is rejected.
#[tokio::test]
async fn test_attest_fail_017_malformed_format_rejected() {
    let (pub_pem, _) = generate_rsa_keypair();
    let verifier = make_attest_verifier(&pub_pem, "Global Trust Authority", Some("rbs"));
    let result = verifier.verify(MALFORMED_TOKEN).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(AuthError::TokenInvalid { .. })));
}

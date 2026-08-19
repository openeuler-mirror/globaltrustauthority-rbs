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

//! Bearer token verification tests.
//!
//! Covers error unification, boundary values, and required claims validation.

use std::sync::Arc;

use serde_json::json;

use rbs_api_types::config::BearerTokenVerificationConfig;
use rbs_core::auth::authn::TokenVerifier;
use rbs_core::auth::{BearerTokenVerifier, LockoutTracker, UserKeyProvider};
use rbs_core::AuthError;

use super::common::*;

const ISSUER: &str = "test-issuer";
const AUDIENCE: &str = "test-audience";
const MALFORMED_TOKEN: &str = "not.a.valid.jwt.token";

// ===========================================================================
// RUST_GTA_RBS_TP_AUTH_BearerFail_010 — 错误统一化防用户枚举
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_AUTH_BearerFail_010
/// Malformed JWT returns TokenInvalid (unified as authentication failure).
#[tokio::test]
async fn test_bearer_fail_010_malformed_token() {
    let (pub_pem, _) = generate_rsa_keypair();
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::new(LockoutTracker::new()));
    let result = verifier.verify(MALFORMED_TOKEN).await;
    assert!(matches!(result, Err(AuthError::TokenInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_BearerFail_010
/// Expired JWT returns TokenExpired (unified as authentication failure).
#[tokio::test]
async fn test_bearer_fail_010_expired_token() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::new(LockoutTracker::new()));
    let now = now_secs();
    let claims = json!({
        "sub": "testuser",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now - 3600,
        "role": "admin",
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(matches!(result, Err(AuthError::TokenExpired)));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_BearerFail_010
/// Locked account returns AccountLocked (unified as authentication failure).
#[tokio::test]
async fn test_bearer_fail_010_locked_account() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let tracker = Arc::new(LockoutTracker::new());
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::clone(&tracker));

    for _ in 0..5 {
        tracker.record_failure("testuser");
    }

    let now = now_secs();
    let claims = json!({
        "sub": "testuser",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "role": "admin",
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(matches!(result, Err(AuthError::AccountLocked)));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_BearerFail_010
/// All three failure modes (TokenInvalid, TokenExpired, AccountLocked) are
/// distinct AuthError variants but are uniformly authentication failures.
#[tokio::test]
async fn test_bearer_fail_010_all_errors_are_auth_errors() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let tracker = Arc::new(LockoutTracker::new());
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::clone(&tracker));

    let err1 = verifier.verify(MALFORMED_TOKEN).await.unwrap_err();
    let now = now_secs();
    let expired_claims = json!({"sub":"u","iss":ISSUER,"aud":AUDIENCE,"exp":now-3600});
    let err2 = verifier.verify(&sign_ps256_jwt(&priv_pem, expired_claims)).await.unwrap_err();

    for _ in 0..5 {
        tracker.record_failure("u");
    }
    let locked_claims = json!({"sub":"u","iss":ISSUER,"aud":AUDIENCE,"exp":now+3600});
    let err3 = verifier.verify(&sign_ps256_jwt(&priv_pem, locked_claims)).await.unwrap_err();

    assert!(matches!(err1, AuthError::TokenInvalid { .. }));
    assert!(matches!(err2, AuthError::TokenExpired));
    assert!(matches!(err3, AuthError::AccountLocked));
}

// ===========================================================================
// RUST_GTA_RBS_TP_AUTH_BearerBoundary_011 — Bearer token exp临界值和claims边界
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_AUTH_BearerBoundary_011
/// JWT with exp at the current timestamp boundary is rejected as expired.
/// (jsonwebtoken 10.x default leeway is 60s; exp must be past the leeway.)
#[tokio::test]
async fn test_bearer_boundary_011_exp_at_current_timestamp() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::new(LockoutTracker::new()));
    let now = now_secs();
    let claims = json!({
        "sub": "testuser",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now - 61,
        "role": "admin",
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(matches!(result, Err(AuthError::TokenExpired)));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_BearerBoundary_011
/// JWT with empty sub ("") is rejected because the key provider cannot find the user.
#[tokio::test]
async fn test_bearer_boundary_011_empty_sub_rejected() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let config = BearerTokenVerificationConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
    };
    let key_provider: Arc<dyn UserKeyProvider> = Arc::new(SelectiveStubKeyProvider {
        pem: pub_pem,
        nonexistent_subs: vec![String::new()],
    });
    let verifier = BearerTokenVerifier::new(config, key_provider, Arc::new(LockoutTracker::new()));

    let now = now_secs();
    let claims = json!({
        "sub": "",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(matches!(result, Err(AuthError::TokenInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_BearerBoundary_011
/// JWT without a role claim authenticates successfully; role defaults to empty string.
#[tokio::test]
async fn test_bearer_boundary_011_no_role_defaults_empty() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::new(LockoutTracker::new()));
    let now = now_secs();
    let claims = json!({
        "sub": "testuser",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().role, "");
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_BearerBoundary_011
/// JWT with only sub/exp/iss/aud (minimal required claims) authenticates successfully.
#[tokio::test]
async fn test_bearer_boundary_011_minimal_claims_succeeds() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::new(LockoutTracker::new()));
    let now = now_secs();
    let claims = json!({
        "sub": "testuser",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(result.is_ok());
    let ctx = result.unwrap();
    assert_eq!(ctx.sub, "testuser");
    assert_eq!(ctx.role, "");
}

// ===========================================================================
// RUST_GTA_RBS_TP_AUTH_ClaimsRequired_029 — Bearer JWT claims必填校验
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ClaimsRequired_029
/// JWT missing the sub claim is rejected with TokenInvalid.
#[tokio::test]
async fn test_claims_required_029_missing_sub_rejected() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::new(LockoutTracker::new()));
    let now = now_secs();
    let claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "role": "admin",
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(matches!(result, Err(AuthError::TokenInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ClaimsRequired_029
/// JWT missing the exp claim is rejected (jsonwebtoken requires exp).
#[tokio::test]
async fn test_claims_required_029_missing_exp_rejected() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::new(LockoutTracker::new()));
    let claims = json!({
        "sub": "testuser",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "role": "admin",
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(matches!(result, Err(AuthError::TokenInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ClaimsRequired_029
/// JWT with a mismatched issuer is rejected with TokenInvalid.
#[tokio::test]
async fn test_claims_required_029_iss_mismatch_rejected() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::new(LockoutTracker::new()));
    let now = now_secs();
    let claims = json!({
        "sub": "testuser",
        "iss": "wrong-issuer",
        "aud": AUDIENCE,
        "exp": now + 3600,
        "role": "admin",
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(matches!(result, Err(AuthError::TokenInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ClaimsRequired_029
/// JWT without a role claim authenticates successfully; role defaults to empty string.
#[tokio::test]
async fn test_claims_required_029_no_role_defaults_empty() {
    let (pub_pem, priv_pem) = generate_rsa_keypair();
    let verifier = make_bearer_verifier(&pub_pem, ISSUER, AUDIENCE, Arc::new(LockoutTracker::new()));
    let now = now_secs();
    let claims = json!({
        "sub": "testuser",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
    });
    let token = sign_ps256_jwt(&priv_pem, claims);
    let result = verifier.verify(&token).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().role, "");
}

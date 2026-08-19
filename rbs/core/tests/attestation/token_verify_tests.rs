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

//! Tests for `AttestTokenVerifier` token verification (invalid signature, missing claims).

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rbs_api_types::config::AttestTokenVerificationConfig;
use rbs_core::auth::authn::TokenVerifier;
use rbs_core::auth::{AuthError, AttestTokenVerifier};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

/// Generate an RSA-2048 key pair and return (private_key_pem, public_key_pem).
fn generate_rsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let rsa = openssl::rsa::Rsa::generate(2048).expect("generate RSA key");
    let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("create PKey");
    let private_pem = pkey.private_key_to_pem_pkcs8().expect("export private PEM");
    let public_pem = pkey.public_key_to_pem().expect("export public PEM");
    (private_pem, public_pem)
}

/// Write the given PEM bytes to a NamedTempFile and return the file (keeps it alive).
fn write_key_file(pem: &[u8]) -> NamedTempFile {
    use std::io::Write;
    let mut file = NamedTempFile::new().expect("create temp file");
    file.write_all(pem).expect("write public key PEM");
    file.flush().expect("flush");
    file
}

/// Create an AttestTokenVerifier pointing at the given public key file path.
fn make_verifier(pub_key_path: &str) -> AttestTokenVerifier {
    let config = AttestTokenVerificationConfig {
        public_key_path: Some(pub_key_path.to_string()),
        jwks_file: None,
        issuer: "Global Trust Authority".to_string(),
        audience: Some("rbs".to_string()),
    };
    AttestTokenVerifier::new(config).expect("failed to create verifier")
}

/// Sign a JWT with PS256 using the given private key PEM and claims.
fn sign_jwt(private_pem: &[u8], claims: &serde_json::Value) -> String {
    let header = Header::new(Algorithm::PS256);
    let key = EncodingKey::from_rsa_pem(private_pem).expect("create encoding key");
    encode(&header, claims, &key).expect("encode JWT")
}

fn future_ts() -> u64 {
    (SystemTime::now() + std::time::Duration::from_secs(3600))
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn valid_claims() -> serde_json::Value {
    serde_json::json!({
        "sub": "test-subject",
        "iss": "Global Trust Authority",
        "aud": "rbs",
        "iat": now_ts(),
        "exp": future_ts(),
    })
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_TokenVerify_048
// token签名无效返回401 (TokenInvalid)
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_TokenVerify_048
/// 验证使用不同密钥签名的token(签名被篡改)返回TokenInvalid(对应401)。
#[tokio::test]
async fn test_token_verify_048_invalid_signature_returns_token_invalid() {
    let (_, pub_a) = generate_rsa_keypair();
    let (priv_b, _) = generate_rsa_keypair();

    let key_file = write_key_file(&pub_a);
    let verifier = make_verifier(key_file.path().to_str().unwrap());

    let token = sign_jwt(&priv_b, &valid_claims());
    let result = verifier.verify(&token).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthError::TokenInvalid { .. }
    ));
}

/// RUST_GTA_RBS_TP_ATTEST_TokenVerify_048
/// 验证同一密钥签名的有效token验证通过(对照实验)，确保测试设置正确。
#[tokio::test]
async fn test_token_verify_048_valid_signature_succeeds() {
    let (priv_a, pub_a) = generate_rsa_keypair();
    let key_file = write_key_file(&pub_a);
    let verifier = make_verifier(key_file.path().to_str().unwrap());

    let token = sign_jwt(&priv_a, &valid_claims());
    let result = verifier.verify(&token).await;

    assert!(result.is_ok(), "valid token should verify: {:?}", result.err());
}

/// RUST_GTA_RBS_TP_ATTEST_TokenVerify_048
/// 验证完全篡改的token字符串(非JWT格式)返回TokenInvalid。
#[tokio::test]
async fn test_token_verify_048_malformed_token_returns_token_invalid() {
    let (_, pub_a) = generate_rsa_keypair();
    let key_file = write_key_file(&pub_a);
    let verifier = make_verifier(key_file.path().to_str().unwrap());

    let result = verifier.verify("not.a.valid.token").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthError::TokenInvalid { .. }
    ));
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_TokenVerify_051
// token缺少必要claims返回401 (TokenInvalid)
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_TokenVerify_051
/// 验证缺少exp claim的token返回TokenInvalid(对应401)。
#[tokio::test]
async fn test_token_verify_051_missing_exp_returns_token_invalid() {
    let (priv_a, pub_a) = generate_rsa_keypair();
    let key_file = write_key_file(&pub_a);
    let verifier = make_verifier(key_file.path().to_str().unwrap());

    let claims = serde_json::json!({
        "sub": "test-subject",
        "iss": "Global Trust Authority",
        "aud": "rbs",
        "iat": now_ts(),
    });

    let token = sign_jwt(&priv_a, &claims);
    let result = verifier.verify(&token).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthError::TokenInvalid { .. }
    ));
}

/// RUST_GTA_RBS_TP_ATTEST_TokenVerify_051
/// 验证缺少iss claim的token返回TokenInvalid(对应401)。
#[tokio::test]
async fn test_token_verify_051_missing_iss_returns_token_invalid() {
    let (priv_a, pub_a) = generate_rsa_keypair();
    let key_file = write_key_file(&pub_a);
    let verifier = make_verifier(key_file.path().to_str().unwrap());

    let claims = serde_json::json!({
        "sub": "test-subject",
        "aud": "rbs",
        "iat": now_ts(),
        "exp": future_ts(),
    });

    let token = sign_jwt(&priv_a, &claims);
    let result = verifier.verify(&token).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthError::TokenInvalid { .. }
    ));
}

/// RUST_GTA_RBS_TP_ATTEST_TokenVerify_051
/// 验证同时缺少exp和iss claims的token返回TokenInvalid(对应401)。
#[tokio::test]
async fn test_token_verify_051_missing_both_claims_returns_token_invalid() {
    let (priv_a, pub_a) = generate_rsa_keypair();
    let key_file = write_key_file(&pub_a);
    let verifier = make_verifier(key_file.path().to_str().unwrap());

    let claims = serde_json::json!({
        "sub": "test-subject",
        "aud": "rbs",
    });

    let token = sign_jwt(&priv_a, &claims);
    let result = verifier.verify(&token).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthError::TokenInvalid { .. }
    ));
}

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

use base64::Engine as _;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use rbc::error::RbcError;
use rbc::tools::tee_key::{KeyType, TeeKeyPair, TeePublicKey};

fn encrypted_ec_pem(passphrase: &[u8]) -> (TeeKeyPair, String) {
    let kp = TeeKeyPair::generate(KeyType::Ec).unwrap();
    let plain_pem = kp.to_private_pem().unwrap();
    let pkey = PKey::private_key_from_pem(plain_pem.as_bytes()).unwrap();
    let enc_bytes = pkey
        .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase)
        .unwrap();
    (kp, String::from_utf8(enc_bytes).unwrap())
}

#[test]
fn test_rsa_generate_and_public_jwk_json() {
    let kp = TeeKeyPair::generate(KeyType::Rsa).unwrap();
    let json = kp.public_jwk_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kty"], "RSA");
    assert!(parsed.get("n").is_some());
    assert!(parsed.get("e").is_some());
    // Must NOT contain private key fields
    assert!(parsed.get("d").is_none());
}

#[test]
fn test_ec_generate_and_public_jwk_json() {
    let kp = TeeKeyPair::generate(KeyType::Ec).unwrap();
    let json = kp.public_jwk_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["kty"], "EC");
    assert_eq!(parsed["crv"], "P-256");
    assert!(parsed.get("x").is_some());
    assert!(parsed.get("y").is_some());
    assert!(parsed.get("d").is_none());
}

// ── JWE encrypt/decrypt round-trip ──

#[test]
fn test_rsa_jwe_round_trip() {
    let kp = TeeKeyPair::generate(KeyType::Rsa).unwrap();
    let pub_key = kp.public_key();
    let plaintext = b"hello RSA-OAEP + A256GCM";

    let jwe_token = pub_key.encrypt_jwe(plaintext).unwrap();
    let decrypted = kp.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_ec_jwe_round_trip() {
    let kp = TeeKeyPair::generate(KeyType::Ec).unwrap();
    let pub_key = kp.public_key();
    let plaintext = b"hello ECDH-ES+A256KW + A256GCM";

    let jwe_token = pub_key.encrypt_jwe(plaintext).unwrap();
    let decrypted = kp.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_rsa_from_jwk_json_encrypt_decrypt() {
    let kp = TeeKeyPair::generate(KeyType::Rsa).unwrap();
    let json = kp.public_jwk_json().unwrap();

    // Server side: load public key from JWK JSON
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    let jwe_token = pub_key.encrypt_jwe(b"secret data").unwrap();

    // Client side: decrypt with key pair
    let decrypted = kp.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, b"secret data");
}

#[test]
fn test_ec_from_jwk_json_encrypt_decrypt() {
    let kp = TeeKeyPair::generate(KeyType::Ec).unwrap();
    let json = kp.public_jwk_json().unwrap();

    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    let jwe_token = pub_key.encrypt_jwe(b"secret data").unwrap();

    let decrypted = kp.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, b"secret data");
}

#[test]
fn test_from_jwk_json_infers_rsa() {
    let kp = TeeKeyPair::generate(KeyType::Rsa).unwrap();
    let json = kp.public_jwk_json().unwrap();
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    // Encrypt should work (proves algorithm was correctly inferred)
    pub_key.encrypt_jwe(b"test").unwrap();
}

#[test]
fn test_from_jwk_json_infers_ec() {
    let kp = TeeKeyPair::generate(KeyType::Ec).unwrap();
    let json = kp.public_jwk_json().unwrap();
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    pub_key.encrypt_jwe(b"test").unwrap();
}

#[test]
fn test_from_jwk_json_rejects_unknown_kty() {
    let json = r#"{"kty":"OKP","crv":"Ed25519","x":"abc"}"#;
    let result = TeePublicKey::from_jwk_json(json);
    assert!(result.is_err());
}

#[test]
fn test_rsa_from_private_pem_round_trip() {
    // Generate a key pair, export private PEM, reload, and verify decrypt works
    let kp = TeeKeyPair::generate(KeyType::Rsa).unwrap();
    let pub_key = kp.public_key();
    let jwe_token = pub_key.encrypt_jwe(b"pem test").unwrap();

    // Export private key as PEM via josekit internals (for test only)
    let priv_pem = kp.to_private_pem().unwrap();

    let kp2 = TeeKeyPair::from_private_pem(KeyType::Rsa, &priv_pem, None).unwrap();
    let decrypted = kp2.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, b"pem test");
}

#[test]
fn test_ec_from_private_pem_round_trip() {
    let kp = TeeKeyPair::generate(KeyType::Ec).unwrap();
    let pub_key = kp.public_key();
    let jwe_token = pub_key.encrypt_jwe(b"pem test").unwrap();

    let priv_pem = kp.to_private_pem().unwrap();

    let kp2 = TeeKeyPair::from_private_pem(KeyType::Ec, &priv_pem, None).unwrap();
    let decrypted = kp2.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, b"pem test");
}

#[test]
fn test_public_key_jwk_json_matches() {
    let kp = TeeKeyPair::generate(KeyType::Ec).unwrap();

    let pub_key = kp.public_key();
    // Encrypt with extracted public key, decrypt with original key pair
    let jwe_token = pub_key.encrypt_jwe(b"match test").unwrap();
    let decrypted = kp.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, b"match test");
}

// ── validate_params: RSA rejection paths ──

#[test]
fn validate_params_rejects_rsa_missing_n() {
    // RSA JWK without 'n' field
    let json = r#"{"kty":"RSA","e":"AQAB"}"#;
    let pub_key = TeePublicKey::from_jwk_json(json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

#[test]
fn validate_params_rejects_rsa_missing_e() {
    // RSA JWK with valid-length 'n' but no 'e'
    // n = 512 bytes of 0xFF = 4096 bits
    let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0xffu8; 512]);
    let json = format!(r#"{{"kty":"RSA","n":"{n_b64}"}}"#);
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

#[test]
fn validate_params_rejects_rsa_key_below_4096_bits() {
    // n = 256 bytes = 2048 bits, below minimum
    let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0xffu8; 256]);
    let json = format!(r#"{{"kty":"RSA","n":"{n_b64}","e":"AQAB"}}"#);
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
    assert!(err.to_string().contains("bits"), "error should mention bits: {err}");
}

#[test]
fn validate_params_rejects_rsa_disallowed_alg() {
    let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0xffu8; 512]);
    let json = format!(r#"{{"kty":"RSA","n":"{n_b64}","e":"AQAB","alg":"RS256"}}"#);
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

// ── validate_params: EC rejection paths ──

#[test]
fn validate_params_rejects_ec_missing_crv() {
    // Valid base64url coordinates but no 'crv' field
    let x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    let y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    let json = format!(r#"{{"kty":"EC","x":"{x}","y":"{y}"}}"#);
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

#[test]
fn validate_params_rejects_ec_disallowed_curve() {
    // secp256k1 is not in the allowlist
    let x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    let y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    let json = format!(r#"{{"kty":"EC","crv":"secp256k1","x":"{x}","y":"{y}"}}"#);
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

#[test]
fn validate_params_rejects_ec_missing_x() {
    let json = r#"{"kty":"EC","crv":"P-256","y":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"}"#;
    let pub_key = TeePublicKey::from_jwk_json(json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

#[test]
fn validate_params_rejects_ec_missing_y() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"}"#;
    let pub_key = TeePublicKey::from_jwk_json(json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

#[test]
fn validate_params_rejects_ec_disallowed_alg() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","alg":"ECDH-ES"}"#;
    let pub_key = TeePublicKey::from_jwk_json(json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

#[test]
fn from_jwk_json_rejects_malformed_ec_coordinate_as_invalid_input() {
    // josekit rejects non-base64url x at parse time; after P1-3 fix this must be InvalidInput
    let json = r#"{"kty":"EC","crv":"P-256","x":"!!!not-base64!!!","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
    let err = TeePublicKey::from_jwk_json(json)
        .err().expect("should return Err");
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

#[test]
fn validate_params_rejects_ec_wrong_coordinate_length_for_curve() {
    // x/y are valid base64url but 16 bytes — wrong for P-256 (should be 32)
    let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 16]);
    let json = format!(r#"{{"kty":"EC","crv":"P-256","x":"{short}","y":"{short}"}}"#);
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    let err = pub_key.validate_params().unwrap_err();
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

// ── encrypted PEM: from_private_pem with passphrase ──

#[test]
fn encrypted_ec_pem_correct_passphrase_roundtrip() {
    let (kp, enc_pem) = encrypted_ec_pem(b"correct-pass");
    let loaded = TeeKeyPair::from_private_pem(KeyType::Ec, &enc_pem, Some(b"correct-pass")).unwrap();
    let plaintext = b"enc pem roundtrip";
    let jwe = kp.public_key().encrypt_jwe(plaintext).unwrap();
    assert_eq!(loaded.decrypt_jwe(&jwe).unwrap(), plaintext);
}

#[test]
fn encrypted_ec_pem_wrong_passphrase_returns_error() {
    let (_kp, enc_pem) = encrypted_ec_pem(b"correct-pass");
    let err = TeeKeyPair::from_private_pem(KeyType::Ec, &enc_pem, Some(b"wrong"))
        .err()
        .unwrap();
    assert!(matches!(err, RbcError::KeyGenError(_)));
}

#[test]
fn encrypted_ec_pem_no_passphrase_returns_error() {
    let (_kp, enc_pem) = encrypted_ec_pem(b"secret");
    let err = TeeKeyPair::from_private_pem(KeyType::Ec, &enc_pem, None)
        .err()
        .unwrap();
    assert!(matches!(err, RbcError::KeyGenError(_)));
}

#[test]
fn encrypted_ec_pem_decrypt_jwe_end_to_end() {
    let (kp, enc_pem) = encrypted_ec_pem(b"jwe-pass");
    let plaintext = b"secret payload";
    let jwe = kp.public_key().encrypt_jwe(plaintext).unwrap();
    let loaded = TeeKeyPair::from_private_pem(KeyType::Ec, &enc_pem, Some(b"jwe-pass")).unwrap();
    assert_eq!(loaded.decrypt_jwe(&jwe).unwrap(), plaintext);
}

// ── from_jwk_json: error type ──

#[test]
fn from_jwk_json_parse_failure_returns_invalid_input() {
    let err = TeePublicKey::from_jwk_json("not json at all")
        .err().expect("should return Err");
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}

#[test]
fn from_jwk_json_unknown_kty_returns_invalid_input() {
    let json = r#"{"kty":"OKP","crv":"Ed25519","x":"abc"}"#;
    let err = TeePublicKey::from_jwk_json(json)
        .err().expect("should return Err");
    assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
}
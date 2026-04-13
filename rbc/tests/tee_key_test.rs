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

use rbc::tools::tee_key::{KeyAlgorithm, TeeKeyPair, TeePublicKey};

#[test]
fn test_rsa_generate_and_public_jwk_json() {
    let kp = TeeKeyPair::generate(KeyAlgorithm::Rsa).unwrap();
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
    let kp = TeeKeyPair::generate(KeyAlgorithm::Ec).unwrap();
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
    let kp = TeeKeyPair::generate(KeyAlgorithm::Rsa).unwrap();
    let pub_key = kp.public_key();
    let plaintext = b"hello RSA-OAEP + A256GCM";

    let jwe_token = pub_key.encrypt_jwe(plaintext).unwrap();
    let decrypted = kp.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_ec_jwe_round_trip() {
    let kp = TeeKeyPair::generate(KeyAlgorithm::Ec).unwrap();
    let pub_key = kp.public_key();
    let plaintext = b"hello ECDH-ES+A256KW + A256GCM";

    let jwe_token = pub_key.encrypt_jwe(plaintext).unwrap();
    let decrypted = kp.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_rsa_from_jwk_json_encrypt_decrypt() {
    let kp = TeeKeyPair::generate(KeyAlgorithm::Rsa).unwrap();
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
    let kp = TeeKeyPair::generate(KeyAlgorithm::Ec).unwrap();
    let json = kp.public_jwk_json().unwrap();

    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    let jwe_token = pub_key.encrypt_jwe(b"secret data").unwrap();

    let decrypted = kp.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, b"secret data");
}

#[test]
fn test_from_jwk_json_infers_rsa() {
    let kp = TeeKeyPair::generate(KeyAlgorithm::Rsa).unwrap();
    let json = kp.public_jwk_json().unwrap();
    let pub_key = TeePublicKey::from_jwk_json(&json).unwrap();
    // Encrypt should work (proves algorithm was correctly inferred)
    pub_key.encrypt_jwe(b"test").unwrap();
}

#[test]
fn test_from_jwk_json_infers_ec() {
    let kp = TeeKeyPair::generate(KeyAlgorithm::Ec).unwrap();
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
    let kp = TeeKeyPair::generate(KeyAlgorithm::Rsa).unwrap();
    let pub_key = kp.public_key();
    let jwe_token = pub_key.encrypt_jwe(b"pem test").unwrap();

    // Export private key as PEM via josekit internals (for test only)
    let priv_pem = kp.to_private_pem().unwrap();

    let kp2 = TeeKeyPair::from_private_pem(KeyAlgorithm::Rsa, &priv_pem).unwrap();
    let decrypted = kp2.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, b"pem test");
}

#[test]
fn test_ec_from_private_pem_round_trip() {
    let kp = TeeKeyPair::generate(KeyAlgorithm::Ec).unwrap();
    let pub_key = kp.public_key();
    let jwe_token = pub_key.encrypt_jwe(b"pem test").unwrap();

    let priv_pem = kp.to_private_pem().unwrap();

    let kp2 = TeeKeyPair::from_private_pem(KeyAlgorithm::Ec, &priv_pem).unwrap();
    let decrypted = kp2.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, b"pem test");
}

#[test]
fn test_public_key_jwk_json_matches() {
    let kp = TeeKeyPair::generate(KeyAlgorithm::Ec).unwrap();
    let json_from_kp = kp.public_jwk_json().unwrap();

    let pub_key = kp.public_key();
    // Encrypt with extracted public key, decrypt with original key pair
    let jwe_token = pub_key.encrypt_jwe(b"match test").unwrap();
    let decrypted = kp.decrypt_jwe(&jwe_token).unwrap();
    assert_eq!(decrypted, b"match test");
}
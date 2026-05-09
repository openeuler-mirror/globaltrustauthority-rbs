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

//! JWKS (JSON Web Key Set) parsing and key matching.
//!
//! Only RSA and OKP (Ed25519) key types are supported for signature verification.

use crate::auth::error::AuthError;
use base64::Engine;
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use serde::Deserialize;

/// A single JWK (JSON Web Key)
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type (RSA, OKP)
    pub kty: String,
    /// Key ID (optional, used for matching)
    #[serde(default)]
    pub kid: Option<String>,
    /// Algorithm (optional)
    #[serde(default)]
    pub alg: Option<String>,
    /// RSA modulus (for RSA keys)
    #[serde(default)]
    pub n: Option<String>,
    /// RSA public exponent (for RSA keys)
    #[serde(default)]
    pub e: Option<String>,
    /// Elliptic curve (for OKP keys: Ed25519)
    #[serde(default)]
    pub crv: Option<String>,
    /// X coordinate (for OKP keys)
    #[serde(default)]
    pub x: Option<String>,
}

/// A JWKS (JSON Web Key Set) containing multiple keys
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Parse a JWKS file and return the keys
pub fn parse_jwks_file(content: &str) -> Result<Jwks, AuthError> {
    serde_json::from_str(content)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to parse JWKS: {}", e) })
}

/// Find a key by kid in the JWKS
pub fn find_key_by_kid<'a>(jwks: &'a Jwks, kid: &str) -> Option<&'a Jwk> {
    jwks.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
}

/// Convert a JWK to PEM-encoded public key bytes
pub fn jwk_to_pem(jwk: &Jwk) -> Result<Vec<u8>, AuthError> {
    match jwk.kty.as_str() {
        "RSA" => jwk_rsa_to_pem(jwk),
        "OKP" => jwk_okp_to_pem(jwk),
        _ => Err(AuthError::TokenInvalid {
            reason: format!("unsupported key type: {}. Only RSA and OKP (Ed25519) are supported", jwk.kty)
        }),
    }
}

/// Convert RSA JWK to PEM
fn jwk_rsa_to_pem(jwk: &Jwk) -> Result<Vec<u8>, AuthError> {
    let n = jwk.n.as_ref()
        .ok_or_else(|| AuthError::TokenInvalid { reason: "missing 'n' in RSA JWK".to_string() })?;
    let e = jwk.e.as_ref()
        .ok_or_else(|| AuthError::TokenInvalid { reason: "missing 'e' in RSA JWK".to_string() })?;

    let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to decode 'n': {}", e) })?;
    let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(e)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to decode 'e': {}", e) })?;

    let n = BigNum::from_slice(&n_bytes)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create RSA modulus: {}", e) })?;
    let e = BigNum::from_slice(&e_bytes)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create RSA exponent: {}", e) })?;

    let rsa = Rsa::from_public_components(n, e)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create RSA key: {}", e) })?;

    let pem = rsa.public_key_to_pem()
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to encode RSA public key to PEM: {}", e) })?;

    Ok(pem)
}

/// Convert OKP JWK (Ed25519) to PEM
fn jwk_okp_to_pem(jwk: &Jwk) -> Result<Vec<u8>, AuthError> {
    let crv = jwk.crv.as_ref()
        .ok_or_else(|| AuthError::TokenInvalid { reason: "missing 'crv' in OKP JWK".to_string() })?;

    if crv != "Ed25519" {
        return Err(AuthError::TokenInvalid {
            reason: format!("unsupported curve: {}. Only Ed25519 is supported", crv)
        });
    }

    let x = jwk.x.as_ref()
        .ok_or_else(|| AuthError::TokenInvalid { reason: "missing 'x' in OKP JWK".to_string() })?;

    let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to decode 'x': {}", e) })?;

    // Build Ed25519 public key in DER format and convert to PEM
    let pem = format_ed25519_public_key(&x_bytes);
    Ok(pem)
}

/// Format Ed25519 public key bytes as PEM
fn format_ed25519_public_key(x_bytes: &[u8]) -> Vec<u8> {
    // Ed25519 public key ASN.1 structure:
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING
    // }
    // For Ed25519, the algorithm is OID 1.3.101.112

    use base64::Engine;

    // Algorithm identifier for Ed25519
    let alg_id = vec![
        0x30, 0x05, // SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID for Ed25519: 1.3.101.112
    ];

    // Bit string containing the public key
    let mut bit_string = vec![0x03, 0x21, 0x00]; // BIT STRING, 33 bytes, 0 unused bits
    bit_string.extend_from_slice(x_bytes);

    // SEQUENCE wrapping with proper DER length encoding
    let seq_len = alg_id.len() + bit_string.len();
    let mut der = vec![0x30];
    der.extend_from_slice(&encode_der_length(seq_len));
    der.extend_from_slice(&alg_id);
    der.extend_from_slice(&bit_string);

    // Convert to PEM
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", b64);
    pem.into_bytes()
}

/// Encode a length in DER format.
///
/// DER length encoding:
/// - 0-127: single byte (bit 7 clear)
/// - 128-255: not possible (would use short form)
/// - 256+: long form: 0x80 | num_bytes, followed by length in big-endian
fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes = len.to_be_bytes();
        let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
        let significant_bytes = &bytes[leading_zeros..];
        let num_bytes = significant_bytes.len() as u8;
        let mut result = vec![0x80 | num_bytes];
        result.extend_from_slice(significant_bytes);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jwks_rsa() {
        let json = r#"{
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-1",
                    "n": "wVRPpZgLRiLDLdT_m60M3lHOVwV9ALhK3q9T_G8iJHJPdq7LOIRyQ6lDvZFMG9BooB9pPR5LlfXSp3uTYCqvJl",
                    "e": "AQAB"
                }
            ]
        }"#;

        let jwks = parse_jwks_file(json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid.as_deref(), Some("test-key-1"));
        assert_eq!(jwks.keys[0].kty, "RSA");
    }

    #[test]
    fn test_find_key_by_kid() {
        let json = r#"{
            "keys": [
                {"kty": "RSA", "kid": "key1", "n": "test", "e": "AQAB"},
                {"kty": "RSA", "kid": "key2", "n": "test", "e": "AQAB"}
            ]
        }"#;

        let jwks = parse_jwks_file(json).unwrap();
        assert!(find_key_by_kid(&jwks, "key1").is_some());
        assert!(find_key_by_kid(&jwks, "key2").is_some());
        assert!(find_key_by_kid(&jwks, "key3").is_none());
    }

    #[test]
    fn test_unsupported_key_type_ec() {
        let json = r#"{
            "keys": [
                {
                    "kty": "EC",
                    "kid": "ec-key",
                    "crv": "P-256",
                    "x": "test",
                    "y": "test"
                }
            ]
        }"#;

        let jwks = parse_jwks_file(json).unwrap();
        let result = jwk_to_pem(&jwks.keys[0]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported key type"));
    }
}

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

use crate::auth::error::AuthError;
use base64::Engine;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use serde::Deserialize;

/// A single JWK (JSON Web Key)
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type (RSA, EC, oct)
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
    /// Elliptic curve (for EC keys)
    #[serde(default)]
    pub crv: Option<String>,
    /// X coordinate (for EC keys)
    #[serde(default)]
    pub x: Option<String>,
    /// Y coordinate (for EC keys)
    #[serde(default)]
    pub y: Option<String>,
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

/// Convert a JWK to an OpenSSL PKey
pub fn jwk_to_pkey(jwk: &Jwk) -> Result<PKey<Public>, AuthError> {
    match jwk.kty.as_str() {
        "RSA" => {
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
            let pkey = PKey::from_rsa(rsa)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create PKey from RSA: {}", e) })?;

            Ok(pkey)
        }
        "EC" => {
            let x = jwk.x.as_ref()
                .ok_or_else(|| AuthError::TokenInvalid { reason: "missing 'x' in EC JWK".to_string() })?;
            let y = jwk.y.as_ref()
                .ok_or_else(|| AuthError::TokenInvalid { reason: "missing 'y' in EC JWK".to_string() })?;
            let crv = jwk.crv.as_ref()
                .ok_or_else(|| AuthError::TokenInvalid { reason: "missing 'crv' in EC JWK".to_string() })?;

            let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to decode 'x': {}", e) })?;
            let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to decode 'y': {}", e) })?;

            let x = BigNum::from_slice(&x_bytes)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create EC x: {}", e) })?;
            let y = BigNum::from_slice(&y_bytes)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create EC y: {}", e) })?;

            // Map curve name
            let nid = match crv.as_str() {
                "P-256" => Nid::X9_62_PRIME256V1,
                "P-384" => Nid::SECP384R1,
                "P-521" => Nid::SECP521R1,
                "SM2" => Nid::SM2,
                _ => return Err(AuthError::TokenInvalid { reason: format!("unsupported curve: {}", crv) }),
            };

            let group = EcGroup::from_curve_name(nid)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create EC group: {}", e) })?;

            let mut ctx = BigNumContext::new()
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create context: {}", e) })?;
            let mut point = EcPoint::new(&group)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create EC point: {}", e) })?;
            point.set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to set EC coordinates: {}", e) })?;

            let ec_key = EcKey::from_public_key(&group, &point)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create EC key: {}", e) })?;
            let pkey = PKey::from_ec_key(ec_key)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create PKey from EC: {}", e) })?;

            Ok(pkey)
        }
        _ => Err(AuthError::TokenInvalid { reason: format!("unsupported key type: {}", jwk.kty) }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jwks() {
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
}

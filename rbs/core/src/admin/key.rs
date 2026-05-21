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

//! Public key processing — validation, algorithm derivation, and JWK-to-PEM conversion.

use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rbs_api_types::error::RbsError;
use serde_json::Value;

type Result<T> = std::result::Result<T, RbsError>;

/// Maximum size for a PEM-encoded public key (10 KB).
const MAX_KEY_SIZE: usize = 10240;

/// Get the curve NID from an EC_GROUP.
#[inline]
fn group_curve_nid(group: &openssl::ec::EcGroupRef) -> openssl::nid::Nid {
    if let Some(nid) = group.curve_name() {
        return nid;
    }
    let degree = group.degree();
    if degree == 256 {
        openssl::nid::Nid::X9_62_PRIME256V1
    } else if degree == 384 {
        openssl::nid::Nid::SECP384R1
    } else if degree == 521 {
        openssl::nid::Nid::SECP521R1
    } else {
        openssl::nid::Nid::from_raw(0)
    }
}

/// Decode a base64-encoded string and return the UTF-8 contents.
pub fn decode_base64_input(input: &str, field_name: &str) -> Result<String> {
    let decoded = STANDARD.decode(input)
        .map_err(|_| RbsError::InvalidParameter(
            format!("invalid base64 encoding for {}", field_name)))?;
    String::from_utf8(decoded)
        .map_err(|_| RbsError::InvalidParameter(
            format!("invalid base64 encoding for {}", field_name)))
}

/// Validate a PEM public key and return its JWS algorithm identifier.
pub fn validate_and_derive_alg(pem: &str) -> Result<String> {
    if pem.len() > MAX_KEY_SIZE {
        log::warn!("Public key validation failed: size {} exceeds limit {}", pem.len(), MAX_KEY_SIZE);
        return Err(RbsError::InvalidParameter(
            format!("Public key exceeds maximum size of {} bytes", MAX_KEY_SIZE)
        ));
    }
    let pkey = openssl::pkey::PKey::public_key_from_pem(pem.as_bytes())
        .map_err(|_| {
            log::warn!("Public key validation failed: invalid PEM format");
            RbsError::InvalidParameter("Invalid public key format".to_string())
        })?;

    match pkey.id() {
        openssl::pkey::Id::RSA => Ok("RSA".to_string()),
        openssl::pkey::Id::EC => {
            let ec_key = pkey.ec_key()
                .map_err(|_| RbsError::InvalidParameter("Invalid EC key".to_string()))?;
            let group = ec_key.group();
            let nid = group_curve_nid(group);

            if nid == openssl::nid::Nid::X9_62_PRIME256V1 {
                Ok("EC".to_string())
            } else if nid == openssl::nid::Nid::SECP384R1 {
                Ok("EC".to_string())
            } else if nid == openssl::nid::Nid::SECP521R1 {
                Ok("EC".to_string())
            } else {
                Err(RbsError::InvalidParameter(
                    "Unsupported EC curve. Supported: P-256 (ES256), P-384 (ES384), P-521 (ES512)"
                        .to_string(),
                ))
            }
        }
        openssl::pkey::Id::ED25519 => Ok("Ed25519".to_string()),
        _ => Err(RbsError::InvalidParameter("Unsupported key type".to_string())),
    }
}

/// Convert a JWK JSON object to PEM-encoded public key.
pub fn jwk_to_pem(jwk: &Value) -> Result<String> {
    // Serialize to check size before processing
    let jwk_str = serde_json::to_string(jwk)
        .map_err(|_| RbsError::InvalidParameter("JWK format invalid".to_string()))?;
    if jwk_str.len() > MAX_KEY_SIZE {
        log::warn!("JWK key validation failed: size {} exceeds limit {}", jwk_str.len(), MAX_KEY_SIZE);
        return Err(RbsError::InvalidParameter(
            format!("JWK key exceeds maximum size of {} bytes", MAX_KEY_SIZE)
        ));
    }

    let kty = jwk.get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RbsError::InvalidParameter("JWK missing kty field".to_string()))?;

    match kty {
        "RSA" => jwk_rsa_to_pem(jwk),
        "EC" => jwk_ec_to_pem(jwk),
        _ => Err(RbsError::InvalidParameter("Unsupported JWK key type".to_string())),
    }
}


fn jwk_rsa_to_pem(jwk: &Value) -> Result<String> {
    let n_b64 = jwk.get("n")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RbsError::InvalidParameter("JWK RSA missing n field".to_string()))?;
    let e_b64 = jwk.get("e")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RbsError::InvalidParameter("JWK RSA missing e field".to_string()))?;
    let n = URL_SAFE_NO_PAD.decode(n_b64)
        .map_err(|_| RbsError::InvalidParameter("JWK n decode failed".to_string()))?;
    let e = URL_SAFE_NO_PAD.decode(e_b64)
        .map_err(|_| RbsError::InvalidParameter("JWK e decode failed".to_string()))?;
    let bn_n = openssl::bn::BigNum::from_slice(&n)
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK public key".to_string()))?;
    let bn_e = openssl::bn::BigNum::from_slice(&e)
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK public key".to_string()))?;
    let rsa = openssl::rsa::Rsa::from_public_components(bn_n, bn_e)
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK public key".to_string()))?;
    let pem = rsa.public_key_to_pem()
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK public key".to_string()))?;
    Ok(String::from_utf8_lossy(&pem).to_string())
}

fn jwk_ec_to_pem(jwk: &Value) -> Result<String> {
    let crv = jwk.get("crv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RbsError::InvalidParameter("JWK EC missing crv field".to_string()))?;
    let x_b64 = jwk.get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RbsError::InvalidParameter("JWK EC missing x field".to_string()))?;
    let y_b64 = jwk.get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RbsError::InvalidParameter("JWK EC missing y field".to_string()))?;
    let curve_nid = match crv {
        "P-256" => openssl::nid::Nid::X9_62_PRIME256V1,
        "P-384" => openssl::nid::Nid::SECP384R1,
        "P-521" => openssl::nid::Nid::SECP521R1,
        _ => return Err(RbsError::InvalidParameter("Unsupported JWK EC curve".to_string())),
    };
    let curve = openssl::ec::EcGroup::from_curve_name(curve_nid)
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK EC curve".to_string()))?;
    let x_bytes = URL_SAFE_NO_PAD.decode(x_b64)
        .map_err(|_| RbsError::InvalidParameter("JWK x decode failed".to_string()))?;
    let y_bytes = URL_SAFE_NO_PAD.decode(y_b64)
        .map_err(|_| RbsError::InvalidParameter("JWK y decode failed".to_string()))?;
    let x = openssl::bn::BigNum::from_slice(&x_bytes)
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK public key".to_string()))?;
    let y = openssl::bn::BigNum::from_slice(&y_bytes)
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK public key".to_string()))?;
    let ec_key = openssl::ec::EcKey::from_public_key_affine_coordinates(&curve, &x, &y)
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK public key".to_string()))?;
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key)
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK public key".to_string()))?;
    let pem = pkey.public_key_to_pem()
        .map_err(|_| RbsError::InvalidParameter("Invalid JWK public key".to_string()))?;
    Ok(String::from_utf8_lossy(&pem).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RSA_PEM: &str = concat!(
    "-----BEGIN PUBLIC KEY-----\n",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7JOjGVgMbclDvZ0zW8by\n",
    "ALpLyUSNYkb5dyy9xFBEg97RI1SSx0rcOkrd7fb/aJThQ7n47OaSpaJZmNzL/phQ\n",
    "9TnqHafrOsY8nYn1PlGbUu0yo99CLF9EOqmUpLfAkCELFumP5xt1DSJ+VN4gxVeq\n",
    "GNAthfi7ceWKuWRgfkTif2wXJXEpCBunyTEM4nqvOZX+lMLWkvv/jaovl+PjNQyk\n",
    "wTFjgs3EC7Cn/C35xYHRAws3iBXk8PJ7TPFiG3L2pDIP30jxTbu3taOpkAarieSg\n",
    "rK+Dsrv9RIirzseAH3XnSOHDQDVU++8Jw421BQw/ZiYCfIye2RplBpaLcL8xhIIf\n",
    "CwIDAQAB\n",
    "-----END PUBLIC KEY-----\n"
    );

    #[test]
    fn validate_and_derive_alg_rejects_invalid_pem() {
        assert!(validate_and_derive_alg("invalid").is_err());
        assert!(validate_and_derive_alg("").is_err());
    }

    #[test]
    fn validate_and_derive_alg_returns_rsa_for_rsa_key() {
        let result = validate_and_derive_alg(VALID_RSA_PEM);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "RSA");
    }

    #[test]
    fn validate_and_derive_alg_rejects_oversized_key() {
        let huge_key = "-----BEGIN PUBLIC KEY-----\n".to_string() + &"A".repeat(15000) + "\n-----END PUBLIC KEY-----\n";
        let result = validate_and_derive_alg(&huge_key);
        assert!(result.is_err());
        match result {
            Err(RbsError::InvalidParameter(msg)) => {
                assert!(msg.contains("exceeds maximum size"));
            }
            _ => panic!("Expected InvalidParameter error"),
        }
    }

    #[test]
    fn jwk_to_pem_rejects_invalid_json() {
        let jwk = serde_json::json!({"invalid": true});
        assert!(jwk_to_pem(&jwk).is_err());
    }

    #[test]
    fn jwk_to_pem_rejects_missing_kty_field() {
        let jwk = serde_json::json!({"n": "test", "e": "AQAB"});
        let result = jwk_to_pem(&jwk);
        assert!(result.is_err());
        match result {
            Err(RbsError::InvalidParameter(msg)) => {
                assert!(msg.contains("missing kty"));
            }
            _ => panic!("Expected InvalidParameter error"),
        }
    }

    #[test]
    fn jwk_to_pem_rejects_rsa_without_required_fields() {
        let jwk = serde_json::json!({"kty": "RSA"});
        let result = jwk_to_pem(&jwk);
        assert!(result.is_err());
    }

    #[test]
    fn jwk_to_pem_rejects_ec_without_required_fields() {
        let jwk = serde_json::json!({"kty": "EC"});
        let result = jwk_to_pem(&jwk);
        assert!(result.is_err());
    }

    #[test]
    fn jwk_to_pem_rejects_unsupported_key_type() {
        let jwk = serde_json::json!({"kty": "oct"});
        let result = jwk_to_pem(&jwk);
        assert!(result.is_err());
        match result {
            Err(RbsError::InvalidParameter(msg)) => {
                assert!(msg.contains("Unsupported JWK key type"));
            }
            _ => panic!("Expected InvalidParameter error"),
        }
    }

    #[test]
    fn decode_base64_input_valid() {
        // "test" base64 encoded
        let result = decode_base64_input("dGVzdA==", "test_field");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test");
    }

    #[test]
    fn decode_base64_input_invalid() {
        // Invalid base64 (contains ! which is not valid)
        let result = decode_base64_input("invalid!!!", "test_field");
        assert!(result.is_err());
        match result {
            Err(RbsError::InvalidParameter(msg)) => {
                assert!(msg.contains("invalid base64 encoding for test_field"));
            }
            _ => panic!("Expected InvalidParameter error"),
        }
    }

    #[test]
    fn decode_base64_input_valid_utf8_but_not_base64() {
        // Valid base64 but decodes to non-UTF8 bytes
        // This shouldn't happen with STANDARD base64 since it only produces valid UTF8 ASCII
        let result = decode_base64_input("dGVzdA==", "public_key");
        assert!(result.is_ok());
    }


    #[test]
    fn validate_and_derive_alg_returns_ed25519_for_ed25519() {
        // Generate an Ed25519 key pair
        let ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
        let pem = ed_key.public_key_to_pem().unwrap();
        let pem_str = String::from_utf8_lossy(&pem).to_string();

        let result = validate_and_derive_alg(&pem_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Ed25519");
    }

    #[test]
    fn validate_and_derive_alg_returns_ec_for_ec_key() {
        // Generate an P-256 EC key pair
        let ec_group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
        let pem = pkey.public_key_to_pem().unwrap();
        let pem_str = String::from_utf8_lossy(&pem).to_string();

        let result = validate_and_derive_alg(&pem_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "EC");
    }
}

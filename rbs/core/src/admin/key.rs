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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rbs_api_types::error::RbsError;
use serde_json::Value;

type Result<T> = std::result::Result<T, RbsError>;

/// Validate a PEM public key and return its JWS algorithm identifier.
pub fn validate_and_derive_alg(pem: &str) -> Result<String> {
    let pkey = openssl::pkey::PKey::public_key_from_pem(pem.as_bytes())
        .map_err(|_| {
            log::warn!("Public key validation failed: invalid PEM format");
            RbsError::InvalidParameter("Invalid public key format".to_string())
        })?;

    match pkey.id() {
        openssl::pkey::Id::RSA => Ok("RS256".to_string()),
        openssl::pkey::Id::EC => {
            let ec_key = pkey.ec_key()
                .map_err(|_| RbsError::InvalidParameter("Invalid public key format".to_string()))?;
            match ec_key.group().curve_name() {
                Some(openssl::nid::Nid::X9_62_PRIME256V1) => Ok("ES256".to_string()),
                Some(openssl::nid::Nid::SECP384R1) => Ok("ES384".to_string()),
                Some(openssl::nid::Nid::SECP521R1) => Ok("ES512".to_string()),
                _ => Err(RbsError::InvalidParameter("Unsupported EC curve".to_string())),
            }
        }
        _ => Err(RbsError::InvalidParameter("Unsupported key type".to_string())),
    }
}

/// Convert a JWK JSON object to PEM-encoded public key.
pub fn jwk_to_pem(jwk: &Value) -> Result<String> {
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

    #[test]
    fn test_validate_pem_invalid() {
        assert!(validate_and_derive_alg("invalid").is_err());
        assert!(validate_and_derive_alg("").is_err());
    }

    #[test]
    fn test_jwk_invalid() {
        let jwk = serde_json::json!({"invalid": true});
        assert!(jwk_to_pem(&jwk).is_err());
    }
}

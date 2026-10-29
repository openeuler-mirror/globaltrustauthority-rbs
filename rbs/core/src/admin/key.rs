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
/// Returns error if the curve is not a named curve — degree-based guessing is unsafe
/// because degree is not unique (e.g., secp256k1 also has degree 256).
#[inline]
fn group_curve_nid(group: &openssl::ec::EcGroupRef) -> Result<openssl::nid::Nid> {
    group
        .curve_name()
        .ok_or_else(|| RbsError::InvalidParameter("EC key must use a named curve (P-256, P-384, P-521)".to_string()))
}

/// Decode a base64-encoded string and return the UTF-8 contents.
pub fn decode_base64_input(input: &str, field_name: &str) -> Result<String> {
    let decoded = STANDARD.decode(input).map_err(|_| {
        log::error!("Base64 decoding failed for field '{}': input is not valid base64", field_name);
        RbsError::InvalidParameter(format!("invalid base64 encoding for {}", field_name))
    })?;
    String::from_utf8(decoded).map_err(|_| {
        log::error!("Base64 decoding failed for field '{}': decoded bytes are not valid UTF-8", field_name);
        RbsError::InvalidParameter(format!("invalid base64 encoding for {}", field_name))
    })
}

/// Validate a PEM public key and return its key algorithm identifier.
pub fn validate_and_derive_alg(pem: &str) -> Result<String> {
    if pem.len() > MAX_KEY_SIZE {
        log::error!("Public key validation failed: size {} exceeds limit {}", pem.len(), MAX_KEY_SIZE);
        return Err(RbsError::InvalidParameter(format!("Public key exceeds maximum size of {} bytes", MAX_KEY_SIZE)));
    }
    let pkey = openssl::pkey::PKey::public_key_from_pem(pem.as_bytes()).map_err(|_| {
        log::error!("Public key validation failed: invalid PEM format");
        RbsError::InvalidParameter("Invalid public key format".to_string())
    })?;

    if matches!(pkey.id(), openssl::pkey::Id::RSA | openssl::pkey::Id::RSA_PSS) && pkey.bits() < 2048 {
        return Err(RbsError::InvalidParameter("RSA JWT keys must be at least 2048 bits".to_string()));
    }
    match pkey.id() {
        openssl::pkey::Id::RSA => Ok("RSA".to_string()),
        openssl::pkey::Id::RSA_PSS => Ok("RSA-PSS".to_string()),
        openssl::pkey::Id::EC => {
            let ec_key = pkey.ec_key().map_err(|_| RbsError::InvalidParameter("Invalid EC key".to_string()))?;
            let group = ec_key.group();
            let nid = group_curve_nid(group)?;

            if nid == openssl::nid::Nid::X9_62_PRIME256V1 {
                Ok("EC".to_string())
            } else if nid == openssl::nid::Nid::SECP384R1 {
                Ok("EC".to_string())
            } else if nid == openssl::nid::Nid::SECP521R1 {
                Ok("EC".to_string())
            } else {
                Err(RbsError::InvalidParameter(
                    "Unsupported EC curve. Supported: P-256 (ES256), P-384 (ES384), P-521 (ES512)".to_string(),
                ))
            }
        },
        openssl::pkey::Id::ED25519 => Ok("Ed25519".to_string()),
        _ => {
            // OpenSSL 3.x may report an SM2 public key's id as -1 (unknown) after
            // parsing a SubjectPublicKeyInfo PEM, so detect SM2 via the EC-specific
            // PEM parser, which preserves the curve NID.
            if let Ok(ec_key) = openssl::ec::EcKey::public_key_from_pem(pem.as_bytes()) {
                if ec_key.group().curve_name() == Some(openssl::nid::Nid::SM2) {
                    return Ok("SM2".to_string());
                }
            }
            Err(RbsError::InvalidParameter("Unsupported key type".to_string()))
        },
    }
}

/// Convert a JWK JSON object to PEM-encoded public key.
pub fn jwk_to_pem(jwk: &Value) -> Result<String> {
    // Serialize to check size before processing
    let jwk_str = serde_json::to_string(jwk).map_err(|_| {
        log::error!("JWK validation failed: unable to serialize input as JSON");
        RbsError::InvalidParameter("JWK format invalid".to_string())
    })?;
    if jwk_str.len() > MAX_KEY_SIZE {
        log::error!("JWK key validation failed: size {} exceeds limit {}", jwk_str.len(), MAX_KEY_SIZE);
        return Err(RbsError::InvalidParameter(format!("JWK key exceeds maximum size of {} bytes", MAX_KEY_SIZE)));
    }

    let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or_else(|| {
        log::error!("JWK validation failed: missing required 'kty' field");
        RbsError::InvalidParameter("JWK missing kty field".to_string())
    })?;

    match kty {
        "RSA" => jwk_rsa_to_pem(jwk),
        "EC" => jwk_ec_to_pem(jwk),
        _ => {
            log::error!("JWK validation failed: unsupported key type '{}'", kty);
            Err(RbsError::InvalidParameter("Unsupported JWK key type".to_string()))
        },
    }
}

fn jwk_rsa_to_pem(jwk: &Value) -> Result<String> {
    let n_b64 = jwk.get("n").and_then(|v| v.as_str()).ok_or_else(|| {
        log::error!("JWK RSA validation failed: missing required 'n' field");
        RbsError::InvalidParameter("JWK RSA missing n field".to_string())
    })?;
    let e_b64 = jwk.get("e").and_then(|v| v.as_str()).ok_or_else(|| {
        log::error!("JWK RSA validation failed: missing required 'e' field");
        RbsError::InvalidParameter("JWK RSA missing e field".to_string())
    })?;
    let n = URL_SAFE_NO_PAD.decode(n_b64).map_err(|_| {
        log::error!("JWK RSA validation failed: 'n' field is not valid base64url");
        RbsError::InvalidParameter("JWK n decode failed".to_string())
    })?;
    let e = URL_SAFE_NO_PAD.decode(e_b64).map_err(|_| {
        log::error!("JWK RSA validation failed: 'e' field is not valid base64url");
        RbsError::InvalidParameter("JWK e decode failed".to_string())
    })?;
    let bn_n = openssl::bn::BigNum::from_slice(&n).map_err(|_| {
        log::error!("JWK RSA validation failed: 'n' is not a valid big number");
        RbsError::InvalidParameter("Invalid JWK public key".to_string())
    })?;
    let bn_e = openssl::bn::BigNum::from_slice(&e).map_err(|_| {
        log::error!("JWK RSA validation failed: 'e' is not a valid big number");
        RbsError::InvalidParameter("Invalid JWK public key".to_string())
    })?;
    let rsa = openssl::rsa::Rsa::from_public_components(bn_n, bn_e).map_err(|_| {
        log::error!("JWK RSA validation failed: invalid RSA public key components");
        RbsError::InvalidParameter("Invalid JWK public key".to_string())
    })?;
    let pem = rsa.public_key_to_pem().map_err(|_| {
        log::error!("JWK RSA validation failed: unable to convert to PEM format");
        RbsError::InvalidParameter("Invalid JWK public key".to_string())
    })?;
    Ok(String::from_utf8_lossy(&pem).to_string())
}

fn jwk_ec_to_pem(jwk: &Value) -> Result<String> {
    let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or_else(|| {
        log::error!("JWK EC validation failed: missing required 'crv' field");
        RbsError::InvalidParameter("JWK EC missing crv field".to_string())
    })?;
    let x_b64 = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
        log::error!("JWK EC validation failed: missing required 'x' field");
        RbsError::InvalidParameter("JWK EC missing x field".to_string())
    })?;
    let y_b64 = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
        log::error!("JWK EC validation failed: missing required 'y' field");
        RbsError::InvalidParameter("JWK EC missing y field".to_string())
    })?;
    let curve_nid = match crv {
        "P-256" => openssl::nid::Nid::X9_62_PRIME256V1,
        "P-384" => openssl::nid::Nid::SECP384R1,
        "P-521" => openssl::nid::Nid::SECP521R1,
        "sm2p256v1" => openssl::nid::Nid::SM2,
        _ => {
            log::error!("JWK EC validation failed: unsupported curve '{}'", crv);
            return Err(RbsError::InvalidParameter("Unsupported JWK EC curve".to_string()));
        },
    };
    let curve = openssl::ec::EcGroup::from_curve_name(curve_nid).map_err(|_| {
        log::error!("JWK EC validation failed: unable to create curve group for '{}'", crv);
        RbsError::InvalidParameter("Invalid JWK EC curve".to_string())
    })?;
    let x_bytes = URL_SAFE_NO_PAD.decode(x_b64).map_err(|_| {
        log::error!("JWK EC validation failed: 'x' field is not valid base64url");
        RbsError::InvalidParameter("JWK x decode failed".to_string())
    })?;
    let y_bytes = URL_SAFE_NO_PAD.decode(y_b64).map_err(|_| {
        log::error!("JWK EC validation failed: 'y' field is not valid base64url");
        RbsError::InvalidParameter("JWK y decode failed".to_string())
    })?;
    let x = openssl::bn::BigNum::from_slice(&x_bytes).map_err(|_| {
        log::error!("JWK EC validation failed: 'x' is not a valid big number");
        RbsError::InvalidParameter("Invalid JWK public key".to_string())
    })?;
    let y = openssl::bn::BigNum::from_slice(&y_bytes).map_err(|_| {
        log::error!("JWK EC validation failed: 'y' is not a valid big number");
        RbsError::InvalidParameter("Invalid JWK public key".to_string())
    })?;
    let ec_key = openssl::ec::EcKey::from_public_key_affine_coordinates(&curve, &x, &y).map_err(|_| {
        log::error!("JWK EC validation failed: invalid EC public key coordinates");
        RbsError::InvalidParameter("Invalid JWK public key".to_string())
    })?;
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).map_err(|_| {
        log::error!("JWK EC validation failed: unable to construct PKey from EC key");
        RbsError::InvalidParameter("Invalid JWK public key".to_string())
    })?;
    let pem = pkey.public_key_to_pem().map_err(|_| {
        log::error!("JWK EC validation failed: unable to convert to PEM format");
        RbsError::InvalidParameter("Invalid JWK public key".to_string())
    })?;
    Ok(String::from_utf8_lossy(&pem).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwk::KeyPair;
    use josekit::jws::PS256;

    #[test]
    fn validate_and_derive_alg_rejects_invalid_pem() {
        assert!(validate_and_derive_alg("invalid").is_err());
        assert!(validate_and_derive_alg("").is_err());
    }

    #[test]
    fn validate_and_derive_alg_returns_rsa_for_rsa_key() {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        let pem = pkey.public_key_to_pem().unwrap();
        let pem_str = String::from_utf8_lossy(&pem).to_string();

        let result = validate_and_derive_alg(&pem_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "RSA");
    }

    #[test]
    fn validate_and_derive_alg_returns_rsa_pss_for_rsa_pss_key() {
        let key_pair = PS256.generate_key_pair(2048).expect("generate RSA-PSS key pair");
        let pem = String::from_utf8(key_pair.to_pem_public_key()).expect("RSA-PSS public key PEM");

        let result = validate_and_derive_alg(&pem);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "RSA-PSS");
    }

    #[test]
    fn validate_and_derive_alg_rejects_oversized_key() {
        let huge_key = "-----BEGIN PUBLIC KEY-----\n".to_string() + &"A".repeat(15000) + "\n-----END PUBLIC KEY-----\n";
        let result = validate_and_derive_alg(&huge_key);
        assert!(result.is_err());
        match result {
            Err(RbsError::InvalidParameter(msg)) => {
                assert!(msg.contains("exceeds maximum size"));
            },
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
            },
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
            },
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
            },
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

    #[test]
    fn validate_and_derive_alg_returns_sm2_for_sm2_key() {
        // SM2 EC key — OpenSSL 3.x reports its re-parsed id as -1, so the SM2
        // curve is detected via the EC-specific PEM parser.
        let ec_group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SM2).unwrap();
        let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
        let pem = pkey.public_key_to_pem().unwrap();
        let pem_str = String::from_utf8_lossy(&pem).to_string();

        let result = validate_and_derive_alg(&pem_str);
        assert!(result.is_ok(), "SM2 key should be accepted: {:?}", result.err());
        assert_eq!(result.unwrap(), "SM2");
    }

    #[test]
    fn reject_short_rsa_authentication_keys() {
        for kind in [openssl::pkey::Id::RSA, openssl::pkey::Id::RSA_PSS] {
            let mut ctx = openssl::pkey_ctx::PkeyCtx::new_id(kind).unwrap();
            ctx.keygen_init().unwrap();
            ctx.set_rsa_keygen_bits(1024).unwrap();
            let key = ctx.keygen().unwrap();
            let pem = String::from_utf8(key.public_key_to_pem().unwrap()).unwrap();
            assert!(validate_and_derive_alg(&pem).is_err());
        }
    }

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn rsa_jwk() -> Value {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa");
        json!({"kty": "RSA", "n": b64(&rsa.n().to_vec()), "e": b64(&rsa.e().to_vec())})
    }

    fn ec_key_and_jwk(curve: &str, nid: openssl::nid::Nid) -> (Value, String) {
        let group = openssl::ec::EcGroup::from_curve_name(nid).expect("group");
        let key = openssl::ec::EcKey::generate(&group).expect("ec key");
        let mut ctx = openssl::bn::BigNumContext::new().expect("bn ctx");
        let mut x = openssl::bn::BigNum::new().expect("x");
        let mut y = openssl::bn::BigNum::new().expect("y");
        key.public_key().affine_coordinates(&group, &mut x, &mut y, &mut ctx).expect("coords");
        let pkey = openssl::pkey::PKey::from_ec_key(key).expect("pkey");
        let pem = String::from_utf8(pkey.public_key_to_pem().expect("pem")).expect("utf8 pem");
        (json!({"kty": "EC", "crv": curve, "x": b64(&x.to_vec()), "y": b64(&y.to_vec())}), pem)
    }

    #[test]
    fn jwk_to_pem_accepts_supported_curves() {
        let (jwk_p256, pem_p256) = ec_key_and_jwk("P-256", openssl::nid::Nid::X9_62_PRIME256V1);
        assert!(jwk_to_pem(&jwk_p256).expect("p256 jwk").contains("BEGIN PUBLIC KEY"));
        assert_eq!(validate_and_derive_alg(&pem_p256).expect("p256 pem"), "EC");

        let (jwk_p384, pem_p384) = ec_key_and_jwk("P-384", openssl::nid::Nid::SECP384R1);
        assert!(jwk_to_pem(&jwk_p384).is_ok());
        assert_eq!(validate_and_derive_alg(&pem_p384).expect("p384 pem"), "EC");

        let (jwk_p521, pem_p521) = ec_key_and_jwk("P-521", openssl::nid::Nid::SECP521R1);
        assert!(jwk_to_pem(&jwk_p521).is_ok());
        assert_eq!(validate_and_derive_alg(&pem_p521).expect("p521 pem"), "EC");
    }

    #[test]
    fn jwk_to_pem_rejects_missing_rsa_components() {
        let jwk = rsa_jwk();
        let mut missing_e = jwk.clone();
        missing_e.as_object_mut().expect("object").remove("e");
        assert!(matches!(jwk_to_pem(&missing_e), Err(RbsError::InvalidParameter(_))));

        let mut missing_n = jwk;
        missing_n.as_object_mut().expect("object").remove("n");
        assert!(matches!(jwk_to_pem(&missing_n), Err(RbsError::InvalidParameter(_))));
    }

    #[test]
    fn jwk_to_pem_rejects_invalid_rsa_base64() {
        assert!(matches!(
            jwk_to_pem(&json!({"kty": "RSA", "n": "***", "e": "AQAB"})),
            Err(RbsError::InvalidParameter(_))
        ));
        assert!(matches!(
            jwk_to_pem(&json!({"kty": "RSA", "n": "AQAB", "e": "***"})),
            Err(RbsError::InvalidParameter(_))
        ));
    }

    #[test]
    fn jwk_to_pem_rejects_missing_ec_coordinates() {
        let (jwk, _) = ec_key_and_jwk("P-256", openssl::nid::Nid::X9_62_PRIME256V1);
        let mut missing_x = jwk.clone();
        missing_x.as_object_mut().expect("object").remove("x");
        assert!(matches!(jwk_to_pem(&missing_x), Err(RbsError::InvalidParameter(_))));

        let mut missing_y = jwk;
        missing_y.as_object_mut().expect("object").remove("y");
        assert!(matches!(jwk_to_pem(&missing_y), Err(RbsError::InvalidParameter(_))));
    }

    #[test]
    fn jwk_to_pem_rejects_unsupported_ec_curve() {
        let err =
            jwk_to_pem(&json!({"kty": "EC", "crv": "P-999", "x": "AQAB", "y": "AQAB"})).expect_err("unsupported curve");
        assert!(err.to_string().contains("Unsupported JWK EC curve"), "err: {err}");
    }

    #[test]
    fn jwk_to_pem_rejects_invalid_ec_coordinates() {
        let zero = b64(&[0u8; 32]);
        let err =
            jwk_to_pem(&json!({"kty": "EC", "crv": "P-256", "x": zero, "y": zero})).expect_err("off-curve coordinates");
        assert!(matches!(err, RbsError::InvalidParameter(_)));

        assert!(matches!(
            jwk_to_pem(&json!({"kty": "EC", "crv": "P-256", "x": "***", "y": "***"})),
            Err(RbsError::InvalidParameter(_))
        ));
    }

    #[test]
    fn jwk_to_pem_rejects_missing_kty_and_unknown_kty() {
        assert!(matches!(jwk_to_pem(&json!({"n": "AQAB", "e": "AQAB"})), Err(RbsError::InvalidParameter(_))));
        assert!(matches!(jwk_to_pem(&json!({"kty": "oct", "k": "secret"})), Err(RbsError::InvalidParameter(_))));
    }

    #[test]
    fn jwk_to_pem_rejects_oversized_input() {
        let err = jwk_to_pem(&json!({"kty": "RSA", "n": "a".repeat(MAX_KEY_SIZE)})).expect_err("oversized jwk");
        assert!(err.to_string().contains("maximum size"), "err: {err}");
    }

    #[test]
    fn validate_and_derive_alg_rejects_unsupported_ec_curve() {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1).expect("group");
        let key = openssl::ec::EcKey::generate(&group).expect("ec key");
        let pkey = openssl::pkey::PKey::from_ec_key(key).expect("pkey");
        let pem = String::from_utf8(pkey.public_key_to_pem().expect("pem")).expect("utf8 pem");
        let err = validate_and_derive_alg(&pem).expect_err("secp256k1 must be rejected");
        assert!(err.to_string().contains("Unsupported EC curve"), "err: {err}");
    }

    #[test]
    fn validate_and_derive_alg_rejects_oversized_and_malformed_pem() {
        let oversized = "a".repeat(MAX_KEY_SIZE + 1);
        assert!(validate_and_derive_alg(&oversized).is_err());
        assert!(validate_and_derive_alg("not a pem").is_err());
    }

    #[test]
    fn decode_base64_input_rejects_invalid_base64_and_non_utf8() {
        assert!(decode_base64_input("***", "public_key").is_err());
        let non_utf8 = super::STANDARD.encode([0xffu8, 0xfeu8]);
        let err = decode_base64_input(&non_utf8, "public_key").expect_err("non-utf8");
        assert!(err.to_string().contains("public_key"), "err: {err}");
        assert_eq!(decode_base64_input(&super::STANDARD.encode("pem"), "public_key").expect("utf8"), "pem");
    }

    #[test]
    fn jwk_to_pem_accepts_well_formed_rsa_components() {
        // Success path of `jwk_rsa_to_pem`: both components decode into big
        // numbers and the resulting key is rendered as a SubjectPublicKeyInfo PEM.
        let pem = jwk_to_pem(&rsa_jwk()).expect("valid RSA JWK must convert to PEM");
        assert!(pem.contains("BEGIN PUBLIC KEY"), "unexpected PEM: {pem}");
        assert_eq!(validate_and_derive_alg(&pem).expect("derived alg"), "RSA");
    }

    #[test]
    fn jwk_to_pem_rejects_empty_ec_coordinates() {
        // An empty coordinate decodes to an empty byte slice, which OpenSSL
        // refuses to turn into a big number — both coordinate branches must map
        // that to `InvalidParameter`.
        let x = b64(&[1u8; 32]);
        let empty_x = json!({"kty": "EC", "crv": "P-256", "x": "", "y": x});
        let err = jwk_to_pem(&empty_x).expect_err("empty x must be rejected");
        assert!(matches!(err, RbsError::InvalidParameter(_)), "err: {err}");

        let y = b64(&[1u8; 32]);
        let empty_y = json!({"kty": "EC", "crv": "P-256", "x": y, "y": ""});
        let err = jwk_to_pem(&empty_y).expect_err("empty y must be rejected");
        assert!(matches!(err, RbsError::InvalidParameter(_)), "err: {err}");
    }

    #[test]
    fn jwk_to_pem_rejects_ec_y_decoding_failure() {
        // `x` decodes fine but `y` does not: the `y`-specific error branch must
        // map to `InvalidParameter` instead of falling through to the OpenSSL
        // curve check.
        let (jwk, _) = ec_key_and_jwk("P-256", openssl::nid::Nid::X9_62_PRIME256V1);
        let mut bad_y = jwk;
        bad_y["y"] = json!("***");
        let err = jwk_to_pem(&bad_y).expect_err("invalid y encoding must be rejected");
        assert!(err.to_string().contains("JWK y decode failed"), "err: {err}");
    }

    #[test]
    fn validate_and_derive_alg_rejects_unsupported_key_types() {
        // Ed448/X25519/X448 parse as valid PEM public keys but are outside the
        // JWT algorithm set, so they must be rejected instead of being reported
        // as EC keys.
        let generators = [
            openssl::pkey::PKey::generate_ed448(),
            openssl::pkey::PKey::generate_x25519(),
            openssl::pkey::PKey::generate_x448(),
        ];
        for key in generators {
            let key = key.expect("generate non-JWT key");
            let pem = String::from_utf8(key.public_key_to_pem().expect("public pem")).expect("utf8 pem");
            let err = validate_and_derive_alg(&pem).expect_err("non-JWT key type must be rejected");
            assert!(err.to_string().contains("Unsupported key type"), "err: {err}");
        }
    }
}

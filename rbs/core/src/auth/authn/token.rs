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

//! AttestToken verification module.

use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{decode, DecodingKey, Validation};
use josekit::jwk::JwkSet;
use josekit::jws::alg::ecdsa::EcdsaJwsVerifier;
use josekit::jws::ES512;
use josekit::jwt::{self, JwtPayloadValidator};
use openssl::bn::BigNum;
use openssl::pkey::PKey;
use rbs_api_types::config::AttestTokenVerificationConfig;
use serde_json::Value;
use std::fs;

use crate::auth::authn::common::{
    create_decoding_key, decode_token_header, is_es512, map_josekit_error, map_jwt_error,
    to_jsonwebtoken_alg, validate_algorithm,
};
use crate::auth::authn::TokenVerifier;
use crate::auth::context::{AttestContext, TokenType};
use crate::auth::error::AuthError;

/// AttestToken verifier
pub struct AttestTokenVerifier {
    config: AttestTokenVerificationConfig,
    decoding_key: Option<DecodingKey>,
    es512_pem_verifier: Option<EcdsaJwsVerifier>,
    jwk_set: Option<JwkSet>,
}

impl std::fmt::Debug for AttestTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestTokenVerifier")
            .field("config", &self.config)
            .field("has_decoding_key", &self.decoding_key.is_some())
            .field("has_es512_verifier", &self.es512_pem_verifier.is_some())
            .field("has_jwk_set", &self.jwk_set.is_some())
            .finish()
    }
}

impl Clone for AttestTokenVerifier {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            decoding_key: self.decoding_key.clone(),
            es512_pem_verifier: self.es512_pem_verifier.clone(),
            jwk_set: self.jwk_set.clone(),
        }
    }
}

impl AttestTokenVerifier {
    /// Create a new AttestTokenVerifier from config
    pub fn new(config: AttestTokenVerificationConfig) -> Result<Self, AuthError> {
        if let Some(ref path) = config.public_key_path {
            log::info!("AttestTokenVerifier: loading public key from '{}'", path);
            let public_key_pem = fs::read(path).map_err(|e| {
                log::error!(
                    "AttestTokenVerifier: failed to read public key file '{}': {}",
                    path,
                    e
                );
                AuthError::TokenInvalid {
                    reason: format!(
                        "failed to read AttestToken public key file '{}': {}",
                        path, e
                    ),
                }
            })?;

            let (decoding_key, es512_verifier) = classify_pem_key(&public_key_pem)?;
            Ok(Self {
                config,
                decoding_key,
                es512_pem_verifier: es512_verifier,
                jwk_set: None,
            })
        } else if let Some(ref path) = config.jwks_file {
            log::info!("AttestTokenVerifier: loading JWKS from '{}'", path);
            let jwks_content = fs::read_to_string(path).map_err(|e| {
                log::error!(
                    "AttestTokenVerifier: failed to read JWKS file '{}': {}",
                    path,
                    e
                );
                AuthError::TokenInvalid {
                    reason: format!("failed to read JWKS file '{}': {}", path, e),
                }
            })?;
            let jwk_set = JwkSet::from_bytes(&jwks_content).map_err(|e| {
                log::error!("AttestTokenVerifier: failed to parse JWKS file: {}", e);
                AuthError::TokenInvalid {
                    reason: format!("failed to parse JWKS file: {}", e),
                }
            })?;
            Ok(Self {
                config,
                decoding_key: None,
                es512_pem_verifier: None,
                jwk_set: Some(jwk_set),
            })
        } else {
            log::error!("AttestTokenVerifier: no public_key_path or jwks_file configured");
            Err(AuthError::TokenInvalid {
                reason: "AttestToken verification requires either public_key_path or jwks_file to be configured".to_string(),
            })
        }
    }
}

#[async_trait]
impl TokenVerifier for AttestTokenVerifier {
    type Context = AttestContext;

    async fn verify(&self, token: &str) -> Result<AttestContext, AuthError> {
        let header = decode_token_header(token)?;
        validate_algorithm(&header.alg)?;

        log::debug!(
            "AttestToken verification: alg={}, kid={:?}",
            header.alg,
            header.kid
        );

        if is_es512(&header.alg) {
            return self.verify_es512(token, header.kid.as_deref()).await;
        }

        // --- Non-ES512 path (jsonwebtoken) ---

        let alg_str = header.alg.clone();
        let decoding_key = self.get_decoding_key(header.kid.as_deref(), &alg_str)?;

        let jwe_alg = to_jsonwebtoken_alg(&alg_str)?;

        let mut validation = Validation::new(jwe_alg);
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.set_issuer(&[&self.config.issuer]);
        if let Some(ref expected_aud) = self.config.audience {
            validation.set_audience(&[expected_aud]);
        }

        let token_data = decode::<Value>(token, &decoding_key, &validation).map_err(|e| {
            log::warn!("AttestToken verification failed: {}", e);
            map_jwt_error(&e, Some(&self.config.issuer))
        })?;

        Ok(AttestContext {
            claims: token_data.claims,
            token_type: TokenType::Attest,
        })
    }
}

impl AttestTokenVerifier {
    /// ES512 verification using josekit.
    async fn verify_es512(
        &self,
        token: &str,
        kid: Option<&str>,
    ) -> Result<AttestContext, AuthError> {
        let verifier: EcdsaJwsVerifier = if let Some(ref v) = self.es512_pem_verifier {
            v.clone()
        } else if let Some(ref jwk_set) = self.jwk_set {
            let jwk = if let Some(kid) = kid {
                let candidates = jwk_set.get(kid);
                candidates
                    .into_iter()
                    .find(|j| j.key_type() == "EC" && j.curve() == Some("P-521"))
                    .ok_or_else(|| AuthError::TokenInvalid {
                        reason: format!("ES512 key with kid '{}' not found in JWKS", kid),
                    })?
            } else {
                jwk_set
                    .keys()
                    .into_iter()
                    .find(|j| j.key_type() == "EC" && j.curve() == Some("P-521"))
                    .ok_or_else(|| AuthError::TokenInvalid {
                        reason: "no ES512 key in JWKS".to_string(),
                    })?
            };
            ES512.verifier_from_jwk(jwk).map_err(|e| {
                log::error!("AttestToken ES512: failed to create verifier from JWK: {}", e);
                AuthError::TokenInvalid {
                    reason: format!("failed to create ES512 verifier from JWK: {}", e),
                }
            })?
        } else {
            return Err(AuthError::TokenInvalid {
                reason: "no key configured for ES512 verification".to_string(),
            });
        };

        let (payload, _header) =
            jwt::decode_with_verifier(token, &verifier).map_err(|e| {
                log::warn!("AttestToken ES512 verification failed: {}", e);
                map_josekit_error(&e, Some(&self.config.issuer))
            })?;

        // Validate claims
        let mut validator = JwtPayloadValidator::new();
        validator.set_issuer(&self.config.issuer);
        if let Some(ref aud) = self.config.audience {
            validator.set_audience(aud);
        }

        // Ensure required claims exist
        if payload.claim("exp").is_none() {
            return Err(AuthError::TokenInvalid {
                reason: "missing exp claim".to_string(),
            });
        }
        if payload.claim("iss").is_none() {
            return Err(AuthError::TokenInvalid {
                reason: "missing iss claim".to_string(),
            });
        }

        validator.validate(&payload).map_err(|e| {
            log::warn!("AttestToken ES512 claim validation failed: {}", e);
            map_josekit_error(&e, Some(&self.config.issuer))
        })?;

        let claims: Value = {
            let map = payload.claims_set().clone();
            serde_json::to_value(map).map_err(|e| AuthError::TokenInvalid {
                reason: format!("failed to serialize claims: {}", e),
            })?
        };

        Ok(AttestContext {
            claims,
            token_type: TokenType::Attest,
        })
    }

    fn get_decoding_key(
        &self,
        kid: Option<&str>,
        alg: &str,
    ) -> Result<DecodingKey, AuthError> {
        // Direct PEM path
        if let Some(ref key) = self.decoding_key {
            return Ok(key.clone());
        }

        // JWKS path
        let jwk_set = self.jwk_set.as_ref().ok_or_else(|| AuthError::TokenInvalid {
            reason: "no JWKS loaded".to_string(),
        })?;

        let jwk = if let Some(kid) = kid {
            let candidates = jwk_set.get(kid);
            candidates
                .into_iter()
                .next()
                .ok_or_else(|| AuthError::TokenInvalid {
                    reason: format!("key with kid '{}' not found in JWKS", kid),
                })?
        } else {
            jwk_set.keys().into_iter().next().ok_or_else(|| {
                AuthError::TokenInvalid {
                    reason: "no keys in JWKS".to_string(),
                }
            })?
        };

        let pem = josekit_jwk_to_pem(jwk)?;
        create_decoding_key(alg, &pem)
    }
}

// ── Key classification & conversion ──

/// Classify a PEM public key and return the appropriate verifier(s).
fn classify_pem_key(
    pem: &[u8],
) -> Result<(Option<DecodingKey>, Option<EcdsaJwsVerifier>), AuthError> {
    let pkey = PKey::public_key_from_pem(pem).map_err(|e| AuthError::TokenInvalid {
        reason: format!("failed to parse PEM public key: {}", e),
    })?;

    match pkey.id() {
        openssl::pkey::Id::ED25519 => {
            let dk = DecodingKey::from_ed_pem(pem).map_err(|e| AuthError::TokenInvalid {
                reason: format!("failed to create EdDSA decoding key: {}", e),
            })?;
            Ok((Some(dk), None))
        }
        openssl::pkey::Id::EC => {
            let ec_key = pkey.ec_key().map_err(|_| AuthError::TokenInvalid {
                reason: "invalid EC key".to_string(),
            })?;
            let nid = ec_key
                .group()
                .curve_name()
                .unwrap_or(openssl::nid::Nid::from_raw(0));

            if nid == openssl::nid::Nid::SECP521R1 {
                let verifier = ES512.verifier_from_pem(pem).map_err(|e| {
                    AuthError::TokenInvalid {
                        reason: format!("failed to create ES512 verifier: {}", e),
                    }
                })?;
                Ok((None, Some(verifier)))
            } else if nid == openssl::nid::Nid::X9_62_PRIME256V1
                || nid == openssl::nid::Nid::SECP384R1
            {
                let dk =
                    DecodingKey::from_ec_pem(pem).map_err(|e| AuthError::TokenInvalid {
                        reason: format!("failed to create EC decoding key: {}", e),
                    })?;
                Ok((Some(dk), None))
            } else {
                Err(AuthError::TokenInvalid {
                    reason: "unsupported EC curve for AttestToken PEM".to_string(),
                })
            }
        }
        openssl::pkey::Id::RSA => {
            let dk =
                DecodingKey::from_rsa_pem(pem).map_err(|e| AuthError::TokenInvalid {
                    reason: format!("failed to create RSA decoding key: {}", e),
                })?;
            Ok((Some(dk), None))
        }
        _ => Err(AuthError::TokenInvalid {
            reason: "unsupported key type for AttestToken".to_string(),
        }),
    }
}

/// Convert a josekit JWK to PEM-encoded public key bytes.
fn josekit_jwk_to_pem(jwk: &josekit::jwk::Jwk) -> Result<Vec<u8>, AuthError> {
    match jwk.key_type() {
        "RSA" => josekit_jwk_rsa_to_pem(jwk),
        "EC" => josekit_jwk_ec_to_pem(jwk),
        "OKP" => josekit_jwk_okp_to_pem(jwk),
        _ => Err(AuthError::TokenInvalid {
            reason: format!(
                "unsupported JWK key type: {}. Only RSA, EC, and OKP are supported",
                jwk.key_type()
            ),
        }),
    }
}

fn josekit_jwk_rsa_to_pem(jwk: &josekit::jwk::Jwk) -> Result<Vec<u8>, AuthError> {
    let n = get_jwk_base64_param(jwk, "n")?;
    let e = get_jwk_base64_param(jwk, "e")?;

    let bn_n = BigNum::from_slice(&n).map_err(|e| AuthError::TokenInvalid {
        reason: format!("invalid RSA modulus: {}", e),
    })?;
    let bn_e = BigNum::from_slice(&e).map_err(|e| AuthError::TokenInvalid {
        reason: format!("invalid RSA exponent: {}", e),
    })?;

    let rsa = openssl::rsa::Rsa::from_public_components(bn_n, bn_e)
        .map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to create RSA key: {}", e),
        })?;
    let pem = rsa
        .public_key_to_pem()
        .map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to encode RSA key to PEM: {}", e),
        })?;
    Ok(pem)
}

fn josekit_jwk_ec_to_pem(jwk: &josekit::jwk::Jwk) -> Result<Vec<u8>, AuthError> {
    let crv = jwk.curve().ok_or_else(|| AuthError::TokenInvalid {
        reason: "missing crv in EC JWK".to_string(),
    })?;
    let curve_nid = match crv {
        "P-256" => openssl::nid::Nid::X9_62_PRIME256V1,
        "P-384" => openssl::nid::Nid::SECP384R1,
        _ => {
            return Err(AuthError::TokenInvalid {
                reason: format!("unsupported EC curve in JWKS: {}", crv),
            })
        }
    };

    let x = get_jwk_base64_param(jwk, "x")?;
    let y = get_jwk_base64_param(jwk, "y")?;

    let curve = openssl::ec::EcGroup::from_curve_name(curve_nid)
        .map_err(|e| AuthError::TokenInvalid {
            reason: format!("invalid EC curve: {}", e),
        })?;
    let bn_x = BigNum::from_slice(&x).map_err(|e| AuthError::TokenInvalid {
        reason: format!("invalid EC x coordinate: {}", e),
    })?;
    let bn_y = BigNum::from_slice(&y).map_err(|e| AuthError::TokenInvalid {
        reason: format!("invalid EC y coordinate: {}", e),
    })?;
    let ec_key =
        openssl::ec::EcKey::from_public_key_affine_coordinates(&curve, &bn_x, &bn_y)
            .map_err(|e| AuthError::TokenInvalid {
                reason: format!("invalid EC public key: {}", e),
            })?;
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key)
        .map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to create EC PKey: {}", e),
        })?;
    let pem = pkey
        .public_key_to_pem()
        .map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to encode EC key to PEM: {}", e),
        })?;
    Ok(pem)
}

fn josekit_jwk_okp_to_pem(jwk: &josekit::jwk::Jwk) -> Result<Vec<u8>, AuthError> {
    let crv = jwk.curve().ok_or_else(|| AuthError::TokenInvalid {
        reason: "missing crv in OKP JWK".to_string(),
    })?;
    if crv != "Ed25519" {
        return Err(AuthError::TokenInvalid {
            reason: format!("unsupported OKP curve: {}. Only Ed25519 is supported", crv),
        });
    }

    let x = get_jwk_base64_param(jwk, "x")?;
    Ok(format_ed25519_public_key(&x))
}

/// Extract and base64-decode a JWK parameter.
fn get_jwk_base64_param(jwk: &josekit::jwk::Jwk, name: &str) -> Result<Vec<u8>, AuthError> {
    let val = jwk.parameter(name).ok_or_else(|| AuthError::TokenInvalid {
        reason: format!("missing '{}' in JWK", name),
    })?;
    let s = val.as_str().ok_or_else(|| AuthError::TokenInvalid {
        reason: format!("'{}' must be a string in JWK", name),
    })?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to decode '{}': {}", name, e),
        })
}

/// Build Ed25519 public key in DER/PEM format.
fn format_ed25519_public_key(x_bytes: &[u8]) -> Vec<u8> {
    let alg_id = vec![
        0x30, 0x05, // SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID for Ed25519: 1.3.101.112
    ];
    let mut bit_string = vec![0x03, 0x21, 0x00]; // BIT STRING, 33 bytes, 0 unused bits
    bit_string.extend_from_slice(x_bytes);

    let seq_len = alg_id.len() + bit_string.len();
    let mut der = vec![0x30];
    der.extend_from_slice(&encode_der_length(seq_len));
    der.extend_from_slice(&alg_id);
    der.extend_from_slice(&bit_string);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        b64
    );
    pem.into_bytes()
}

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
    use std::io::Write;
    use std::sync::Once;

    static INIT: Once = Once::new();
    static mut TEST_KEY_PATH: Option<String> = None;
    static mut TEST_ED25519_KEY_PATH: Option<String> = None;

    /// Generate a fresh RSA public key PEM for each test session.
    fn generate_test_rsa_public_key_pem() -> String {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        String::from_utf8(pkey.public_key_to_pem().unwrap()).unwrap()
    }

    const MALFORMED_TOKEN: &str = "not.a.valid.token";

    fn setup_test_keys() -> (String, String) {
        INIT.call_once(|| {
            let pem = generate_test_rsa_public_key_pem();
            let temp_dir = std::env::temp_dir();

            // RSA key
            let rsa_key_path = temp_dir.join("rbs_test_attest_rsa_pubkey.pem");
            let mut file =
                std::fs::File::create(&rsa_key_path).expect("Failed to create temp RSA key file");
            file.write_all(pem.as_bytes())
                .expect("Failed to write RSA key");
            unsafe {
                TEST_KEY_PATH = Some(rsa_key_path.to_string_lossy().to_string());
            }

            // Ed25519 key — generated fresh
            let ed_key_path = temp_dir.join("rbs_test_attest_ed_pubkey.pem");
            let ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
            let ed_pem = ed_key.public_key_to_pem().unwrap();
            let mut file2 =
                std::fs::File::create(&ed_key_path).expect("Failed to create temp Ed key file");
            file2
                .write_all(&ed_pem)
                .expect("Failed to write Ed key");
            unsafe {
                TEST_ED25519_KEY_PATH = Some(ed_key_path.to_string_lossy().to_string());
            }
        });
        unsafe {
            (
                TEST_KEY_PATH.clone().unwrap(),
                TEST_ED25519_KEY_PATH.clone().unwrap(),
            )
        }
    }

    fn create_verifier() -> AttestTokenVerifier {
        let (rsa_key_path, _) = setup_test_keys();
        let config = AttestTokenVerificationConfig {
            public_key_path: Some(rsa_key_path),
            jwks_file: None,
            issuer: "Global Trust Authority".to_string(),
            audience: Some("rbs".to_string()),
        };
        AttestTokenVerifier::new(config).expect("failed to create verifier")
    }

    #[tokio::test]
    async fn test_attest_token_malformed_format() {
        let verifier = create_verifier();
        let result = verifier.verify(MALFORMED_TOKEN).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_attest_token_missing_config() {
        let config = AttestTokenVerificationConfig {
            public_key_path: None,
            jwks_file: None,
            issuer: "test".to_string(),
            audience: None,
        };
        let result = AttestTokenVerifier::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_classify_pem_key_rsa() {
        let pem = generate_test_rsa_public_key_pem();
        let (dk, es512) = classify_pem_key(pem.as_bytes()).unwrap();
        assert!(dk.is_some());
        assert!(es512.is_none());
    }

    #[test]
    fn test_classify_pem_key_ed25519() {
        let ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
        let ed_pem = ed_key.public_key_to_pem().unwrap();
        let (dk, es512) = classify_pem_key(&ed_pem).unwrap();
        assert!(dk.is_some());
        assert!(es512.is_none());
    }

    #[test]
    fn test_classify_pem_key_ec_p256() {
        let ec_group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
        let pem = pkey.public_key_to_pem().unwrap();
        let (dk, es512) = classify_pem_key(&pem).unwrap();
        assert!(dk.is_some());
        assert!(es512.is_none());
    }

    #[test]
    fn test_classify_pem_key_ec_p521() {
        let ec_group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP521R1).unwrap();
        let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
        let pem = pkey.public_key_to_pem().unwrap();
        let (dk, es512) = classify_pem_key(&pem).unwrap();
        assert!(dk.is_none());
        assert!(es512.is_some());
    }

    #[test]
    fn test_classify_pem_key_ec_p384() {
        let ec_group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
        let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
        let pem = pkey.public_key_to_pem().unwrap();
        let (dk, es512) = classify_pem_key(&pem).unwrap();
        assert!(dk.is_some());
        assert!(es512.is_none());
    }

    #[test]
    fn test_classify_pem_key_invalid_pem() {
        let result = classify_pem_key(b"not a valid PEM");
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_der_length_short() {
        assert_eq!(encode_der_length(5), vec![5]);
        assert_eq!(encode_der_length(0), vec![0]);
        assert_eq!(encode_der_length(127), vec![127]);
    }

    #[test]
    fn test_encode_der_length_long() {
        let result = encode_der_length(128);
        assert_eq!(result[0], 0x81);
        assert_eq!(result[1], 128);
        let result = encode_der_length(256);
        assert_eq!(result[0], 0x82);
        assert_eq!(result[1], 1);
        assert_eq!(result[2], 0);
    }

    #[test]
    fn test_format_ed25519_public_key_produces_valid_pem() {
        let ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
        let raw_bytes = ed_key.raw_public_key().unwrap();
        let pem_bytes = format_ed25519_public_key(&raw_bytes);
        let pem_str = String::from_utf8(pem_bytes.clone()).unwrap();
        assert!(pem_str.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem_str.ends_with("-----END PUBLIC KEY-----\n"));
        // Verify the PEM can be parsed by openssl
        let parsed = openssl::pkey::PKey::public_key_from_pem(&pem_bytes).unwrap();
        assert_eq!(parsed.id(), openssl::pkey::Id::ED25519);
    }

    #[test]
    fn test_get_jwk_base64_param_missing() {
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(serde_json::to_vec(&serde_json::json!({"kty": "RSA"})).unwrap()).unwrap();
        let result = get_jwk_base64_param(&jwk, "n");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_jwk_base64_param_valid() {
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"hello");
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(serde_json::to_vec(&serde_json::json!({"kty": "RSA", "n": n})).unwrap()).unwrap();
        let result = get_jwk_base64_param(&jwk, "n").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_get_jwk_base64_param_invalid_base64() {
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(serde_json::to_vec(&serde_json::json!({"kty": "RSA", "n": "!!!invalid"})).unwrap()).unwrap();
        let result = get_jwk_base64_param(&jwk, "n");
        assert!(result.is_err());
    }

    #[test]
    fn test_josekit_jwk_rsa_to_pem_valid() {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let n = rsa.n().to_vec();
        let e = rsa.e().to_vec();
        let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&n);
        let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e);
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(&serde_json::json!({"kty": "RSA", "n": n_b64, "e": e_b64})).unwrap()
        ).unwrap();
        let result = josekit_jwk_rsa_to_pem(&jwk).unwrap();
        let parsed = openssl::pkey::PKey::public_key_from_pem(&result).unwrap();
        assert_eq!(parsed.id(), openssl::pkey::Id::RSA);
    }

    #[test]
    fn test_josekit_jwk_ec_to_pem_p256() {
        let ec_group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let mut x = openssl::bn::BigNum::new().unwrap();
        let mut y = openssl::bn::BigNum::new().unwrap();
        ec_key.public_key().affine_coordinates(&ec_group, &mut x, &mut y, &mut ctx).unwrap();
        let x_bytes = x.to_vec();
        let y_bytes = y.to_vec();
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x_bytes);
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&y_bytes);
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(&serde_json::json!({"kty": "EC", "crv": "P-256", "x": x_b64, "y": y_b64})).unwrap()
        ).unwrap();
        let result = josekit_jwk_ec_to_pem(&jwk).unwrap();
        let parsed = openssl::pkey::PKey::public_key_from_pem(&result).unwrap();
        assert_eq!(parsed.id(), openssl::pkey::Id::EC);
    }

    #[test]
    fn test_josekit_jwk_ec_to_pem_p384() {
        let ec_group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
        let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let mut x = openssl::bn::BigNum::new().unwrap();
        let mut y = openssl::bn::BigNum::new().unwrap();
        ec_key.public_key().affine_coordinates(&ec_group, &mut x, &mut y, &mut ctx).unwrap();
        let x_bytes = x.to_vec();
        let y_bytes = y.to_vec();
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x_bytes);
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&y_bytes);
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(&serde_json::json!({"kty": "EC", "crv": "P-384", "x": x_b64, "y": y_b64})).unwrap()
        ).unwrap();
        let result = josekit_jwk_ec_to_pem(&jwk).unwrap();
        let parsed = openssl::pkey::PKey::public_key_from_pem(&result).unwrap();
        assert_eq!(parsed.id(), openssl::pkey::Id::EC);
    }

    #[test]
    fn test_josekit_jwk_ec_to_pem_unsupported_curve() {
        // Use valid base64 values for x and y, but with unsupported curve "P-521"
        // (P-521 goes through ES512 path, not EC-to-PEM conversion)
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"x-coordinate");
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"y-coordinate");
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(&serde_json::json!({"kty": "EC", "crv": "secp256k1", "x": x_b64, "y": y_b64})).unwrap()
        ).unwrap();
        let result = josekit_jwk_ec_to_pem(&jwk);
        assert!(result.is_err());
    }

    #[test]
    fn test_josekit_jwk_ec_to_pem_missing_crv() {
        // JWK without crv — josekit may still parse it if kty=EC but crv defaults to something
        // Let's test with a valid EC JWK but explicitly check for crv handling
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"x-coordinate");
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"y-coordinate");
        // A JWK without crv can still be parsed by josekit but will fail in ec_to_pem
        let jwk = josekit::jwk::Jwk::new("EC");
        let result = josekit_jwk_ec_to_pem(&jwk);
        assert!(result.is_err());
    }

    #[test]
    fn test_josekit_jwk_okp_to_pem_ed25519() {
        let ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
        let x_bytes = ed_key.raw_public_key().unwrap();
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x_bytes);
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(&serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": x_b64})).unwrap()
        ).unwrap();
        let result = josekit_jwk_okp_to_pem(&jwk).unwrap();
        let parsed = openssl::pkey::PKey::public_key_from_pem(&result).unwrap();
        assert_eq!(parsed.id(), openssl::pkey::Id::ED25519);
    }

    #[test]
    fn test_josekit_jwk_okp_to_pem_unsupported_curve() {
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(&serde_json::json!({"kty": "OKP", "crv": "Ed448", "x": "abc"})).unwrap()
        ).unwrap();
        let result = josekit_jwk_okp_to_pem(&jwk);
        assert!(result.is_err());
    }

    #[test]
    fn test_josekit_jwk_to_pem_unsupported_type() {
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(&serde_json::json!({"kty": "oct", "k": "abc"})).unwrap()
        ).unwrap();
        let result = josekit_jwk_to_pem(&jwk);
        assert!(result.is_err());
    }
}

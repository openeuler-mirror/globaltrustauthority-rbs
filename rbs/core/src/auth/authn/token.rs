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
    create_decoding_key, decode_token_header, is_es512, is_sm2, map_josekit_error, map_jwt_error,
    to_jsonwebtoken_alg, validate_algorithm, validate_jwt_claims, validate_josekit_exp, validate_josekit_audience, validate_rsa_key_size,
};
use crate::auth::authn::sm2;
use crate::auth::authn::TokenVerifier;
use crate::auth::context::{AttestContext, TokenType};
use crate::auth::error::AuthError;

/// AttestToken verifier
pub struct AttestTokenVerifier {
    config: AttestTokenVerificationConfig,
    decoding_key: Option<DecodingKey>,
    es512_pem_verifier: Option<EcdsaJwsVerifier>,
    /// SM2 public key PEM (SM2+SM3 verification path via OpenSSL).
    sm2_pem: Option<Vec<u8>>,
    jwk_set: Option<JwkSet>,
}

impl std::fmt::Debug for AttestTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestTokenVerifier")
            .field("config", &self.config)
            .field("has_decoding_key", &self.decoding_key.is_some())
            .field("has_es512_verifier", &self.es512_pem_verifier.is_some())
            .field("has_sm2_key", &self.sm2_pem.is_some())
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
            sm2_pem: self.sm2_pem.clone(),
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

            let (decoding_key, es512_verifier, sm2_pem) = classify_pem_key(&public_key_pem)?;
            Ok(Self {
                config,
                decoding_key,
                es512_pem_verifier: es512_verifier,
                sm2_pem,
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
                sm2_pem: None,
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

        if is_sm2(&header.alg) {
            return self.verify_sm2(token, header.kid.as_deref()).await;
        }

        if is_es512(&header.alg) {
            return self.verify_es512(token, header.kid.as_deref()).await;
        }

        // --- Non-ES512 path (jsonwebtoken) ---

        let alg_str = header.alg.clone();
        let decoding_key = self.get_decoding_key(header.kid.as_deref(), &alg_str)?;

        let jws_alg = to_jsonwebtoken_alg(&alg_str)?;

        let mut validation = Validation::new(jws_alg);
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.set_issuer(&[&self.config.issuer]);
        if let Some(ref expected_aud) = self.config.audience {
            validation.set_audience(&[expected_aud]);
            validation.required_spec_claims.insert("aud".to_string());
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

        // Validate exp explicitly (see `validate_josekit_exp`) so an expired token
        // returns TokenExpired and a missing exp is rejected outright — identical
        // to the Bearer ES512 path; then the remaining claims (iss, aud, nbf)
        // with the same pinned clock read.
        let now = validate_josekit_exp("AttestToken", &payload)?;
        validate_josekit_audience(&payload, self.config.audience.as_deref())?;

        let mut validator = JwtPayloadValidator::new();
        validator.set_base_time(now);
        validator.set_issuer(&self.config.issuer);
        if let Some(ref aud) = self.config.audience {
            validator.set_audience(aud);
        }

        // Ensure required claims exist (exp is already handled above)
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

    /// SM2 verification using OpenSSL (SM2 ECDSA over the SM3 digest).
    ///
    /// Neither `jsonwebtoken` nor `josekit` supports SM2, so this path verifies
    /// the compact JWS signature directly with the vendored OpenSSL backend and
    /// parses claims manually (mirroring `verify_es512`'s structure and
    /// user-enumeration-safe error collapsing).
    async fn verify_sm2(
        &self,
        token: &str,
        kid: Option<&str>,
    ) -> Result<AttestContext, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::TokenInvalid { reason: "invalid token".to_string() });
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| {
                log::warn!("AttestToken SM2 signature decode failed: {}", e);
                AuthError::TokenInvalid { reason: "invalid token".to_string() }
            })?;

        let pem = self.get_sm2_pem(kid)?;
        let pkey = PKey::public_key_from_pem(&pem).map_err(|e| {
            log::warn!("AttestToken SM2 public key parse failed: {}", e);
            AuthError::TokenInvalid { reason: "invalid token".to_string() }
        })?;
        // SM2+SM3 verification with the standard (GM/T 0009) user ID pinned;
        // see `authn::sm2` for why the plain Verifier path is not usable.
        let valid = sm2::verify(&pkey, signing_input.as_bytes(), &signature).map_err(|e| {
            log::warn!("AttestToken SM2 verify failed: {}", e);
            AuthError::TokenInvalid { reason: "invalid token".to_string() }
        })?;
        if !valid {
            log::warn!("AttestToken SM2 signature verification failed");
            return Err(AuthError::TokenInvalid { reason: "invalid token".to_string() });
        }

        // Signature trusted — parse and validate claims manually.
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| AuthError::TokenInvalid { reason: "invalid token".to_string() })?;
        let claims: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|_| AuthError::TokenInvalid { reason: "invalid token".to_string() })?;

        validate_jwt_claims(&claims, &self.config.issuer, self.config.audience.as_deref())?;

        Ok(AttestContext {
            claims,
            token_type: TokenType::Attest,
        })
    }

    /// Resolve the SM2 public key PEM: either the PEM loaded at construction
    /// (`sm2_pem`) or an SM2-curve EC JWK looked up in the JWKS by `kid`.
    fn get_sm2_pem(&self, kid: Option<&str>) -> Result<Vec<u8>, AuthError> {
        if let Some(ref pem) = self.sm2_pem {
            return Ok(pem.clone());
        }

        let jwk_set = self.jwk_set.as_ref().ok_or_else(|| AuthError::TokenInvalid {
            reason: "no key configured for SM2 verification".to_string(),
        })?;

        let candidates = if let Some(kid) = kid {
            jwk_set.get(kid)
        } else {
            jwk_set.keys()
        };
        let jwk = candidates
            .into_iter()
            .find(|j| j.key_type() == "EC" && j.curve() == Some("sm2p256v1"))
            .ok_or_else(|| AuthError::TokenInvalid {
                reason: "no SM2 key found in JWKS".to_string(),
            })?;

        josekit_jwk_to_pem(&jwk)
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
///
/// The third tuple element holds the raw SM2 public key PEM (for the OpenSSL
/// SM2+SM3 path); it is `Some` only for SM2 keys, which neither `jsonwebtoken`
/// (`DecodingKey`) nor `josekit` (`EcdsaJwsVerifier`) can represent.
fn classify_pem_key(
    pem: &[u8],
) -> Result<(Option<DecodingKey>, Option<EcdsaJwsVerifier>, Option<Vec<u8>>), AuthError> {
    let pkey = PKey::public_key_from_pem(pem).map_err(|e| AuthError::TokenInvalid {
        reason: format!("failed to parse PEM public key: {}", e),
    })?;

    validate_rsa_key_size(&pkey)?;
    match pkey.id() {
        openssl::pkey::Id::SM2 => Ok((None, None, Some(pem.to_vec()))),
        openssl::pkey::Id::ED25519 => {
            let dk = DecodingKey::from_ed_pem(pem).map_err(|e| AuthError::TokenInvalid {
                reason: format!("failed to create EdDSA decoding key: {}", e),
            })?;
            Ok((Some(dk), None, None))
        }
        openssl::pkey::Id::EC => {
            let ec_key = pkey.ec_key().map_err(|_| AuthError::TokenInvalid {
                reason: "invalid EC key".to_string(),
            })?;
            let nid = ec_key
                .group()
                .curve_name()
                .unwrap_or(openssl::nid::Nid::from_raw(0));

            if nid == openssl::nid::Nid::SM2 {
                // SM2-curve EC key: OpenSSL may report Id::EC rather than Id::SM2
                // depending on how the key was constructed. Route to the SM2 path.
                return Ok((None, None, Some(pem.to_vec())));
            }

            if nid == openssl::nid::Nid::SECP521R1 {
                let verifier = ES512.verifier_from_pem(pem).map_err(|e| {
                    AuthError::TokenInvalid {
                        reason: format!("failed to create ES512 verifier: {}", e),
                    }
                })?;
                Ok((None, Some(verifier), None))
            } else if nid == openssl::nid::Nid::X9_62_PRIME256V1
                || nid == openssl::nid::Nid::SECP384R1
            {
                let dk =
                    DecodingKey::from_ec_pem(pem).map_err(|e| AuthError::TokenInvalid {
                        reason: format!("failed to create EC decoding key: {}", e),
                    })?;
                Ok((Some(dk), None, None))
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
            Ok((Some(dk), None, None))
        }
        openssl::pkey::Id::RSA_PSS => {
            let rsa = pkey.rsa().map_err(|e| AuthError::TokenInvalid {
                reason: format!("failed to extract RSA-PSS public key: {}", e),
            })?;
            Ok((
                Some(DecodingKey::from_rsa_raw_components(
                    rsa.n().to_vec().as_slice(),
                    rsa.e().to_vec().as_slice(),
                )),
                None,
                None,
            ))
        }
        _ => {
            // OpenSSL 3.x may report an SM2 public key's id as -1 (unknown) after
            // round-tripping through a SubjectPublicKeyInfo PEM, so the EC arm above
            // is bypassed. Detect SM2 via the EC-specific PEM parser, which preserves
            // the curve NID, and route to the OpenSSL SM2+SM3 path.
            if let Ok(ec_key) = openssl::ec::EcKey::public_key_from_pem(pem) {
                if ec_key.group().curve_name() == Some(openssl::nid::Nid::SM2) {
                    return Ok((None, None, Some(pem.to_vec())));
                }
            }
            Err(AuthError::TokenInvalid {
                reason: "unsupported key type for AttestToken".to_string(),
            })
        }
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
        "sm2p256v1" => openssl::nid::Nid::SM2,
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
    use josekit::jwk::KeyPair;
    use josekit::jws::{JwsHeader, PS256};
    use josekit::jwt::JwtPayload;
    use std::io::Write;
    use std::sync::OnceLock;

    static TEST_KEY_PATH: OnceLock<String> = OnceLock::new();
    static TEST_ED25519_KEY_PATH: OnceLock<String> = OnceLock::new();

    /// Generate a fresh RSA public key PEM for each test session.
    fn generate_test_rsa_public_key_pem() -> String {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        String::from_utf8(pkey.public_key_to_pem().unwrap()).unwrap()
    }

    const MALFORMED_TOKEN: &str = "not.a.valid.token";

    fn setup_test_keys() -> (String, String) {
        let temp_dir = std::env::temp_dir();

        let rsa_key_path = TEST_KEY_PATH.get_or_init(|| {
            let pem = generate_test_rsa_public_key_pem();

            // RSA key
            let rsa_key_path = temp_dir.join("rbs_test_attest_rsa_pubkey.pem");
            let mut file =
                std::fs::File::create(&rsa_key_path).expect("Failed to create temp RSA key file");
            file.write_all(pem.as_bytes())
                .expect("Failed to write RSA key");
            rsa_key_path.to_string_lossy().to_string()
        }).clone();

        let ed_key_path = TEST_ED25519_KEY_PATH.get_or_init(|| {
            // Ed25519 key — generated fresh
            let ed_key_path = temp_dir.join("rbs_test_attest_ed_pubkey.pem");
            let ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
            let ed_pem = ed_key.public_key_to_pem().unwrap();
            let mut file2 =
                std::fs::File::create(&ed_key_path).expect("Failed to create temp Ed key file");
            file2
                .write_all(&ed_pem)
                .expect("Failed to write Ed key");
            ed_key_path.to_string_lossy().to_string()
        }).clone();

        (rsa_key_path, ed_key_path)
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

    // ── Helpers for JWKS / ES512 / error-path tests ──

    /// Current UNIX time in seconds, used for `exp` claims.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the UNIX epoch")
            .as_secs()
    }

    /// Write `contents` to a uniquely named file in the system temp directory.
    /// The file is removed when the returned handle is dropped.
    fn write_temp_file(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        file.write_all(contents).expect("write temp file");
        file.flush().expect("flush temp file");
        file
    }

    /// Serialize public JWKs into a `{"keys":[...]}` JWKS document.
    fn jwks_document(keys: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "keys": keys })).expect("serialize JWKS")
    }

    /// AttestToken verifier backed by a JWKS file holding `keys`.
    fn jwks_verifier(keys: Vec<serde_json::Value>, audience: Option<&str>) -> AttestTokenVerifier {
        let file = write_temp_file(&jwks_document(keys));
        let config = AttestTokenVerificationConfig {
            public_key_path: None,
            jwks_file: Some(file.path().to_string_lossy().to_string()),
            issuer: "Global Trust Authority".to_string(),
            audience: audience.map(str::to_string),
        };
        AttestTokenVerifier::new(config).expect("create JWKS verifier")
    }

    /// AttestToken verifier backed by a PEM public key file.
    fn pem_verifier(pem: &[u8], audience: Option<&str>) -> AttestTokenVerifier {
        let file = write_temp_file(pem);
        let config = AttestTokenVerificationConfig {
            public_key_path: Some(file.path().to_string_lossy().to_string()),
            jwks_file: None,
            issuer: "Global Trust Authority".to_string(),
            audience: audience.map(str::to_string),
        };
        AttestTokenVerifier::new(config).expect("create PEM verifier")
    }

    /// Claims accepted by every AttestToken verification path.
    fn attest_claims(expires_in: u64) -> serde_json::Value {
        serde_json::json!({
            "iss": "Global Trust Authority",
            "sub": "attest-sub",
            "aud": "rbs",
            "exp": now_secs() + expires_in,
        })
    }

    /// Fresh P-521 key pair for the ES512 (josekit) paths.
    fn generate_p521_key_pair() -> Box<dyn KeyPair> {
        Box::new(
            josekit::jws::ES512
                .generate_key_pair()
                .expect("generate P-521 key pair"),
        )
    }

    /// RSA key pair for the jsonwebtoken RSA-PSS paths: PKCS#1 private key PEM
    /// plus the matching public JWK (`kty` RSA with `n`/`e`).
    fn generate_rsa_key_pair() -> (Vec<u8>, serde_json::Value) {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("generate RSA key");
        let private_pem = rsa.private_key_to_pem().expect("RSA private key PEM");
        let modulus = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
        let exponent = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
        (
            private_pem,
            serde_json::json!({ "kty": "RSA", "n": modulus, "e": exponent }),
        )
    }

    /// Sign an ES512 JWT with a P-521 private key PEM, setting `kid` when given.
    fn sign_es512_jwt(priv_pem: &[u8], claims: serde_json::Value, kid: Option<&str>) -> String {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm("ES512");
        if let Some(kid) = kid {
            header.set_key_id(kid);
        }
        let map = claims
            .as_object()
            .cloned()
            .expect("claims must be a JSON object");
        let payload = JwtPayload::from_map(map).expect("create JWT payload");
        let signer = josekit::jws::ES512
            .signer_from_pem(priv_pem)
            .expect("create ES512 signer");
        jwt::encode_with_signer(&payload, &header, &signer).expect("sign ES512 JWT")
    }

    /// Sign a PS256 JWT with an RSA private key PEM (jsonwebtoken header, so
    /// `kid` is carried in the protected header for JWKS lookups).
    fn sign_ps256_jwt(priv_pem: &[u8], claims: serde_json::Value, kid: Option<&str>) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
        header.kid = kid.map(str::to_string);
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(priv_pem).expect("RSA encoding key");
        jsonwebtoken::encode(&header, &claims, &key).expect("sign PS256 JWT")
    }

    /// Compact JWS with an SM2 header and a caller-supplied signature segment,
    /// used to exercise the signature-decoding failure branches.
    fn sm2_jws_with_signature(claims: serde_json::Value, signature_segment: &str) -> String {
        let header = serde_json::json!({ "alg": "SM2", "typ": "JWT" });
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).expect("encode SM2 header"));
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).expect("encode claims"));
        format!("{}.{}.{}", header_b64, payload_b64, signature_segment)
    }

    /// SM2 public JWK (crv "sm2p256v1") plus the matching private key PEM.
    fn sm2_jwk_with_private_pem(kid: Option<&str>) -> (serde_json::Value, String) {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SM2).expect("SM2 group");
        let ec_key = openssl::ec::EcKey::generate(&group).expect("generate SM2 EC key");
        let mut ctx = openssl::bn::BigNumContext::new().expect("big number context");
        let mut x = openssl::bn::BigNum::new().expect("big number x");
        let mut y = openssl::bn::BigNum::new().expect("big number y");
        ec_key
            .public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
            .expect("SM2 affine coordinates");
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).expect("SM2 PKey");
        let priv_pem =
            String::from_utf8(pkey.private_key_to_pem_pkcs8().expect("SM2 private key PEM"))
                .expect("SM2 private key PEM is UTF-8");
        let mut jwk = serde_json::json!({
            "kty": "EC",
            "crv": "sm2p256v1",
            "use": "sig",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x.to_vec()),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y.to_vec()),
        });
        if let Some(kid) = kid {
            jwk["kid"] = serde_json::Value::String(kid.to_string());
        }
        (jwk, priv_pem)
    }

    /// Build a compact SM2 JWS, placing `kid` in the header when given.
    fn sign_sm2_jws(priv_pem: &str, kid: Option<&str>, claims: serde_json::Value) -> String {
        let pkey =
            openssl::pkey::PKey::private_key_from_pem(priv_pem.as_bytes()).expect("load SM2 key");
        let mut header = serde_json::json!({ "alg": "SM2", "typ": "JWT" });
        if let Some(kid) = kid {
            header["kid"] = serde_json::Value::String(kid.to_string());
        }
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).expect("encode SM2 header"));
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).expect("encode claims"));
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature = sm2::sign(&pkey, signing_input.as_bytes()).expect("sign SM2 JWS");
        format!(
            "{}.{}",
            signing_input,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
        )
    }

    #[tokio::test]
    async fn test_attest_token_malformed_format() {
        let verifier = create_verifier();
        let result = verifier.verify(MALFORMED_TOKEN).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_rsa_pss_attest_token_signed_by_josekit() {
        let key_pair = PS256.generate_key_pair(2048).expect("generate RSA-PSS key pair");
        let mut public_key_file = tempfile::NamedTempFile::new().expect("create public key file");
        public_key_file
            .write_all(&key_pair.to_pem_public_key())
            .expect("write RSA-PSS public key");

        let config = AttestTokenVerificationConfig {
            public_key_path: Some(public_key_file.path().to_string_lossy().to_string()),
            jwks_file: None,
            issuer: "Global Trust Authority".to_string(),
            audience: Some("rbs".to_string()),
        };
        let verifier = AttestTokenVerifier::new(config).expect("create RSA-PSS verifier");

        let mut payload = JwtPayload::new();
        payload.set_issuer("Global Trust Authority");
        payload.set_audience(vec!["rbs"]);
        payload.set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(3600)));

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm("PS256");
        let signer = PS256
            .signer_from_pem(key_pair.to_pem_private_key())
            .expect("create RSA-PSS signer");
        let token = jwt::encode_with_signer(&payload, &header, &signer).expect("sign RSA-PSS JWT");

        verifier.verify(&token).await.expect("RBS should verify a josekit RSA-PSS AttestToken");
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
        let (dk, es512, _sm2) = classify_pem_key(pem.as_bytes()).unwrap();
        assert!(dk.is_some());
        assert!(es512.is_none());
    }

    #[test]
    fn test_classify_pem_key_ed25519() {
        let ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
        let ed_pem = ed_key.public_key_to_pem().unwrap();
        let (dk, es512, _sm2) = classify_pem_key(&ed_pem).unwrap();
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
        let (dk, es512, _sm2) = classify_pem_key(&pem).unwrap();
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
        let (dk, es512, _sm2) = classify_pem_key(&pem).unwrap();
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
        let (dk, es512, _sm2) = classify_pem_key(&pem).unwrap();
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

    // ── SM2 tests ──

    /// Generate an SM2 key pair (EC key on the SM2 curve wrapped in PKey).
    fn generate_test_sm2_key_pair() -> (String, String) {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SM2).expect("SM2 group");
        let ec = openssl::ec::EcKey::generate(&group).expect("generate SM2 EC key");
        let pkey = openssl::pkey::PKey::from_ec_key(ec).expect("PKey from SM2 EC key");
        let pub_pem = String::from_utf8(pkey.public_key_to_pem().expect("pub pem")).unwrap();
        let priv_pem =
            String::from_utf8(pkey.private_key_to_pem_pkcs8().expect("priv pem")).unwrap();
        (pub_pem, priv_pem)
    }

    /// Build an SM2-signed compact JWS (alg "SM2") for AttestToken tests.
    fn sign_sm2_attest_token(priv_pem: &str, iss: &str, aud: Option<&str>, exp: u64) -> String {
        sign_sm2_attest_token_with_id(priv_pem, iss, aud, exp, sm2::SM2_USER_ID)
    }

    /// Like [`sign_sm2_attest_token`] but with an explicit SM2 user ID, used
    /// to prove that non-standard IDs are rejected.
    fn sign_sm2_attest_token_with_id(
        priv_pem: &str,
        iss: &str,
        aud: Option<&str>,
        exp: u64,
        user_id: &[u8],
    ) -> String {
        let pkey = openssl::pkey::PKey::private_key_from_pem(priv_pem.as_bytes())
            .expect("load SM2 priv key");
        let header = serde_json::json!({ "alg": "SM2", "typ": "JWT" });
        let mut payload = serde_json::json!({ "iss": iss, "sub": "attest-sub", "exp": exp });
        if let Some(aud) = aud {
            payload["aud"] = serde_json::Value::String(aud.to_string());
        }
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = sm2::sign_with_id(&pkey, signing_input.as_bytes(), user_id).expect("SM2 sign");
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig);
        format!("{}.{}", signing_input, sig_b64)
    }

    fn sm2_attest_verifier(pub_key_path: String) -> AttestTokenVerifier {
        let config = AttestTokenVerificationConfig {
            public_key_path: Some(pub_key_path),
            jwks_file: None,
            issuer: "Global Trust Authority".to_string(),
            audience: Some("rbs".to_string()),
        };
        AttestTokenVerifier::new(config).expect("verifier")
    }

    #[test]
    fn test_classify_pem_key_sm2() {
        let (pub_pem, _) = generate_test_sm2_key_pair();
        let (dk, es512, sm2) = classify_pem_key(pub_pem.as_bytes()).unwrap();
        assert!(dk.is_none(), "SM2 must not produce a DecodingKey");
        assert!(es512.is_none(), "SM2 must not produce an ES512 verifier");
        assert!(sm2.is_some(), "SM2 must produce a raw PEM");
    }

    #[tokio::test]
    async fn test_sm2_attest_token_round_trip() {
        let (pub_pem, priv_pem) = generate_test_sm2_key_pair();
        let path = std::env::temp_dir().join("rbs_test_attest_sm2_rt.pem");
        std::fs::write(&path, &pub_pem).expect("write pub");
        let verifier = sm2_attest_verifier(path.to_string_lossy().to_string());

        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600) as u64;
        let token =
            sign_sm2_attest_token(&priv_pem, "Global Trust Authority", Some("rbs"), exp);

        let result = verifier.verify(&token).await;
        assert!(result.is_ok(), "valid SM2 AttestToken should verify: {:?}", result.err());
        assert_eq!(result.unwrap().token_type, TokenType::Attest);
    }

    /// An expired SM2 AttestToken returns TokenExpired.
    #[tokio::test]
    async fn test_sm2_attest_token_expired() {
        let (pub_pem, priv_pem) = generate_test_sm2_key_pair();
        let path = std::env::temp_dir().join("rbs_test_attest_sm2_exp.pem");
        std::fs::write(&path, &pub_pem).expect("write pub");
        let verifier = sm2_attest_verifier(path.to_string_lossy().to_string());

        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600) as u64;
        let token =
            sign_sm2_attest_token(&priv_pem, "Global Trust Authority", Some("rbs"), exp);

        let result = verifier.verify(&token).await;
        assert!(result.is_err(), "expired SM2 AttestToken must be rejected");
        match result.unwrap_err() {
            AuthError::TokenExpired => {}
            other => panic!("expected TokenExpired, got: {:?}", other),
        }
    }

    /// An SM2 AttestToken signed with a non-standard user ID is rejected:
    /// verification pins the GM/T 0009 default ID (see `authn::sm2`).
    #[tokio::test]
    async fn test_sm2_attest_token_non_standard_user_id_rejected() {
        let (pub_pem, priv_pem) = generate_test_sm2_key_pair();
        let path = std::env::temp_dir().join("rbs_test_attest_sm2_wid.pem");
        std::fs::write(&path, &pub_pem).expect("write pub");
        let verifier = sm2_attest_verifier(path.to_string_lossy().to_string());

        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600) as u64;
        let token = sign_sm2_attest_token_with_id(
            &priv_pem,
            "Global Trust Authority",
            Some("rbs"),
            exp,
            b"",
        );

        let result = verifier.verify(&token).await;
        assert!(result.is_err(), "SM2 AttestToken with empty user ID must be rejected");
        match result.unwrap_err() {
            AuthError::TokenInvalid { .. } => {}
            other => panic!("expected TokenInvalid, got: {:?}", other),
        }
    }

    /// SM2 AttestToken verification via a JWKS file (crv "sm2p256v1") works end
    /// to end: kid lookup, JWK-to-PEM conversion, and signature verification
    /// under the standard user ID.
    #[tokio::test]
    async fn test_sm2_attest_token_via_jwks() {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SM2).unwrap();
        let ec = openssl::ec::EcKey::generate(&group).unwrap();

        // Affine coordinates for the SM2 JWK (crv "sm2p256v1").
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let mut x = openssl::bn::BigNum::new().unwrap();
        let mut y = openssl::bn::BigNum::new().unwrap();
        ec.public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
            .unwrap();
        let pkey = openssl::pkey::PKey::from_ec_key(ec).unwrap();
        let priv_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();

        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x.to_vec());
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&y.to_vec());
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "sm2p256v1", "kid": "sm2-kid-1",
                "use": "sig", "x": x_b64, "y": y_b64,
            }],
        });
        let jwks_path = std::env::temp_dir().join("rbs_test_attest_sm2_jwks.json");
        std::fs::write(&jwks_path, serde_json::to_vec(&jwks).unwrap()).unwrap();

        let config = AttestTokenVerificationConfig {
            public_key_path: None,
            jwks_file: Some(jwks_path.to_string_lossy().to_string()),
            issuer: "Global Trust Authority".to_string(),
            audience: Some("rbs".to_string()),
        };
        let verifier = AttestTokenVerifier::new(config).expect("verifier");

        // Compact JWS with kid pointing at the JWKS key.
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600) as u64;
        let header = serde_json::json!({ "alg": "SM2", "typ": "JWT", "kid": "sm2-kid-1" });
        let payload = serde_json::json!({
            "iss": "Global Trust Authority", "sub": "attest-sub", "aud": "rbs", "exp": exp
        });
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signing_key = openssl::pkey::PKey::private_key_from_pem(priv_pem.as_bytes()).unwrap();
        let sig = sm2::sign(&signing_key, signing_input.as_bytes()).expect("SM2 sign");
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig);
        let token = format!("{}.{}", signing_input, sig_b64);

        let result = verifier.verify(&token).await;
        assert!(result.is_ok(), "SM2 AttestToken via JWKS should verify: {:?}", result.err());
        assert_eq!(result.unwrap().token_type, TokenType::Attest);
    }

    /// SM2 JWK (crv "sm2p256v1") round-trips to a PEM that parses as an SM2 key.
    #[test]
    fn test_josekit_jwk_ec_to_pem_sm2() {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SM2).unwrap();
        let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let mut x = openssl::bn::BigNum::new().unwrap();
        let mut y = openssl::bn::BigNum::new().unwrap();
        ec_key
            .public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
            .unwrap();
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x.to_vec());
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&y.to_vec());
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(
                &serde_json::json!({"kty": "EC", "crv": "sm2p256v1", "x": x_b64, "y": y_b64}),
            )
            .unwrap(),
        )
        .unwrap();
        let result = josekit_jwk_ec_to_pem(&jwk).unwrap();
        let parsed = openssl::pkey::PKey::public_key_from_pem(&result).unwrap();
        // OpenSSL may report Id::SM2 or Id::EC for an SM2-curve key; both are accepted
        // by classify_pem_key. Assert it classifies as SM2.
        let (dk, es512, sm2) = classify_pem_key(&result).unwrap();
        assert!(dk.is_none() && es512.is_none() && sm2.is_some());
        let _ = parsed;
    }

    // ── Debug / Clone impls ──

    #[test]
    fn test_attest_token_verifier_debug_and_clone() {
        let verifier = create_verifier();
        let debug = format!("{:?}", verifier);
        assert!(debug.contains("AttestTokenVerifier"), "unexpected Debug output: {debug}");
        assert!(debug.contains("has_decoding_key: true"), "unexpected Debug output: {debug}");
        assert!(debug.contains("has_es512_verifier: false"), "unexpected Debug output: {debug}");
        assert!(debug.contains("has_sm2_key: false"), "unexpected Debug output: {debug}");
        assert!(debug.contains("has_jwk_set: false"), "unexpected Debug output: {debug}");

        let cloned = verifier.clone();
        assert!(cloned.decoding_key.is_some(), "clone must keep the PEM decoding key");
        assert!(cloned.jwk_set.is_none(), "clone must keep the absent JWKS");
        assert_eq!(format!("{:?}", cloned), debug, "clone must match the original");
    }

    // ── Construction: key file read/parse failures ──

    #[test]
    fn test_new_rejects_unreadable_public_key_file() {
        let config = AttestTokenVerificationConfig {
            public_key_path: Some(
                std::env::temp_dir()
                    .join("rbs_test_attest_missing_pubkey.pem")
                    .to_string_lossy()
                    .to_string(),
            ),
            jwks_file: None,
            issuer: "Global Trust Authority".to_string(),
            audience: None,
        };
        match AttestTokenVerifier::new(config) {
            Err(AuthError::TokenInvalid { reason }) => {
                assert!(
                    reason.contains("failed to read AttestToken public key file"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn test_new_rejects_unreadable_jwks_file() {
        let config = AttestTokenVerificationConfig {
            public_key_path: None,
            jwks_file: Some(
                std::env::temp_dir()
                    .join("rbs_test_attest_missing_jwks.json")
                    .to_string_lossy()
                    .to_string(),
            ),
            issuer: "Global Trust Authority".to_string(),
            audience: None,
        };
        match AttestTokenVerifier::new(config) {
            Err(AuthError::TokenInvalid { reason }) => {
                assert!(
                    reason.contains("failed to read JWKS file"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn test_new_rejects_malformed_jwks_file() {
        let file = write_temp_file(b"this is not a JWKS document");
        let config = AttestTokenVerificationConfig {
            public_key_path: None,
            jwks_file: Some(file.path().to_string_lossy().to_string()),
            issuer: "Global Trust Authority".to_string(),
            audience: None,
        };
        match AttestTokenVerifier::new(config) {
            Err(AuthError::TokenInvalid { reason }) => {
                assert!(
                    reason.contains("failed to parse JWKS file"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    // ── ES512 verification via JWKS ──

    /// ES512 AttestToken verifies against a JWKS selected by the header `kid`.
    #[tokio::test]
    async fn test_es512_via_jwks_with_kid() {
        let key_pair = generate_p521_key_pair();
        let mut jwk = key_pair.to_jwk_public_key();
        jwk.set_key_id("es512-kid-1");
        let verifier = jwks_verifier(
            vec![serde_json::to_value(jwk).expect("JWK to JSON")],
            Some("rbs"),
        );

        let token = sign_es512_jwt(
            &key_pair.to_pem_private_key(),
            attest_claims(3600),
            Some("es512-kid-1"),
        );
        let context = verifier
            .verify(&token)
            .await
            .expect("ES512 AttestToken should verify via JWKS");
        assert_eq!(context.token_type, TokenType::Attest);
        assert_eq!(context.claims["sub"], "attest-sub");
    }

    /// Without a `kid`, the first P-521 key in the JWKS is used.
    #[tokio::test]
    async fn test_es512_via_jwks_without_kid() {
        let key_pair = generate_p521_key_pair();
        // No `kid` on the JWK either: josekit would otherwise require the
        // token header to carry the same key ID.
        let jwk = key_pair.to_jwk_public_key();
        let verifier = jwks_verifier(
            vec![serde_json::to_value(jwk).expect("JWK to JSON")],
            Some("rbs"),
        );

        let token = sign_es512_jwt(&key_pair.to_pem_private_key(), attest_claims(3600), None);
        let context = verifier
            .verify(&token)
            .await
            .expect("ES512 AttestToken without kid should verify via JWKS");
        assert_eq!(context.token_type, TokenType::Attest);
    }

    /// A `kid` that is absent from the JWKS is rejected.
    #[tokio::test]
    async fn test_es512_via_jwks_rejects_unknown_kid() {
        let key_pair = generate_p521_key_pair();
        let mut jwk = key_pair.to_jwk_public_key();
        jwk.set_key_id("es512-kid-1");
        let verifier = jwks_verifier(
            vec![serde_json::to_value(jwk).expect("JWK to JSON")],
            Some("rbs"),
        );

        let token = sign_es512_jwt(
            &key_pair.to_pem_private_key(),
            attest_claims(3600),
            Some("unknown-kid"),
        );
        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("not found in JWKS"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// A `kid` that maps to a non-P-521 EC key cannot be used for ES512.
    #[tokio::test]
    async fn test_es512_via_jwks_rejects_kid_of_non_p521_key() {
        let p256_key_pair = josekit::jws::ES256
            .generate_key_pair()
            .expect("generate P-256 key pair");
        let mut p256_jwk = p256_key_pair.to_jwk_public_key();
        p256_jwk.set_key_id("p256-kid");
        let verifier = jwks_verifier(
            vec![serde_json::to_value(p256_jwk).expect("JWK to JSON")],
            Some("rbs"),
        );

        let key_pair = generate_p521_key_pair();
        let token = sign_es512_jwt(
            &key_pair.to_pem_private_key(),
            attest_claims(3600),
            Some("p256-kid"),
        );
        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("not found in JWKS"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// A JWKS without any P-521 key cannot verify an ES512 AttestToken that
    /// carries no `kid`.
    #[tokio::test]
    async fn test_es512_via_jwks_without_es512_key() {
        let rsa_key_pair = PS256.generate_key_pair(2048).expect("generate RSA key pair");
        let verifier = jwks_verifier(
            vec![serde_json::to_value(rsa_key_pair.to_jwk_public_key()).expect("JWK to JSON")],
            Some("rbs"),
        );

        let key_pair = generate_p521_key_pair();
        let token = sign_es512_jwt(&key_pair.to_pem_private_key(), attest_claims(3600), None);
        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("no ES512 key in JWKS"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// A P-521 JWK selected by `kid` but lacking key material fails to produce
    /// a verifier instead of panicking.
    #[tokio::test]
    async fn test_es512_via_jwks_rejects_incomplete_jwk() {
        let verifier = jwks_verifier(
            vec![serde_json::json!({
                "kty": "EC", "crv": "P-521", "alg": "ES512", "kid": "broken-kid",
            })],
            Some("rbs"),
        );

        let key_pair = generate_p521_key_pair();
        let token = sign_es512_jwt(
            &key_pair.to_pem_private_key(),
            attest_claims(3600),
            Some("broken-kid"),
        );
        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("failed to create ES512 verifier from JWK"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// A verifier holding only a non-EC key has no ES512 key at all.
    #[tokio::test]
    async fn test_es512_without_any_configured_key() {
        let verifier = create_verifier();
        let key_pair = generate_p521_key_pair();
        let token = sign_es512_jwt(
            &key_pair.to_pem_private_key(),
            attest_claims(3600),
            Some("es512-kid-1"),
        );
        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("no key configured for ES512 verification"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// An ES512 AttestToken signed by an untrusted key is rejected.
    #[tokio::test]
    async fn test_es512_rejects_invalid_signature() {
        let trusted = generate_p521_key_pair();
        let attacker = generate_p521_key_pair();
        let verifier = pem_verifier(&trusted.to_pem_public_key(), Some("rbs"));
        let token = sign_es512_jwt(&attacker.to_pem_private_key(), attest_claims(3600), None);

        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => {
                assert_eq!(reason, "invalid signature");
            }
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// An ES512 AttestToken without an `iss` claim is rejected even though the
    /// signature and the other claims are valid.
    #[tokio::test]
    async fn test_es512_rejects_missing_iss_claim() {
        let key_pair = generate_p521_key_pair();
        let verifier = pem_verifier(&key_pair.to_pem_public_key(), Some("rbs"));
        let claims = serde_json::json!({
            "sub": "attest-sub",
            "aud": "rbs",
            "exp": now_secs() + 3600,
        });
        let token = sign_es512_jwt(&key_pair.to_pem_private_key(), claims, None);

        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert_eq!(reason, "missing iss claim"),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// An ES512 AttestToken issued by another party fails the issuer check of
    /// the shared josekit payload validator.
    #[tokio::test]
    async fn test_es512_rejects_issuer_mismatch() {
        let key_pair = generate_p521_key_pair();
        let verifier = pem_verifier(&key_pair.to_pem_public_key(), Some("rbs"));
        let mut claims = attest_claims(3600);
        claims["iss"] = serde_json::Value::String("another issuer".to_string());
        let token = sign_es512_jwt(&key_pair.to_pem_private_key(), claims, None);

        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("issuer"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    // ── SM2 key resolution and signature decoding ──

    /// `verify_sm2` requires the compact JWS shape; `verify` already rejects
    /// shorter tokens, so the check is exercised directly.
    #[tokio::test]
    async fn test_verify_sm2_rejects_malformed_compact_jws() {
        let verifier = create_verifier();
        match verifier.verify_sm2("not-a-compact-jws", None).await {
            Err(AuthError::TokenInvalid { reason }) => assert_eq!(reason, "invalid token"),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// A signature segment that is not base64url is rejected before any key is
    /// resolved.
    #[tokio::test]
    async fn test_sm2_rejects_undecodable_signature() {
        let verifier = create_verifier();
        let token = sm2_jws_with_signature(attest_claims(3600), "!!not-base64!!");
        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert_eq!(reason, "invalid token"),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// Signature bytes that OpenSSL cannot decode are reported as an invalid
    /// token rather than an internal error.
    #[tokio::test]
    async fn test_sm2_rejects_undecodable_signature_bytes() {
        let (pub_pem, _) = generate_test_sm2_key_pair();
        let verifier = pem_verifier(pub_pem.as_bytes(), Some("rbs"));
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 100]);
        let token = sm2_jws_with_signature(attest_claims(3600), &signature);

        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert_eq!(reason, "invalid token"),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// A verifier configured with a non-SM2 PEM has no SM2 key to use.
    #[tokio::test]
    async fn test_sm2_without_configured_sm2_key() {
        let verifier = create_verifier();
        let (_, priv_pem) = sm2_jwk_with_private_pem(None);
        let token = sign_sm2_jws(&priv_pem, None, attest_claims(3600));

        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("no key configured for SM2 verification"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// Without a `kid`, the SM2 key is found by scanning the JWKS keys.
    #[tokio::test]
    async fn test_sm2_via_jwks_without_kid_selects_sm2_key() {
        let (sm2_jwk, priv_pem) = sm2_jwk_with_private_pem(Some("sm2-kid-1"));
        let rsa_key_pair = PS256.generate_key_pair(2048).expect("generate RSA key pair");
        // The RSA key comes first so the SM2 key is not simply the first entry.
        let verifier = jwks_verifier(
            vec![
                serde_json::to_value(rsa_key_pair.to_jwk_public_key()).expect("JWK to JSON"),
                sm2_jwk,
            ],
            Some("rbs"),
        );

        let token = sign_sm2_jws(&priv_pem, None, attest_claims(3600));
        let context = verifier
            .verify(&token)
            .await
            .expect("SM2 AttestToken should verify via JWKS");
        assert_eq!(context.token_type, TokenType::Attest);
    }

    /// A JWKS holding no SM2-curve key is reported as such, both for a `kid`
    /// lookup and for a full scan.
    #[tokio::test]
    async fn test_sm2_via_jwks_without_sm2_key() {
        let rsa_key_pair = PS256.generate_key_pair(2048).expect("generate RSA key pair");
        let verifier = jwks_verifier(
            vec![serde_json::to_value(rsa_key_pair.to_jwk_public_key()).expect("JWK to JSON")],
            Some("rbs"),
        );
        let (_, priv_pem) = sm2_jwk_with_private_pem(None);

        for kid in [Some("sm2-kid-1"), None] {
            let token = sign_sm2_jws(&priv_pem, kid, attest_claims(3600));
            match verifier.verify(&token).await {
                Err(AuthError::TokenInvalid { reason }) => assert!(
                    reason.contains("no SM2 key found in JWKS"),
                    "unexpected reason: {reason}"
                ),
                other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
            }
        }
    }

    // ── Decoding key resolution via JWKS ──

    /// An SM2 PEM key cannot verify an RSA-PSS token: neither a PEM decoding
    /// key nor a JWKS is available.
    #[tokio::test]
    async fn test_ps256_with_sm2_pem_reports_no_jwks() {
        let (pub_pem, _) = generate_test_sm2_key_pair();
        let verifier = pem_verifier(pub_pem.as_bytes(), Some("rbs"));
        let (private_pem, _) = generate_rsa_key_pair();
        let token = sign_ps256_jwt(&private_pem, attest_claims(3600), None);

        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert_eq!(reason, "no JWKS loaded"),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// RSA-PSS AttestToken verifies against a JWKS selected by the header `kid`.
    #[tokio::test]
    async fn test_ps256_via_jwks_with_kid() {
        let (private_pem, mut jwk) = generate_rsa_key_pair();
        jwk["kid"] = serde_json::Value::String("rsa-kid-1".to_string());
        let verifier = jwks_verifier(vec![jwk], Some("rbs"));

        let token = sign_ps256_jwt(&private_pem, attest_claims(3600), Some("rsa-kid-1"));
        let context = verifier
            .verify(&token)
            .await
            .expect("RSA-PSS AttestToken should verify via JWKS");
        assert_eq!(context.token_type, TokenType::Attest);
    }

    /// A `kid` that is absent from the JWKS is rejected.
    #[tokio::test]
    async fn test_ps256_via_jwks_rejects_unknown_kid() {
        let (private_pem, mut jwk) = generate_rsa_key_pair();
        jwk["kid"] = serde_json::Value::String("rsa-kid-1".to_string());
        let verifier = jwks_verifier(vec![jwk], Some("rbs"));

        let token = sign_ps256_jwt(&private_pem, attest_claims(3600), Some("unknown-kid"));
        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("not found in JWKS"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    /// Without a `kid`, the first key in the JWKS is used.
    #[tokio::test]
    async fn test_ps256_via_jwks_without_kid() {
        let (private_pem, jwk) = generate_rsa_key_pair();
        let verifier = jwks_verifier(vec![jwk], Some("rbs"));

        let token = sign_ps256_jwt(&private_pem, attest_claims(3600), None);
        let context = verifier
            .verify(&token)
            .await
            .expect("RSA-PSS AttestToken without kid should verify via JWKS");
        assert_eq!(context.token_type, TokenType::Attest);
    }

    /// An empty JWKS cannot resolve any key.
    #[tokio::test]
    async fn test_ps256_via_jwks_rejects_empty_key_set() {
        let verifier = jwks_verifier(Vec::new(), Some("rbs"));
        let (private_pem, _) = generate_rsa_key_pair();
        let token = sign_ps256_jwt(&private_pem, attest_claims(3600), None);

        match verifier.verify(&token).await {
            Err(AuthError::TokenInvalid { reason }) => assert_eq!(reason, "no keys in JWKS"),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    // ── PEM classification of unsupported keys ──

    #[test]
    fn test_classify_pem_key_unsupported_ec_curve() {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1)
            .expect("secp256k1 group");
        let ec_key = openssl::ec::EcKey::generate(&group).expect("generate secp256k1 key");
        let pem = openssl::pkey::PKey::from_ec_key(ec_key)
            .expect("wrap secp256k1 key")
            .public_key_to_pem()
            .expect("secp256k1 PEM");

        match classify_pem_key(&pem) {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("unsupported EC curve"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn test_classify_pem_key_unsupported_key_type() {
        let x25519 = openssl::pkey::PKey::generate_x25519().expect("generate X25519 key");
        let pem = x25519.public_key_to_pem().expect("X25519 PEM");

        match classify_pem_key(&pem) {
            Err(AuthError::TokenInvalid { reason }) => assert_eq!(
                reason, "unsupported key type for AttestToken",
                "unexpected reason"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    // ── JWK-to-PEM conversion failures ──

    #[test]
    fn test_get_jwk_base64_param_rejects_non_string_parameter() {
        let mut jwk = josekit::jwk::Jwk::new("RSA");
        jwk.set_parameter("n", Some(serde_json::json!(123)))
            .expect("set numeric n parameter");

        match get_jwk_base64_param(&jwk, "n") {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("must be a string in JWK"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn test_josekit_jwk_ec_to_pem_rejects_point_off_curve() {
        // Coordinates in range for P-256 but not a point on the curve.
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let jwk: josekit::jwk::Jwk = josekit::jwk::Jwk::from_bytes(
            serde_json::to_vec(
                &serde_json::json!({"kty": "EC", "crv": "P-256", "x": x_b64, "y": y_b64}),
            )
            .expect("serialize JWK"),
        )
        .expect("parse JWK");

        match josekit_jwk_ec_to_pem(&jwk) {
            Err(AuthError::TokenInvalid { reason }) => assert!(
                reason.contains("invalid EC public key"),
                "unexpected reason: {reason}"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn test_josekit_jwk_okp_to_pem_missing_crv() {
        let jwk = josekit::jwk::Jwk::new("OKP");

        match josekit_jwk_okp_to_pem(&jwk) {
            Err(AuthError::TokenInvalid { reason }) => assert_eq!(
                reason, "missing crv in OKP JWK",
                "unexpected reason"
            ),
            other => panic!("expected TokenInvalid, got: {:?}", other.map(|_| ())),
        }
    }
}

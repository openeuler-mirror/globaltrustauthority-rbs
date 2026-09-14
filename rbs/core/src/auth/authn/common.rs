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

//! Common JWT verification utilities shared between token verifiers.

use crate::auth::error::AuthError;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;

/// Supported algorithms for token verification.
///
/// `SM2` is a non-RFC-registered custom JWS algorithm identifier (see RFC 7518):
/// it denotes SM2 ECDSA over the SM3 digest, mandated by GM/T 0003. Both
/// `jsonwebtoken` and `josekit` lack SM2 support, so SM2 tokens take a dedicated
/// verification path (`verify_sm2`) backed by the vendored OpenSSL backend rather
/// than the `DecodingKey`/`jsonwebtoken::Algorithm` route. All SM2 operations pin
/// the GM/T 0009 default user ID "1234567812345678" (see `authn::sm2`) because
/// OpenSSL >= 3.5 no longer applies it implicitly.
pub const SUPPORTED_ALGORITHMS: &[&str] =
    &["PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "SM2"];

/// Parsed JWT header (library-agnostic).
#[derive(Debug, Clone)]
pub struct RawHeader {
    pub alg: String,
    pub kid: Option<String>,
}

/// Minimal header JSON for raw parsing.
#[derive(Debug, Deserialize)]
struct RawHeaderJson {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// Decode the JWT header without verifying the signature.
pub fn decode_token_header(token: &str) -> Result<RawHeader, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::TokenInvalid {
            reason: "invalid token format".to_string(),
        });
    }

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to decode token header: {}", e),
        })?;

    let header: RawHeaderJson = serde_json::from_slice(&header_bytes).map_err(|e| {
        AuthError::TokenInvalid {
            reason: format!("failed to parse token header: {}", e),
        }
    })?;

    Ok(RawHeader {
        alg: header.alg,
        kid: header.kid,
    })
}

/// Validate that the algorithm is supported.
pub fn validate_algorithm(alg: &str) -> Result<(), AuthError> {
    if SUPPORTED_ALGORITHMS.contains(&alg) {
        Ok(())
    } else {
        Err(AuthError::TokenInvalid {
            reason: format!(
                "unsupported algorithm: {}. Supported algorithms: {}",
                alg, SUPPORTED_ALGORITHMS.join(", ")
            ),
        })
    }
}

/// True if the algorithm is ES512 (requires josekit verification path).
#[inline]
pub fn is_es512(alg: &str) -> bool {
    alg == "ES512"
}

/// True if the algorithm is SM2 (requires the OpenSSL SM2+SM3 verification path).
///
/// Neither `jsonwebtoken` nor `josekit` supports SM2, so callers must dispatch
/// to a dedicated `verify_sm2` path before reaching `to_jsonwebtoken_alg` /
/// `create_decoding_key`, which have no SM2 mapping.
#[inline]
pub fn is_sm2(alg: &str) -> bool {
    alg == "SM2"
}

/// Convert an algorithm string to jsonwebtoken's `Algorithm` enum.
pub(crate) fn to_jsonwebtoken_alg(alg: &str) -> Result<Algorithm, AuthError> {
    match alg {
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        _ => Err(AuthError::TokenInvalid {
            reason: format!("unsupported algorithm: {}", alg),
        }),
    }
}

/// Create a `DecodingKey` from PEM-encoded public key bytes.
pub fn create_decoding_key(alg: &str, pem: &[u8]) -> Result<DecodingKey, AuthError> {
    match to_jsonwebtoken_alg(alg)? {
        Algorithm::EdDSA => DecodingKey::from_ed_pem(pem).map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to create EdDSA decoding key: {}", e),
        }),
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(pem).map_err(|e| AuthError::TokenInvalid {
                reason: format!("failed to create EC decoding key: {}", e),
            })
        }
        _ => {
            // RSA-PSS algorithms use RSA keys
            DecodingKey::from_rsa_pem(pem).map_err(|e| AuthError::TokenInvalid {
                reason: format!("failed to create RSA decoding key: {}", e),
            })
        }
    }
}

/// Validate standard JWT claims (exp, iss, aud) for library-unsupported algorithm
/// paths (e.g. SM2) that verify the signature out-of-band and parse claims manually.
///
/// `exp` is required and must be in the future (expired → `TokenExpired`).
/// `iss` must equal `issuer`. `audience`, when `Some`, must be present in the `aud`
/// claim (accepted as a string or array of strings). All other failures collapse to
/// `TokenInvalid { reason: "invalid token" }` to keep the user-enumeration-safe
/// behavior of the ES512 path.
pub fn validate_jwt_claims(
    claims: &serde_json::Value,
    issuer: &str,
    audience: Option<&str>,
) -> Result<(), AuthError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AuthError::TokenInvalid { reason: "invalid token".to_string() })?
        .as_secs() as i64;

    match claims.get("exp").and_then(|v| v.as_i64()) {
        None => {
            return Err(AuthError::TokenInvalid { reason: "missing exp claim".to_string() });
        }
        Some(exp) if exp <= now => {
            return Err(AuthError::TokenExpired);
        }
        _ => {}
    }

    match claims.get("iss").and_then(|v| v.as_str()) {
        Some(iss) if iss == issuer => {}
        _ => {
            return Err(AuthError::TokenInvalid { reason: "invalid token".to_string() });
        }
    }

    if let Some(expected_aud) = audience {
        let aud_ok = match claims.get("aud") {
            Some(serde_json::Value::String(s)) => s == expected_aud,
            Some(serde_json::Value::Array(arr)) => {
                arr.iter().filter_map(|v| v.as_str()).any(|s| s == expected_aud)
            }
            _ => false,
        };
        if !aud_ok {
            return Err(AuthError::TokenInvalid { reason: "invalid token".to_string() });
        }
    }

    Ok(())
}

/// Explicitly validate `exp` on a josekit-decoded JWT payload (ES512 paths).
///
/// josekit's `JwtPayloadValidator` only checks `exp` when the claim is present
/// and reports expiry as a generic `InvalidClaim`, so presence and expiry are
/// handled here — matching the jsonwebtoken paths' required-claims behavior —
/// before iss/aud/nbf are delegated to the validator. The shared
/// implementation keeps the Bearer and Attest ES512 paths from drifting apart.
///
/// Returns the pinned `now` used for the expiry comparison so the caller can
/// pass the same clock read to `JwtPayloadValidator::set_base_time` (every
/// time-based check then shares one timestamp).
pub fn validate_josekit_exp(
    label: &str,
    payload: &josekit::jwt::JwtPayload,
) -> Result<std::time::SystemTime, AuthError> {
    let now = std::time::SystemTime::now();
    match payload.expires_at() {
        None => {
            log::warn!("{} ES512 rejected: missing exp claim", label);
            Err(AuthError::TokenInvalid {
                reason: "missing exp claim".to_string(),
            })
        }
        Some(exp) if exp <= now => {
            log::warn!("{} ES512 rejected: token expired", label);
            Err(AuthError::TokenExpired)
        }
        _ => Ok(now),
    }
}

/// Map jsonwebtoken errors to AuthError with detailed messages.
pub fn map_jwt_error(
    error: &jsonwebtoken::errors::Error,
    expected_issuer: Option<&str>,
) -> AuthError {
    use jsonwebtoken::errors::ErrorKind;

    match error.kind() {
        ErrorKind::InvalidSignature => AuthError::TokenInvalid {
            reason: "invalid signature".to_string(),
        },
        ErrorKind::ExpiredSignature => AuthError::TokenExpired,
        ErrorKind::ImmatureSignature => AuthError::TokenNotYetValid,
        ErrorKind::InvalidIssuer => AuthError::TokenInvalid {
            reason: if let Some(issuer) = expected_issuer {
                format!("issuer mismatch: expected '{}'", issuer)
            } else {
                "invalid issuer".to_string()
            },
        },
        ErrorKind::InvalidAudience => AuthError::TokenInvalid {
            reason: "audience mismatch".to_string(),
        },
        ErrorKind::InvalidToken => AuthError::TokenInvalid {
            reason: "invalid token format".to_string(),
        },
        _ => AuthError::TokenInvalid {
            reason: format!("token verification failed: {}", error),
        },
    }
}

/// Map josekit errors to AuthError with detailed messages.
pub fn map_josekit_error(error: &josekit::JoseError, expected_issuer: Option<&str>) -> AuthError {
    use josekit::JoseError;

    match error {
        JoseError::InvalidSignature(_) => AuthError::TokenInvalid {
            reason: "invalid signature".to_string(),
        },
        JoseError::InvalidClaim(err) => {
            let msg = err.to_string();
            if msg.contains("expired") || msg.contains("expires") {
                AuthError::TokenExpired
            } else if msg.contains("not yet valid") || msg.contains("not before") {
                AuthError::TokenNotYetValid
            } else if msg.contains("iss") || msg.contains("issuer") {
                AuthError::TokenInvalid {
                    reason: if let Some(issuer) = expected_issuer {
                        format!("issuer mismatch: expected '{}'", issuer)
                    } else {
                        "invalid issuer".to_string()
                    },
                }
            } else if msg.contains("aud") || msg.contains("audience") {
                AuthError::TokenInvalid {
                    reason: "audience mismatch".to_string(),
                }
            } else {
                AuthError::TokenInvalid {
                    reason: format!("invalid claim: {}", msg),
                }
            }
        }
        _ => AuthError::TokenInvalid {
            reason: format!("token verification failed: {}", error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_algorithm_supported() {
        assert!(validate_algorithm("PS256").is_ok());
        assert!(validate_algorithm("PS384").is_ok());
        assert!(validate_algorithm("PS512").is_ok());
        assert!(validate_algorithm("ES256").is_ok());
        assert!(validate_algorithm("ES384").is_ok());
        assert!(validate_algorithm("ES512").is_ok());
        assert!(validate_algorithm("EdDSA").is_ok());
    }

    #[test]
    fn test_validate_algorithm_unsupported() {
        let result = validate_algorithm("RS256");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported algorithm"));
    }

    #[test]
    fn test_supported_algorithms_constant() {
        assert_eq!(SUPPORTED_ALGORITHMS.len(), 8);
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS256"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS384"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS512"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"ES256"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"ES384"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"ES512"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"EdDSA"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"SM2"));
    }

    #[test]
    fn test_unsupported_algorithms_not_in_list() {
        assert!(!SUPPORTED_ALGORITHMS.contains(&"RS256"));
        assert!(!SUPPORTED_ALGORITHMS.contains(&"RS384"));
        assert!(!SUPPORTED_ALGORITHMS.contains(&"RS512"));
        assert!(!SUPPORTED_ALGORITHMS.contains(&"HS256"));
        assert!(!SUPPORTED_ALGORITHMS.contains(&"HS384"));
        assert!(!SUPPORTED_ALGORITHMS.contains(&"HS512"));
    }

    #[test]
    fn test_is_es512() {
        assert!(is_es512("ES512"));
        assert!(!is_es512("ES256"));
        assert!(!is_es512("ES384"));
        assert!(!is_es512("EdDSA"));
    }

    #[test]
    fn test_decode_token_header_es512() {
        // A well-formed JWT header with ES512
        let header = r#"{"alg":"ES512","kid":"test-key"}"#;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);
        let token = format!("{}.eyJzdWIiOiJ0ZXN0In0=.sig", header_b64);

        let parsed = decode_token_header(&token).unwrap();
        assert_eq!(parsed.alg, "ES512");
        assert_eq!(parsed.kid.as_deref(), Some("test-key"));
    }

    #[test]
    fn test_decode_token_header_missing_kid() {
        let header = r#"{"alg":"ES256"}"#;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);
        let token = format!("{}.eyJzdWIiOiJ0ZXN0In0=.sig", header_b64);

        let parsed = decode_token_header(&token).unwrap();
        assert_eq!(parsed.alg, "ES256");
        assert_eq!(parsed.kid, None);
    }

    #[test]
    fn test_decode_token_header_malformed() {
        assert!(decode_token_header("not.a.token").is_err());
        assert!(decode_token_header("").is_err());
    }
}

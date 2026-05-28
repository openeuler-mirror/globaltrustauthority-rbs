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
pub const SUPPORTED_ALGORITHMS: &[&str] =
    &["PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"];

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
        assert_eq!(SUPPORTED_ALGORITHMS.len(), 7);
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS256"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS384"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS512"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"ES256"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"ES384"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"ES512"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"EdDSA"));
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

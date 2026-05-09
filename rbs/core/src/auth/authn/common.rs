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
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Header};

/// Supported algorithms for token verification.
/// Only RSA-PSS and EdDSA are supported for security reasons.
pub const SUPPORTED_ALGORITHMS: &[Algorithm] =
    &[Algorithm::PS256, Algorithm::PS384, Algorithm::PS512, Algorithm::EdDSA];

/// Human-readable list of supported algorithms for error messages.
pub const SUPPORTED_ALGORITHMS_STR: &str = "PS256, PS384, PS512, EdDSA";

/// Validate that the algorithm is supported.
///
/// # Arguments
/// * `alg` - The algorithm to validate
///
/// # Returns
/// * `Ok(())` if the algorithm is supported
/// * `Err(AuthError::TokenInvalid)` if the algorithm is not supported
pub fn validate_algorithm(alg: &Algorithm) -> Result<(), AuthError> {
    if SUPPORTED_ALGORITHMS.contains(alg) {
        Ok(())
    } else {
        Err(AuthError::TokenInvalid {
            reason: format!("unsupported algorithm: {:?}. Supported algorithms: {}", alg, SUPPORTED_ALGORITHMS_STR),
        })
    }
}

/// Decode the JWT header without verifying the signature.
///
/// # Arguments
/// * `token` - The JWT token string
///
/// # Returns
/// * `Ok(Header)` on success
/// * `Err(AuthError::TokenInvalid)` if the header cannot be decoded
pub fn decode_token_header(token: &str) -> Result<Header, AuthError> {
    decode_header(token).map_err(|e| AuthError::TokenInvalid {
        reason: format!("failed to decode token header: {}", e),
    })
}

/// Create a DecodingKey from PEM-encoded public key bytes.
///
/// Automatically detects whether the key is Ed25519 or RSA based on the algorithm.
///
/// # Arguments
/// * `alg` - The algorithm to use (determines key type)
/// * `pem` - PEM-encoded public key bytes
///
/// # Returns
/// * `Ok(DecodingKey)` on success
/// * `Err(AuthError::TokenInvalid)` if the key cannot be created
pub fn create_decoding_key(alg: &Algorithm, pem: &[u8]) -> Result<DecodingKey, AuthError> {
    if *alg == Algorithm::EdDSA {
        DecodingKey::from_ed_pem(pem).map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to create EdDSA decoding key: {}", e),
        })
    } else {
        DecodingKey::from_rsa_pem(pem).map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to create RSA decoding key: {}", e),
        })
    }
}

/// Map jsonwebtoken errors to AuthError with detailed messages.
///
/// This function provides consistent error mapping across all token verifiers.
///
/// # Arguments
/// * `error` - The jsonwebtoken error
/// * `expected_issuer` - Optional expected issuer for issuer mismatch errors
///
/// # Returns
/// * The appropriate AuthError variant
pub fn map_jwt_error(error: &jsonwebtoken::errors::Error, expected_issuer: Option<&str>) -> AuthError {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_algorithm_supported() {
        assert!(validate_algorithm(&Algorithm::PS256).is_ok());
        assert!(validate_algorithm(&Algorithm::PS384).is_ok());
        assert!(validate_algorithm(&Algorithm::PS512).is_ok());
        assert!(validate_algorithm(&Algorithm::EdDSA).is_ok());
    }

    #[test]
    fn test_validate_algorithm_unsupported() {
        let result = validate_algorithm(&Algorithm::RS256);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported algorithm"));
    }

    #[test]
    fn test_supported_algorithms_constant() {
        assert_eq!(SUPPORTED_ALGORITHMS.len(), 4);
        assert!(SUPPORTED_ALGORITHMS.contains(&Algorithm::PS256));
        assert!(SUPPORTED_ALGORITHMS.contains(&Algorithm::PS384));
        assert!(SUPPORTED_ALGORITHMS.contains(&Algorithm::PS512));
        assert!(SUPPORTED_ALGORITHMS.contains(&Algorithm::EdDSA));
    }

    #[test]
    fn test_unsupported_algorithms_not_in_list() {
        // RS* algorithms are not supported
        assert!(!SUPPORTED_ALGORITHMS.contains(&Algorithm::RS256));
        assert!(!SUPPORTED_ALGORITHMS.contains(&Algorithm::RS384));
        assert!(!SUPPORTED_ALGORITHMS.contains(&Algorithm::RS512));
        // HS* algorithms are not supported (symmetric)
        assert!(!SUPPORTED_ALGORITHMS.contains(&Algorithm::HS256));
        assert!(!SUPPORTED_ALGORITHMS.contains(&Algorithm::HS384));
        assert!(!SUPPORTED_ALGORITHMS.contains(&Algorithm::HS512));
    }
}

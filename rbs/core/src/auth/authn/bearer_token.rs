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

//! Bearer token verification module.
//!
//! BearerToken uses per-user public keys resolved from storage
//! via [`UserKeyProvider`] using the `sub` claim.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{decode, Validation};
use log::{debug, error};
use rbs_api_types::config::BearerTokenVerificationConfig;
use serde_json::Value;

use crate::auth::authn::common::{create_decoding_key, decode_token_header, validate_algorithm};
use crate::auth::authn::{TokenVerifier, UserKeyProvider};
use crate::auth::context::{BearerContext, TokenType};
use crate::auth::error::AuthError;

/// Bearer token verifier.
///
/// Unlike AttestToken, BearerToken public keys come from the database (per-user),
/// looked up via [`UserKeyProvider`] using the `sub` claim.
#[derive(Clone)]
pub struct BearerTokenVerifier {
    config: BearerTokenVerificationConfig,
    key_provider: Arc<dyn UserKeyProvider>,
}

impl std::fmt::Debug for BearerTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerTokenVerifier")
            .field("issuer", &self.config.issuer)
            .finish()
    }
}

impl BearerTokenVerifier {
    /// Create a new BearerTokenVerifier.
    ///
    /// `key_provider` resolves per-user public keys from storage.
    pub fn new(config: BearerTokenVerificationConfig, key_provider: Arc<dyn UserKeyProvider>) -> Self {
        Self { config, key_provider }
    }
}

#[async_trait]
impl TokenVerifier for BearerTokenVerifier {
    type Context = BearerContext;

    /// Verify Bearer token and return BearerContext.
    ///
    /// # Security Note
    ///
    /// This implementation decodes the JWT payload without signature verification
    /// to extract the `sub` claim for per-user key lookup. This is necessary because
    /// BearerToken uses per-user public keys stored in the database.
    ///
    /// The security model is:
    /// 1. Extract `sub` from unverified payload
    /// 2. Look up the user's public key from trusted storage
    /// 3. Verify the signature with the looked-up key
    /// 4. Re-validate all claims after signature verification
    ///
    /// This approach is secure because:
    /// - The signature is verified before any claims are trusted
    /// - An attacker cannot forge a signature without the user's private key
    /// - Key lookup failures are masked to prevent user enumeration
    async fn verify(&self, token: &str) -> Result<BearerContext, AuthError> {
        // Step 1 — Parse header to get algorithm.
        let header = decode_token_header(token)?;

        // Validate algorithm is supported
        validate_algorithm(&header.alg)?;

        // Step 2 — Extract sub from unverified payload for key lookup.
        // See security note above for why this is safe.
        let sub = extract_sub_from_payload(token)?;

        // Step 3 — Look up the per-user public key.
        // Mask key-lookup errors with a generic message (prevent user enumeration).
        // Log detailed errors for debugging (不影响返回给客户端的错误信息).
        let public_key_pem = self
            .key_provider
            .get_public_key(&sub)
            .await
            .map_err(|e| {
                error!("BearerToken key lookup failed for sub '{}': {}", sub, e);
                AuthError::TokenInvalid {
                    reason: "invalid token".to_string(),
                }
            })?;

        // Create decoding key based on algorithm
        // Log detailed errors for debugging.
        let decoding_key =
            create_decoding_key(&header.alg, public_key_pem.as_bytes()).map_err(|e| {
                debug!("BearerToken decoding key creation failed: {}", e);
                AuthError::TokenInvalid {
                    reason: "invalid token".to_string(),
                }
            })?;

        // Step 4 — Verify the cryptographic signature.
        let mut validation = Validation::new(header.alg);
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let token_data = decode::<Value>(token, &decoding_key, &validation).map_err(|e| {
            // Mask detailed errors for security (prevent user enumeration)
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                ErrorKind::ImmatureSignature => AuthError::TokenNotYetValid,
                _ => AuthError::TokenInvalid {
                    reason: "invalid token".to_string(),
                },
            }
        })?;

        // Step 5 — Signature is trusted. Extract claims.
        let iss = token_data
            .claims
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::TokenInvalid {
                reason: "missing iss claim".to_string(),
            })?
            .to_string();

        let role = token_data
            .claims
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(BearerContext {
            iss,
            sub,
            role,
            claims: token_data.claims,
            token_type: TokenType::Bearer,
        })
    }
}

/// Extract the `sub` claim from JWT payload without signature verification.
///
/// # Security
///
/// This function only extracts the `sub` claim for key lookup purposes.
/// The extracted value is NOT trusted until signature verification completes.
/// Errors are intentionally generic to prevent information leakage.
fn extract_sub_from_payload(token: &str) -> Result<String, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::TokenInvalid {
            reason: "invalid token".to_string(),
        });
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AuthError::TokenInvalid {
            reason: "invalid token".to_string(),
        })?;

    let claims: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| AuthError::TokenInvalid {
            reason: "invalid token".to_string(),
        })?;

    claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| AuthError::TokenInvalid {
            reason: "invalid token".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authn::common::SUPPORTED_ALGORITHMS;

    const TEST_PUBLIC_KEY_PEM: &str = concat!(
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

    const MALFORMED_TOKEN: &str = "not.a.valid.jwt.token";

    /// Stub UserKeyProvider that returns the test public key for any sub.
    #[derive(Debug)]
    struct StubKeyProvider(String);

    #[async_trait]
    impl UserKeyProvider for StubKeyProvider {
        async fn get_public_key(&self, _sub: &str) -> Result<String, AuthError> {
            Ok(self.0.clone())
        }
    }

    fn create_verifier() -> BearerTokenVerifier {
        let config = BearerTokenVerificationConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "globaltrustauthority-rbs".to_string(),
        };
        let key_provider = Arc::new(StubKeyProvider(TEST_PUBLIC_KEY_PEM.to_string()));
        BearerTokenVerifier::new(config, key_provider)
    }

    #[tokio::test]
    async fn test_bearer_token_malformed_format() {
        let verifier = create_verifier();
        let result = verifier.verify(MALFORMED_TOKEN).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_supported_algorithms_from_common() {
        assert!(SUPPORTED_ALGORITHMS.contains(&jsonwebtoken::Algorithm::PS256));
        assert!(SUPPORTED_ALGORITHMS.contains(&jsonwebtoken::Algorithm::PS384));
        assert!(SUPPORTED_ALGORITHMS.contains(&jsonwebtoken::Algorithm::PS512));
        assert!(SUPPORTED_ALGORITHMS.contains(&jsonwebtoken::Algorithm::EdDSA));
    }

    #[test]
    fn test_extract_sub_valid_payload() {
        // Payload: {"sub":"user123","iss":"test"}
        let token = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoidGVzdCJ9.signature";
        let result = extract_sub_from_payload(token);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "user123");
    }

    #[test]
    fn test_extract_sub_missing_sub() {
        // Payload: {"iss":"test"}
        let token = "eyJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature";
        let result = extract_sub_from_payload(token);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_sub_malformed_payload() {
        let token = "header.invalid.signature";
        let result = extract_sub_from_payload(token);
        assert!(result.is_err());
    }
}

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

//! JWT verification module for Bearer tokens.
//!
//! Public keys are resolved per-user: the `sub` claim is used to look up the
//! PEM-encoded key from the database via [`UserKeyProvider`].

use std::sync::Arc;

use crate::auth::authn::signature::{decode_jwt_part, verify_jwt_signature};
use crate::auth::authn::UserKeyProvider;
use crate::auth::context::{BearerContext, TokenType};
use crate::auth::error::AuthError;
use chrono::Utc;
use openssl::pkey::PKey;
use rbs_api_types::config::JwtVerificationConfig;
use serde_json::Value;

/// JWT verifier for Bearer tokens.
///
/// Unlike AttestToken, BearerToken public keys come from the database (per-user),
/// looked up via [`UserKeyProvider`] using the `sub` claim.
#[derive(Clone)]
pub struct JwtVerifier {
    config: JwtVerificationConfig,
    key_provider: Arc<dyn UserKeyProvider>,
}

impl std::fmt::Debug for JwtVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtVerifier")
            .field("issuer", &self.config.issuer)
            .finish()
    }
}

impl JwtVerifier {
    /// Create a new JwtVerifier.
    ///
    /// `key_provider` resolves per-user public keys from storage.
    pub fn new(config: JwtVerificationConfig, key_provider: Arc<dyn UserKeyProvider>) -> Self {
        Self { config, key_provider }
    }

    /// Verify JWT token and return BearerContext.
    ///
    /// Verification order (per JWT best practice):
    /// 1. Parse header (alg) and payload (sub only — needed for key lookup).
    /// 2. Look up the per-user public key.
    /// 3. Verify the cryptographic signature.
    /// 4. Only after the signature is trusted, validate claims (iss, exp, nbf, role).
    ///
    /// Errors from key lookup and signature verification are masked with a
    /// generic message to prevent user-enumeration attacks.
    pub async fn verify(&self, token: &str) -> Result<BearerContext, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::TokenInvalid { reason: "invalid JWT format".to_string() });
        }

        let header = parts[0];
        let payload = parts[1];
        let signature = parts[2];

        // Step 1 — Parse header to get algorithm.
        let header_bytes = decode_jwt_part(header)?;
        let header_json: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to parse header: {}", e) })?;

        let alg = header_json.get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing alg in header".to_string() })?;

        // Step 1 — Parse payload, extract only `sub` (required to look up the key).
        // Other claims are not trusted until after signature verification.
        let payload_bytes = decode_jwt_part(payload)?;
        let claims: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to parse claims: {}", e) })?;

        let sub = claims.get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing sub claim".to_string() })?;

        // Decode signature bytes.
        let signature_bytes = decode_jwt_part(signature)?;

        // Step 2 — Look up the per-user public key.
        // Mask key-lookup errors with a generic message (prevent user enumeration).
        let public_key_pem = self.key_provider.get_public_key(sub).await
            .map_err(|_| AuthError::TokenInvalid {
                reason: "invalid token".to_string(),
            })?;

        let public_key = PKey::public_key_from_pem(public_key_pem.as_bytes())
            .map_err(|_| AuthError::TokenInvalid {
                reason: "invalid token".to_string(),
            })?;

        // Step 3 — Verify the cryptographic signature.
        verify_jwt_signature(alg, header, payload, &signature_bytes, &public_key)
            .map_err(|_| AuthError::TokenInvalid {
                reason: "invalid token".to_string(),
            })?;

        // Step 4 — Signature is trusted. Now validate claims.
        let iss = claims.get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing iss claim".to_string() })?
            .to_string();

        if iss != self.config.issuer {
            return Err(AuthError::TokenInvalid {
                reason: format!("issuer mismatch: expected '{}'", self.config.issuer),
            });
        }

        let exp = claims.get("exp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing exp claim".to_string() })?;

        let now = Utc::now().timestamp();
        if exp < now {
            return Err(AuthError::TokenExpired);
        }

        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
            if now < nbf {
                return Err(AuthError::TokenNotYetValid);
            }
        }

        let role = claims.get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(BearerContext {
            iss,
            sub: sub.to_string(),
            role,
            claims,
            token_type: TokenType::Bearer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Once;

    static INIT: Once = Once::new();
    static mut TEST_KEY_PATH: Option<String> = None;

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

    const VALID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5LCJhdWQiOiJyYnMifQ.WuO6Qi6EoKFWIlKV6omSzrExq_qOmAmWwIAvNGlfLANt0L5aYH9Q6RXJGNWtDAJTzCp8s8VEMXsMxl_UaUol8jHqSjZ3_n6Tm4cwTuKk5mkd2CjNVKlYBelt3d1pOc9z3phWDgz0FAt-kQrryxpzOvjfBBt4iXPddNou3xpt76foaimkFwwDGgBB2ocHrbsvUCDyr_dLNuP7pT5JPLt4d8ErONS_CLh3eqghOvWzAPpkPsHiXZ9fSYGBkiZX__iRdNGJaIlu0Z5OaOPBwPaZwyTwpZF_DA7dCvbrDE_IlVhHRKmFNl9JDUsh2A-zofdFJ4zuAxYDg-KfQoKwE-zKdA";
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

    fn create_verifier() -> JwtVerifier {
        let config = JwtVerificationConfig {
            public_key_path: None,
            jwks_file: None,
            issuer: "https://auth.example.com".to_string(),
        };
        let key_provider = Arc::new(StubKeyProvider(TEST_PUBLIC_KEY_PEM.to_string()));
        JwtVerifier::new(config, key_provider)
    }

    #[tokio::test]
    async fn test_jwt_valid_token() {
        let verifier = create_verifier();
        let result = verifier.verify(VALID_TOKEN).await;
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.iss, "https://auth.example.com");
        assert_eq!(ctx.sub, "user123");
        assert_eq!(ctx.role, "admin");
    }

    #[tokio::test]
    async fn test_jwt_malformed_format() {
        let verifier = create_verifier();
        let result = verifier.verify(MALFORMED_TOKEN).await;
        assert!(result.is_err());
    }
}

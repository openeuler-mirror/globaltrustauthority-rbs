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
//!
//! Account lockout is enforced via [`LockoutTracker`]: if a user
//! accumulates `MAX_FAILED_ATTEMPTS` consecutive failures, the account
//! is locked for `LOCK_DURATION`. A successful authentication resets
//! the failure counter.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use josekit::jws::ES512;
use josekit::jwt::{self, JwtPayloadValidator};
use jsonwebtoken::{decode, Validation};
use log::{debug, warn};
use rbs_api_types::config::BearerTokenVerificationConfig;
use serde_json::Value;

use crate::auth::authn::common::{
    create_decoding_key, decode_token_header, is_es512, to_jsonwebtoken_alg, validate_algorithm,
};
use crate::auth::authn::{LockoutTracker, TokenVerifier, UserKeyProvider};
use crate::auth::context::{BearerContext, TokenType};
use crate::auth::error::AuthError;

/// Bearer token verifier.
#[derive(Clone)]
pub struct BearerTokenVerifier {
    config: BearerTokenVerificationConfig,
    key_provider: Arc<dyn UserKeyProvider>,
    lockout_tracker: Arc<LockoutTracker>,
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
    pub fn new(
        config: BearerTokenVerificationConfig,
        key_provider: Arc<dyn UserKeyProvider>,
        lockout_tracker: Arc<LockoutTracker>,
    ) -> Self {
        Self { config, key_provider, lockout_tracker }
    }
}

#[async_trait]
impl TokenVerifier for BearerTokenVerifier {
    type Context = BearerContext;

    async fn verify(&self, token: &str) -> Result<BearerContext, AuthError> {
        // Periodically clean up expired lockout entries to prevent unbounded memory growth.
        self.lockout_tracker.cleanup_expired();

        // Step 1 — Parse header to get algorithm.
        let header = decode_token_header(token)?;
        validate_algorithm(&header.alg)?;

        // Step 2 — Extract sub from unverified payload for key lookup.
        let sub = extract_sub_from_payload(token)?;

        // Step 3 — Check if the account is currently locked out.
        if self.lockout_tracker.is_locked(&sub) {
            warn!("BearerToken authentication rejected: account locked for sub '{}'", sub);
            return Err(AuthError::AccountLocked);
        }

        // Step 4 — Look up the per-user public key.
        // If the user does not exist, we do NOT record a failure for lockout
        // tracking — only real (existing) users accumulate failure counts.
        let public_key_pem = self
            .key_provider
            .get_public_key(&sub)
            .await
            .map_err(|e| {
                warn!("BearerToken key lookup failed for sub '{}': {}", sub, e);
                AuthError::TokenInvalid {
                    reason: "invalid token".to_string(),
                }
            })?;

        // Step 5 — Branch: ES512 goes through josekit; everything else through jsonwebtoken.
        let result = if is_es512(&header.alg) {
            self.verify_es512(token, &sub, &public_key_pem).await
        } else {
            self.verify_jsonwebtoken(token, &sub, &header.alg, &public_key_pem)
                .await
        };

        // Step 6 — Record success or failure for lockout tracking.
        // Only record for real users (those whose key lookup succeeded in Step 4).
        match result {
            Ok(ctx) => {
                self.lockout_tracker.record_success(&sub);
                Ok(ctx)
            }
            Err(e) => {
                self.lockout_tracker.record_failure(&sub);
                Err(e)
            }
        }
    }
}

impl BearerTokenVerifier {
    /// ES512 verification using josekit.
    async fn verify_es512(
        &self,
        token: &str,
        sub: &str,
        public_key_pem: &str,
    ) -> Result<BearerContext, AuthError> {
        let verifier = ES512
            .verifier_from_pem(public_key_pem.as_bytes())
            .map_err(|e| {
                warn!("BearerToken ES512 verifier creation failed: {}", e);
                AuthError::TokenInvalid {
                    reason: "invalid token".to_string(),
                }
            })?;

        let (payload, _header) =
            jwt::decode_with_verifier(token, &verifier).map_err(|e| {
                use josekit::JoseError;
                match &e {
                    JoseError::InvalidSignature(_) => {
                        warn!("BearerToken ES512 signature verification failed");
                        AuthError::TokenInvalid {
                            reason: "invalid token".to_string(),
                        }
                    }
                    _ => {
                        warn!("BearerToken ES512 verification failed: {}", e);
                        AuthError::TokenInvalid {
                            reason: "invalid token".to_string(),
                        }
                    }
                }
            })?;

        // Validate claims
        let mut validator = JwtPayloadValidator::new();
        validator.set_issuer(&self.config.issuer);
        validator.set_audience(&self.config.audience);

        validator.validate(&payload).map_err(|e| {
            use josekit::JoseError;
            match &e {
                JoseError::InvalidSignature(_) => {
                    warn!("BearerToken ES512 claim validation: invalid signature");
                    AuthError::TokenInvalid {
                        reason: "invalid token".to_string(),
                    }
                }
                _ => {
                    warn!("BearerToken ES512 claim validation failed: {}", e);
                    AuthError::TokenInvalid {
                        reason: "invalid token".to_string(),
                    }
                }
            }
        })?;

        // Require exp claim — josekit JwtPayloadValidator only validates exp if present,
        // but does not reject tokens that lack it. Explicitly reject to match jsonwebtoken
        // path which requires exp via set_required_spec_claims.
        if payload.expires_at().is_none() {
            warn!("BearerToken ES512 rejected: missing exp claim");
            return Err(AuthError::TokenInvalid {
                reason: "missing exp claim".to_string(),
            });
        }

        // Extract claims (signature is trusted at this point).
        let iss = payload
            .issuer()
            .map(|s| s.to_string())
            .unwrap_or_default();

        let role = payload
            .claim("role")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let claims: Value = {
            let map = payload.claims_set().clone();
            serde_json::to_value(map).map_err(|_| AuthError::TokenInvalid {
                reason: "invalid token".to_string(),
            })?
        };

        Ok(BearerContext {
            iss,
            sub: sub.to_string(),
            role,
            claims,
            token_type: TokenType::Bearer,
        })
    }

    /// Jsonwebtoken-based verification (non-ES512 algorithms).
    async fn verify_jsonwebtoken(
        &self,
        token: &str,
        sub: &str,
        alg_str: &str,
        public_key_pem: &str,
    ) -> Result<BearerContext, AuthError> {
        let decoding_key =
            create_decoding_key(alg_str, public_key_pem.as_bytes()).map_err(|e| {
                warn!("BearerToken decoding key creation failed: {}", e);
                AuthError::TokenInvalid {
                    reason: "invalid token".to_string(),
                }
            })?;

        let jws_alg = to_jsonwebtoken_alg(alg_str).map_err(|e| {
            debug!("BearerToken unsupported algorithm '{}': {}", alg_str, e);
            AuthError::TokenInvalid {
                reason: "invalid token".to_string(),
            }
        })?;

        let mut validation = Validation::new(jws_alg);
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let token_data = decode::<Value>(token, &decoding_key, &validation).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                ErrorKind::ImmatureSignature => AuthError::TokenNotYetValid,
                _ => {
                    warn!("BearerToken jsonwebtoken verification failed: {}", e);
                    AuthError::TokenInvalid {
                        reason: "invalid token".to_string(),
                    }
                }
            }
        })?;

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
            sub: sub.to_string(),
            role,
            claims: token_data.claims,
            token_type: TokenType::Bearer,
        })
    }
}

/// Extract the `sub` claim from JWT payload without signature verification.
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

    /// Generate a fresh RSA public key PEM for each test.
    fn generate_test_public_key_pem() -> String {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        String::from_utf8(pkey.public_key_to_pem().unwrap()).unwrap()
    }

    const MALFORMED_TOKEN: &str = "not.a.valid.jwt.token";

    #[derive(Debug)]
    struct StubKeyProvider(String);

    #[async_trait]
    impl UserKeyProvider for StubKeyProvider {
        async fn get_public_key(&self, _sub: &str) -> Result<String, AuthError> {
            Ok(self.0.clone())
        }
    }

    fn create_verifier() -> BearerTokenVerifier {
        let pem = generate_test_public_key_pem();
        let config = BearerTokenVerificationConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "globaltrustauthority-rbs".to_string(),
        };
        let key_provider = Arc::new(StubKeyProvider(pem));
        let lockout_tracker = Arc::new(LockoutTracker::new());
        BearerTokenVerifier::new(config, key_provider, lockout_tracker)
    }

    #[tokio::test]
    async fn test_bearer_token_malformed_format() {
        let verifier = create_verifier();
        let result = verifier.verify(MALFORMED_TOKEN).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_supported_algorithms_from_common() {
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS256"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS384"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"PS512"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"ES256"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"ES384"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"ES512"));
        assert!(SUPPORTED_ALGORITHMS.contains(&"EdDSA"));
    }

    #[test]
    fn test_extract_sub_valid_payload() {
        let token = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoidGVzdCJ9.signature";
        let result = extract_sub_from_payload(token);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "user123");
    }

    #[test]
    fn test_extract_sub_missing_sub() {
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

    #[tokio::test]
    async fn test_bearer_token_lockout_after_failures() {
        let tracker = Arc::new(LockoutTracker::new());
        let pem = generate_test_public_key_pem();
        let config = BearerTokenVerificationConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "globaltrustauthority-rbs".to_string(),
        };
        let key_provider = Arc::new(StubKeyProvider(pem));
        let verifier = BearerTokenVerifier::new(config, key_provider, Arc::clone(&tracker));

        // Malformed tokens still trigger failure recording because the sub
        // extraction fails before the lockout check.
        let result = verifier.verify(MALFORMED_TOKEN).await;
        assert!(result.is_err());

        // Simulate 5 failures by calling record_failure directly (since
        // verify() won't reach record_failure for a malformed token —
        // the failure happens at Step 1/2 before the lockout check).
        // Use a sub that exists in the StubKeyProvider (it returns a key for any sub).
        for _ in 0..5 {
            tracker.record_failure("user123");
        }
        assert!(tracker.is_locked("user123"));

        // Now verify should return AccountLocked for this user.
        // Create a token with sub "user123" that would otherwise fail signature
        // verification, but the lockout check should kick in first.
        let token_with_sub = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoidGVzdCJ9.signature";
        let result = verifier.verify(token_with_sub).await;
        assert!(result.is_err());
        // The lockout check happens before key lookup and signature verification,
        // so we should get AccountLocked.
        match result.unwrap_err() {
            AuthError::AccountLocked => {},
            other => panic!("Expected AccountLocked, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_bearer_token_success_clears_lockout() {
        let tracker = Arc::new(LockoutTracker::new());
        tracker.record_failure("user123");
        tracker.record_failure("user123");

        // Simulate a success clearing the counter.
        tracker.record_success("user123");
        assert!(!tracker.is_locked("user123"));
    }

    /// A key provider that returns errors for certain subs (simulating non-existent users)
    /// and a valid PEM for all others (simulating existing users).
    #[derive(Debug)]
    struct SelectiveStubKeyProvider {
        pem: String,
        nonexistent_subs: Vec<String>,
    }

    #[async_trait]
    impl UserKeyProvider for SelectiveStubKeyProvider {
        async fn get_public_key(&self, sub: &str) -> Result<String, AuthError> {
            if self.nonexistent_subs.contains(&sub.to_string()) {
                Err(AuthError::TokenInvalid { reason: "user not found".to_string() })
            } else {
                Ok(self.pem.clone())
            }
        }
    }

    /// When the sub does not exist in the key provider (user not found),
    /// verify() should return TokenInvalid but NOT record a failure in the
    /// lockout tracker. This is the core security boundary: only real (existing)
    /// users accumulate failure counts.
    #[tokio::test]
    async fn test_nonexistent_sub_does_not_count_failure() {
        let tracker = Arc::new(LockoutTracker::new());
        let pem = generate_test_public_key_pem();
        let config = BearerTokenVerificationConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "globaltrustauthority-rbs".to_string(),
        };
        let key_provider = Arc::new(SelectiveStubKeyProvider {
            pem,
            nonexistent_subs: vec!["ghost_user".to_string()],
        });
        let verifier = BearerTokenVerifier::new(config, key_provider, Arc::clone(&tracker));

        // Token with a sub that does not exist in the key provider.
        let token = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJnb2hvc3RfdXNlciIsImlzcyI6InRlc3QifQ.signature";

        // Call verify 5 times with the non-existent sub.
        for _ in 0..5 {
            let result = verifier.verify(token).await;
            assert!(result.is_err());
        }

        // The ghost_user should NOT have any entry in the tracker —
        // failure counting skipped because key_provider.get_public_key() failed.
        assert!(!tracker.is_locked("ghost_user"));
        assert!(!tracker.has_entry("ghost_user"),
            "non-existent sub should not have a lockout entry");
    }

    /// Verify that an existing user's failure IS counted when key lookup succeeds
    /// but signature verification fails.
    #[tokio::test]
    async fn test_existing_sub_counts_failure_on_signature_mismatch() {
        let tracker = Arc::new(LockoutTracker::new());
        let pem = generate_test_public_key_pem();
        let config = BearerTokenVerificationConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "globaltrustauthority-rbs".to_string(),
        };
        let key_provider = Arc::new(StubKeyProvider(pem));
        let verifier = BearerTokenVerifier::new(config, key_provider, Arc::clone(&tracker));

        // Token with a real sub but invalid signature — key lookup succeeds,
        // signature verification fails, so record_failure should be called.
        let token = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJyZWFsX3VzZXIiLCJpc3MiOiJ0ZXN0In0.signature";

        for _ in 0..5 {
            let result = verifier.verify(token).await;
            assert!(result.is_err());
        }

        // The real_user should now be locked out.
        assert!(tracker.is_locked("real_user"));
        assert_eq!(tracker.get_failed_count("real_user"), 5);
    }

    /// End-to-end test: verify() succeeds on a valid JWT, and record_success
    /// is called on the lockout tracker, clearing any previous failure count.
    ///
    /// We generate an RSA key pair, sign a PS256 JWT with the private key,
    /// and have the StubKeyProvider return the matching public key PEM.
    /// Before verification, we accumulate 2 failures for the same sub,
    /// then verify() succeeds and the tracker entry should be gone.
    #[tokio::test]
    async fn test_verify_success_calls_record_success_end_to_end() {
        let tracker = Arc::new(LockoutTracker::new());

        // Generate RSA key pair for PS256.
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        let pub_pem = String::from_utf8(pkey.public_key_to_pem().unwrap()).unwrap();
        let priv_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();

        let config = BearerTokenVerificationConfig {
            issuer: "rbs-cli".to_string(),
            audience: "globaltrustauthority-rbs".to_string(),
        };
        let key_provider = Arc::new(StubKeyProvider(pub_pem));
        let verifier = BearerTokenVerifier::new(config.clone(), key_provider, Arc::clone(&tracker));

        // Pre-populate 2 failures for the sub we'll verify as "testuser".
        tracker.record_failure("testuser");
        tracker.record_failure("testuser");
        assert_eq!(tracker.get_failed_count("testuser"), 2);

        // Sign a valid PS256 JWT.
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "sub": "testuser",
            "iss": "rbs-cli",
            "aud": "globaltrustauthority-rbs",
            "exp": now + 3600,
            "role": "admin",
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

        // verify() should succeed.
        let result = verifier.verify(&token).await;
        assert!(result.is_ok(), "valid JWT should verify successfully");

        // After successful verification, record_success should have cleared
        // the tracker entry for "testuser".
        assert!(!tracker.has_entry("testuser"),
            "successful verify() should clear lockout counter via record_success");
        assert!(!tracker.is_locked("testuser"));
    }
}

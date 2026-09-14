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
use openssl::pkey::PKey;
use rbs_api_types::config::BearerTokenVerificationConfig;
use serde_json::Value;

use crate::auth::authn::common::{
    create_decoding_key, decode_token_header, is_es512, is_sm2, to_jsonwebtoken_alg,
    validate_algorithm, validate_jwt_claims, validate_josekit_exp,
};
use crate::auth::authn::sm2;
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

        // Step 5 — Branch: SM2 goes through OpenSSL; ES512 through josekit; everything else
        // through jsonwebtoken. SM2 and ES512 are library-unsupported (or josekit-specific) and
        // bypass the jsonwebtoken DecodingKey path.
        let result = if is_sm2(&header.alg) {
            self.verify_sm2(token, &sub, &public_key_pem).await
        } else if is_es512(&header.alg) {
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

        // Validate exp explicitly (see `validate_josekit_exp`), then the remaining
        // claims (iss, aud, nbf, iat) with the same pinned clock read.
        let now = validate_josekit_exp("BearerToken", &payload)?;

        let mut validator = JwtPayloadValidator::new();
        validator.set_base_time(now);
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

    /// SM2 verification using OpenSSL (SM2 ECDSA over the SM3 digest).
    ///
    /// Neither `jsonwebtoken` nor `josekit` supports SM2, so this path verifies the
    /// compact JWS signature directly with the vendored OpenSSL backend and parses
    /// claims manually. All errors collapse to `TokenInvalid { reason: "invalid token" }`
    /// (and `TokenExpired` for expired tokens) to match the user-enumeration-safe
    /// behavior of the ES512 path.
    async fn verify_sm2(
        &self,
        token: &str,
        sub: &str,
        public_key_pem: &str,
    ) -> Result<BearerContext, AuthError> {
        // Split compact JWS: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::TokenInvalid { reason: "invalid token".to_string() });
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| {
                warn!("BearerToken SM2 signature decode failed: {}", e);
                AuthError::TokenInvalid { reason: "invalid token".to_string() }
            })?;

        // Verify the SM2 signature (SM3 digest) with the per-user public key,
        // pinning the standard (GM/T 0009) user ID; see `authn::sm2` for why
        // the plain Verifier path is not usable.
        let pkey = PKey::public_key_from_pem(public_key_pem.as_bytes()).map_err(|e| {
            warn!("BearerToken SM2 public key parse failed: {}", e);
            AuthError::TokenInvalid { reason: "invalid token".to_string() }
        })?;
        let valid = sm2::verify(&pkey, signing_input.as_bytes(), &signature).map_err(|e| {
            warn!("BearerToken SM2 verify failed: {}", e);
            AuthError::TokenInvalid { reason: "invalid token".to_string() }
        })?;
        if !valid {
            warn!("BearerToken SM2 signature verification failed");
            return Err(AuthError::TokenInvalid { reason: "invalid token".to_string() });
        }

        // Signature trusted — parse and validate claims manually.
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| AuthError::TokenInvalid { reason: "invalid token".to_string() })?;
        let claims: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|_| AuthError::TokenInvalid { reason: "invalid token".to_string() })?;

        validate_jwt_claims(&claims, &self.config.issuer, Some(&self.config.audience))?;

        let iss = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let role = claims
            .get("role")
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
    use josekit::jws::{JwsHeader, ES512};
    use josekit::jwt::{self, JwtPayload};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use std::time::{Duration, SystemTime};

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

    /// Generate an EC P-521 key pair for ES512 tests.
    /// Returns (public_pem, private_pem).
    fn generate_test_es512_key_pair() -> (String, String) {
        let group = EcGroup::from_curve_name(Nid::SECP521R1).expect("P-521 group");
        let ec = EcKey::generate(&group).expect("generate EC key");
        let pkey = PKey::from_ec_key(ec).expect("PKey from EC");
        let pub_pem = String::from_utf8(pkey.public_key_to_pem().expect("pub pem")).unwrap();
        let priv_pem = String::from_utf8(
            pkey.private_key_to_pem_pkcs8().expect("priv pem"),
        )
        .unwrap();
        (pub_pem, priv_pem)
    }

    /// Build an ES512-signed JWT with the given expiry (None = no exp claim).
    /// Sets iss/aud/sub to match the verifier config used in tests.
    fn sign_es512_token(priv_pem: &str, exp: Option<SystemTime>) -> String {
        let mut payload = JwtPayload::new();
        payload.set_issuer("https://auth.example.com");
        payload.set_subject("es512-user");
        payload.set_audience(vec!["globaltrustauthority-rbs"]);
        if let Some(t) = exp {
            payload.set_expires_at(&t);
        }

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm("ES512");

        let signer = ES512.signer_from_pem(priv_pem.as_bytes()).expect("signer");
        jwt::encode_with_signer(&payload, &header, &signer).expect("encode jwt")
    }

    fn es512_verifier(pub_pem: &str) -> BearerTokenVerifier {
        let config = BearerTokenVerificationConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "globaltrustauthority-rbs".to_string(),
        };
        let key_provider = Arc::new(StubKeyProvider(pub_pem.to_string()));
        let lockout_tracker = Arc::new(LockoutTracker::new());
        BearerTokenVerifier::new(config, key_provider, lockout_tracker)
    }

    /// An expired ES512 token must return AuthError::TokenExpired (not the
    /// generic TokenInvalid). This is the regression test for the ES512
    /// expiry-error-type fix.
    #[tokio::test]
    async fn test_es512_expired_returns_token_expired() {
        let (pub_pem, priv_pem) = generate_test_es512_key_pair();
        let verifier = es512_verifier(&pub_pem);

        // exp in the past.
        let exp = SystemTime::now() - Duration::from_secs(3600);
        let token = sign_es512_token(&priv_pem, Some(exp));

        let result = verifier.verify(&token).await;
        assert!(result.is_err(), "expired ES512 token must be rejected");
        match result.unwrap_err() {
            AuthError::TokenExpired => {}
            other => panic!("expected TokenExpired, got: {:?}", other),
        }
    }

    /// An ES512 token without an exp claim must be rejected (TokenInvalid,
    /// "missing exp claim"). Ensures the explicit missing-exp guard still
    /// works after reordering the exp check before josekit's validate().
    #[tokio::test]
    async fn test_es512_missing_exp_rejected() {
        let (pub_pem, priv_pem) = generate_test_es512_key_pair();
        let verifier = es512_verifier(&pub_pem);

        let token = sign_es512_token(&priv_pem, None);

        let result = verifier.verify(&token).await;
        assert!(result.is_err(), "ES512 token without exp must be rejected");
        match result.unwrap_err() {
            AuthError::TokenInvalid { reason } => {
                assert!(
                    reason.contains("exp"),
                    "reason should mention exp, got: {}",
                    reason
                );
            }
            other => panic!("expected TokenInvalid, got: {:?}", other),
        }
    }

    /// A valid ES512 token (correct signature, iss/aud, non-expired exp)
    /// verifies successfully. Regression guard for the happy path after
    /// reordering exp validation before josekit's claim validation.
    #[tokio::test]
    async fn test_es512_valid_token_succeeds() {
        let (pub_pem, priv_pem) = generate_test_es512_key_pair();
        let verifier = es512_verifier(&pub_pem);

        let exp = SystemTime::now() + Duration::from_secs(3600);
        let token = sign_es512_token(&priv_pem, Some(exp));

        let result = verifier.verify(&token).await;
        assert!(result.is_ok(), "valid ES512 token should verify: {:?}", result.err());
        let ctx = result.unwrap();
        assert_eq!(ctx.sub, "es512-user");
        assert_eq!(ctx.token_type, TokenType::Bearer);
    }

    // ── SM2 tests ──

    /// Generate an SM2 key pair for tests. Returns (public_pem, private_pem).
    ///
    /// SM2 keys are generated as EC keys on the SM2 curve (`Nid::SM2`) and wrapped
    /// in a `PKey`; OpenSSL derives the SM2 algorithm context from the curve.
    fn generate_test_sm2_key_pair() -> (String, String) {
        use openssl::ec::{EcGroup, EcKey};
        let group = EcGroup::from_curve_name(Nid::SM2).expect("SM2 group");
        let ec = EcKey::generate(&group).expect("generate SM2 EC key");
        let pkey = PKey::from_ec_key(ec).expect("PKey from SM2 EC key");
        let pub_pem = String::from_utf8(pkey.public_key_to_pem().expect("pub pem")).unwrap();
        let priv_pem =
            String::from_utf8(pkey.private_key_to_pem_pkcs8().expect("priv pem")).unwrap();
        (pub_pem, priv_pem)
    }

    /// Build an SM2-signed compact JWS (alg "SM2") with claims matching the verifier
    /// config used in tests. `exp` overrides the expiry; `None` defaults to now+3600.
    fn sign_sm2_token(
        priv_pem: &str,
        exp: Option<SystemTime>,
        iss: &str,
        aud: &str,
        sub: &str,
    ) -> String {
        sign_sm2_token_with_id(priv_pem, exp, iss, aud, sub, sm2::SM2_USER_ID)
    }

    /// Like [`sign_sm2_token`] but with an explicit SM2 user ID, used to prove
    /// that non-standard IDs are rejected.
    fn sign_sm2_token_with_id(
        priv_pem: &str,
        exp: Option<SystemTime>,
        iss: &str,
        aud: &str,
        sub: &str,
        user_id: &[u8],
    ) -> String {
        let pkey = PKey::private_key_from_pem(priv_pem.as_bytes()).expect("load SM2 priv key");
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp_val = match exp {
            Some(t) => t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            None => now + 3600,
        };
        let header = serde_json::json!({ "alg": "SM2", "typ": "JWT" });
        let payload = serde_json::json!({
            "iss": iss, "sub": sub, "aud": aud, "exp": exp_val, "role": "admin",
        });
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = sm2::sign_with_id(&pkey, signing_input.as_bytes(), user_id).expect("SM2 sign");
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig);
        format!("{}.{}", signing_input, sig_b64)
    }

    fn sm2_verifier(pub_pem: &str) -> BearerTokenVerifier {
        let config = BearerTokenVerificationConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "globaltrustauthority-rbs".to_string(),
        };
        let key_provider = Arc::new(StubKeyProvider(pub_pem.to_string()));
        let lockout_tracker = Arc::new(LockoutTracker::new());
        BearerTokenVerifier::new(config, key_provider, lockout_tracker)
    }

    /// A valid SM2 token verifies successfully and the lockout counter is cleared.
    #[tokio::test]
    async fn test_sm2_valid_token_succeeds() {
        let (pub_pem, priv_pem) = generate_test_sm2_key_pair();
        let verifier = sm2_verifier(&pub_pem);

        let exp = SystemTime::now() + Duration::from_secs(3600);
        let token = sign_sm2_token(
            &priv_pem,
            Some(exp),
            "https://auth.example.com",
            "globaltrustauthority-rbs",
            "sm2-user",
        );

        let result = verifier.verify(&token).await;
        assert!(result.is_ok(), "valid SM2 token should verify: {:?}", result.err());
        let ctx = result.unwrap();
        assert_eq!(ctx.sub, "sm2-user");
        assert_eq!(ctx.role, "admin");
        assert_eq!(ctx.token_type, TokenType::Bearer);
    }

    /// An expired SM2 token returns AuthError::TokenExpired.
    #[tokio::test]
    async fn test_sm2_expired_returns_token_expired() {
        let (pub_pem, priv_pem) = generate_test_sm2_key_pair();
        let verifier = sm2_verifier(&pub_pem);

        let exp = SystemTime::now() - Duration::from_secs(3600);
        let token = sign_sm2_token(
            &priv_pem,
            Some(exp),
            "https://auth.example.com",
            "globaltrustauthority-rbs",
            "sm2-user",
        );

        let result = verifier.verify(&token).await;
        assert!(result.is_err(), "expired SM2 token must be rejected");
        match result.unwrap_err() {
            AuthError::TokenExpired => {}
            other => panic!("expected TokenExpired, got: {:?}", other),
        }
    }

    /// A token signed by a different key (signature mismatch) is rejected as
    /// TokenInvalid, and the failure is recorded for lockout tracking.
    #[tokio::test]
    async fn test_sm2_invalid_signature_rejected() {
        let (pub_pem, _priv_pem) = generate_test_sm2_key_pair();
        let (other_pub, other_priv) = generate_test_sm2_key_pair();
        let tracker = Arc::new(LockoutTracker::new());
        let config = BearerTokenVerificationConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "globaltrustauthority-rbs".to_string(),
        };
        let key_provider = Arc::new(StubKeyProvider(pub_pem));
        let verifier = BearerTokenVerifier::new(config, key_provider, Arc::clone(&tracker));

        // Sign with `other_priv` but the verifier holds `pub_pem` (mismatch).
        let exp = SystemTime::now() + Duration::from_secs(3600);
        let token = sign_sm2_token(
            &other_priv,
            Some(exp),
            "https://auth.example.com",
            "globaltrustauthority-rbs",
            "sm2-user",
        );
        let _ = &other_pub;

        let result = verifier.verify(&token).await;
        assert!(result.is_err(), "SM2 token with wrong signature must be rejected");
        match result.unwrap_err() {
            AuthError::TokenInvalid { .. } => {}
            other => panic!("expected TokenInvalid, got: {:?}", other),
        }
        assert!(tracker.has_entry("sm2-user"));
    }

    /// An SM2 token whose header alg is "SM2" but with a tampered payload must fail
    /// signature verification (covers the manual JWS reassembly path).
    #[tokio::test]
    async fn test_sm2_tampered_payload_rejected() {
        let (pub_pem, priv_pem) = generate_test_sm2_key_pair();
        let verifier = sm2_verifier(&pub_pem);

        let exp = SystemTime::now() + Duration::from_secs(3600);
        let token = sign_sm2_token(
            &priv_pem,
            Some(exp),
            "https://auth.example.com",
            "globaltrustauthority-rbs",
            "sm2-user",
        );
        // Flip the last character of the payload segment to break the signature binding.
        let mut parts: Vec<&str> = token.split('.').collect();
        let mut payload_bytes = parts[1].as_bytes().to_vec();
        let last = payload_bytes.pop().unwrap();
        payload_bytes.push(if last == b'A' { b'B' } else { b'A' });
        parts[1] = std::str::from_utf8(&payload_bytes).unwrap();
        let tampered = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

        let result = verifier.verify(&tampered).await;
        assert!(result.is_err(), "tampered SM2 token must be rejected");
        match result.unwrap_err() {
            AuthError::TokenInvalid { .. } => {}
            other => panic!("expected TokenInvalid, got: {:?}", other),
        }
    }

    /// SM2 tokens signed with a non-standard user ID are rejected: verification
    /// pins the GM/T 0009 default ID, so signatures from implementations using
    /// any other ID (including the empty ID that OpenSSL >= 3.5 defaults to)
    /// fail closed.
    #[tokio::test]
    async fn test_sm2_non_standard_user_id_rejected() {
        let (pub_pem, priv_pem) = generate_test_sm2_key_pair();

        for wrong_id in [b"" as &[u8], b"rbs"] {
            let verifier = sm2_verifier(&pub_pem);
            let exp = SystemTime::now() + Duration::from_secs(3600);
            let token = sign_sm2_token_with_id(
                &priv_pem,
                Some(exp),
                "https://auth.example.com",
                "globaltrustauthority-rbs",
                "sm2-user",
                wrong_id,
            );

            let result = verifier.verify(&token).await;
            assert!(result.is_err(), "SM2 token with user ID {wrong_id:?} must be rejected");
            match result.unwrap_err() {
                AuthError::TokenInvalid { .. } => {}
                other => panic!("expected TokenInvalid, got: {:?}", other),
            }
        }
    }
}

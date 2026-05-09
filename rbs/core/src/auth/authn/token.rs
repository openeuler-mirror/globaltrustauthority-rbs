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
use jsonwebtoken::{decode, DecodingKey, Validation};
use openssl::pkey::PKey;
use rbs_api_types::config::AttestTokenVerificationConfig;
use serde_json::Value;
use std::fs;

use crate::auth::authn::common::{
    create_decoding_key, decode_token_header, map_jwt_error, validate_algorithm,
};
use crate::auth::authn::jwks::{self, Jwks};
use crate::auth::authn::TokenVerifier;
use crate::auth::context::{AttestContext, TokenType};
use crate::auth::error::AuthError;

/// AttestToken verifier
pub struct AttestTokenVerifier {
    config: AttestTokenVerificationConfig,
    decoding_key: Option<DecodingKey>,
    jwks: Option<Jwks>,
}

impl std::fmt::Debug for AttestTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestTokenVerifier")
            .field("config", &self.config)
            .field("jwks", &self.jwks)
            .finish()
    }
}

impl Clone for AttestTokenVerifier {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            decoding_key: self.decoding_key.clone(),
            jwks: self.jwks.clone(),
        }
    }
}

impl AttestTokenVerifier {
    /// Create a new AttestTokenVerifier from config
    pub fn new(config: AttestTokenVerificationConfig) -> Result<Self, AuthError> {
        if let Some(ref path) = config.public_key_path {
            let public_key_pem = fs::read(path).map_err(|e| AuthError::TokenInvalid {
                reason: format!("failed to read AttestToken public key file '{}': {}", path, e),
            })?;
            let decoding_key = create_decoding_key_for_pem(&public_key_pem)?;
            Ok(Self {
                config,
                decoding_key: Some(decoding_key),
                jwks: None,
            })
        } else if let Some(ref path) = config.jwks_file {
            let jwks_content = fs::read_to_string(path).map_err(|e| AuthError::TokenInvalid {
                reason: format!("failed to read JWKS file '{}': {}", path, e),
            })?;
            let jwks = jwks::parse_jwks_file(&jwks_content).map_err(|e| AuthError::TokenInvalid {
                reason: format!("failed to parse JWKS file: {}", e),
            })?;
            Ok(Self {
                config,
                decoding_key: None,
                jwks: Some(jwks),
            })
        } else {
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
        // Decode header to get algorithm and kid
        let header = decode_token_header(token)?;

        // Validate algorithm is supported
        validate_algorithm(&header.alg)?;

        // Get decoding key
        let decoding_key = self.get_decoding_key(header.kid.as_deref(), &header.alg)?;

        // Create validation with the specific algorithm
        let mut validation = Validation::new(header.alg);

        // Set required claims
        validation.set_required_spec_claims(&["exp", "iss"]);

        // Validate issuer
        validation.set_issuer(&[&self.config.issuer]);

        // Validate audience if configured
        if let Some(ref expected_aud) = self.config.audience {
            validation.set_audience(&[expected_aud]);
        }

        // Decode and verify token
        let token_data = decode::<Value>(token, &decoding_key, &validation)
            .map_err(|e| map_jwt_error(&e, Some(&self.config.issuer)))?;

        Ok(AttestContext {
            claims: token_data.claims,
            token_type: TokenType::Attest,
        })
    }
}

impl AttestTokenVerifier {
    fn get_decoding_key(
        &self,
        kid: Option<&str>,
        alg: &jsonwebtoken::Algorithm,
    ) -> Result<DecodingKey, AuthError> {
        // If we have a direct decoding key, use it
        if let Some(ref key) = self.decoding_key {
            return Ok(key.clone());
        }

        // Otherwise, get key from JWKS
        let jwks = self.jwks.as_ref().ok_or_else(|| AuthError::TokenInvalid {
            reason: "no JWKS loaded".to_string(),
        })?;

        let jwk = if let Some(kid) = kid {
            jwks::find_key_by_kid(jwks, kid).ok_or_else(|| AuthError::TokenInvalid {
                reason: format!("key with kid '{}' not found in JWKS", kid),
            })?
        } else {
            jwks.keys.first().ok_or_else(|| AuthError::TokenInvalid {
                reason: "no keys in JWKS".to_string(),
            })?
        };

        // Convert JWK to PEM and then to DecodingKey
        let pem = jwks::jwk_to_pem(jwk)?;
        create_decoding_key(alg, &pem)
    }
}

/// Create a DecodingKey from PEM-encoded public key bytes.
/// Automatically detects whether the key is Ed25519 or RSA.
fn create_decoding_key_for_pem(pem: &[u8]) -> Result<DecodingKey, AuthError> {
    // Try to detect key type using OpenSSL
    let is_ed25519 = PKey::public_key_from_pem(pem)
        .map(|pkey| pkey.id() == openssl::pkey::Id::ED25519)
        .unwrap_or(false);

    if is_ed25519 {
        DecodingKey::from_ed_pem(pem).map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to create EdDSA decoding key: {}", e),
        })
    } else {
        DecodingKey::from_rsa_pem(pem).map_err(|e| AuthError::TokenInvalid {
            reason: format!("failed to create RSA decoding key: {}", e),
        })
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

    const TEST_RSA_PUBLIC_KEY_PEM: &str = concat!(
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

    const MALFORMED_TOKEN: &str = "not.a.valid.token";

    fn setup_test_keys() -> (String, String) {
        INIT.call_once(|| {
            let temp_dir = std::env::temp_dir();

            // RSA key
            let rsa_key_path = temp_dir.join("rbs_test_attest_rsa_pubkey.pem");
            let mut file = std::fs::File::create(&rsa_key_path).expect("Failed to create temp RSA key file");
            file.write_all(TEST_RSA_PUBLIC_KEY_PEM.as_bytes())
                .expect("Failed to write RSA key");
            unsafe {
                TEST_KEY_PATH = Some(rsa_key_path.to_string_lossy().to_string());
            }

            // Ed25519 key
            let ed_key_path = temp_dir.join("rbs_test_attest_ed_pubkey.pem");
            let ed_key = openssl::pkey::PKey::generate_ed25519().unwrap();
            let ed_pem = ed_key.public_key_to_pem().unwrap();
            let mut file2 = std::fs::File::create(&ed_key_path).expect("Failed to create temp Ed key file");
            file2.write_all(&ed_pem).expect("Failed to write Ed key");
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
}

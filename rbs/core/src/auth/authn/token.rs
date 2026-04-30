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

use crate::auth::context::{AttestContext, TokenType};
use crate::auth::error::AuthError;
use crate::auth::authn::jwks::{self, Jwks};
use crate::auth::authn::signature::{decode_jwt_part, verify_jwt_signature};
use chrono::Utc;
use openssl::pkey::{PKey, Public};
use rbs_api_types::config::AttestTokenVerificationConfig;
use serde_json::Value;
use std::fs;

/// AttestToken verifier
#[derive(Debug, Clone)]
pub struct AttestTokenVerifier {
    config: AttestTokenVerificationConfig,
    public_key: Option<PKey<Public>>,
    jwks: Option<Jwks>,
}

impl AttestTokenVerifier {
    /// Create a new AttestTokenVerifier from config
    pub fn new(config: AttestTokenVerificationConfig) -> Result<Self, AuthError> {
        if let Some(ref path) = config.public_key_path {
            let public_key_pem = fs::read(path)
                .map_err(|e| AuthError::TokenInvalid {
                    reason: format!("failed to read AttestToken public key file '{}': {}", path, e)
                })?;
            let public_key = PKey::public_key_from_pem(&public_key_pem)
                .map_err(|e| AuthError::TokenInvalid {
                    reason: format!("failed to parse public key: {}", e)
                })?;
            Ok(Self {
                config,
                public_key: Some(public_key),
                jwks: None,
            })
        } else if let Some(ref path) = config.jwks_file {
            let jwks_content = fs::read_to_string(path)
                .map_err(|e| AuthError::TokenInvalid {
                    reason: format!("failed to read JWKS file '{}': {}", path, e)
                })?;
            let jwks = jwks::parse_jwks_file(&jwks_content)
                .map_err(|e| AuthError::TokenInvalid {
                    reason: format!("failed to parse JWKS file: {}", e)
                })?;
            Ok(Self {
                config,
                public_key: None,
                jwks: Some(jwks),
            })
        } else {
            Err(AuthError::TokenInvalid {
                reason: "JWKS URL is not yet implemented".to_string()
            })
        }
    }

    /// Verify AttestToken and return AttestContext
    pub async fn verify(&self, token: &str) -> Result<AttestContext, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::TokenInvalid { reason: "invalid token format".to_string() });
        }

        let header = parts[0];
        let payload = parts[1];
        let signature = parts[2];

        // Decode header
        let header_bytes = decode_jwt_part(header)?;
        let header_json: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to parse header: {}", e) })?;

        // Get algorithm and kid
        let alg = header_json.get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing alg in header".to_string() })?;
        let kid = header_json.get("kid").and_then(|v| v.as_str()).map(String::from);

        // Decode payload
        let payload_bytes = decode_jwt_part(payload)?;
        let claims: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to parse claims: {}", e) })?;

        // Decode signature
        let signature_bytes = decode_jwt_part(signature)?;

        // Get public key
        let public_key = self.get_public_key(kid.as_deref())?;

        // Verify signature
        verify_jwt_signature(alg, header, payload, &signature_bytes, &public_key)?;

        // Extract standard claims
        let iss = claims.get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing iss claim".to_string() })?
            .to_string();
        let exp = claims.get("exp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing exp claim".to_string() })?;
        let nbf = claims.get("nbf").and_then(|v| v.as_i64());

        // Verify issuer
        if iss != self.config.issuer {
            return Err(AuthError::TokenInvalid { reason: format!("issuer mismatch: expected '{}'", self.config.issuer) });
        }

        // Verify audience if configured
        if let Some(ref expected_aud) = self.config.audience {
            let aud = claims.get("aud")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AuthError::TokenInvalid { reason: "missing aud claim".to_string() })?;
            if aud != *expected_aud {
                return Err(AuthError::TokenInvalid { reason: format!("audience mismatch: expected '{}'", expected_aud) });
            }
        }

        // Verify expiration
        let now = Utc::now().timestamp();
        if exp < now {
            return Err(AuthError::TokenExpired);
        }

        // Verify not before
        if let Some(nbf) = nbf {
            if now < nbf {
                return Err(AuthError::TokenNotYetValid);
            }
        }

        Ok(AttestContext {
            claims,
            token_type: TokenType::Attest,
        })
    }

    fn get_public_key(&self, kid: Option<&str>) -> Result<PKey<Public>, AuthError> {
        if let Some(ref public_key) = self.public_key {
            return Ok(public_key.clone());
        }

        let jwks = self.jwks.as_ref()
            .ok_or_else(|| AuthError::TokenInvalid { reason: "no JWKS loaded".to_string() })?;

        let jwk = if let Some(kid) = kid {
            jwks::find_key_by_kid(jwks, kid)
                .ok_or_else(|| AuthError::TokenInvalid { reason: format!("key with kid '{}' not found in JWKS", kid) })?
        } else {
            jwks.keys.first()
                .ok_or_else(|| AuthError::TokenInvalid { reason: "no keys in JWKS".to_string() })?
        };

        jwks::jwk_to_pkey(jwk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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

    const VALID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJHbG9iYWwgVHJ1c3QgQXV0aG9yaXR5IiwiYXVkIjoicmJzIiwiZXhwIjo5OTk5OTk5OTk5fQ.nfKG4tCyEqzzsauOeQjb2h_X8eVtik9vcqIOq39Hd_ArVJT4vQp9vMZS-34VebOSiOn4EJ20lIQcSZjzh-vkPN2jxPOwZDX_JDJtePEkCUSioQPA0wgOBVQoVF9hu02qZDvrqt5qLe1uYsL46yTYLmSyOjveFz7sMUjwYhUnMmRebnX5ZEO0Cvd6P-eTEwaqRUkrYeJ-XVKxRvfHf6U-PaE9CRhKyHPkaPz2AtOGGk3jUreAzVYWFRqjj2ukl8na0hpcHGwicCMLdwVRrUVSTasMsNLtbpCPB1IJDNLeSFEIZUrGhG_OLSYAwu0KYyZ0xkk-Kfvjk1PBY6ypoFPm6Q";
    const EXPIRED_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJHbG9iYWwgVHJ1c3QgQXV0aG9yaXR5IiwiYXVkIjoicmJzIiwiZXhwIjoxfQ.VrggtRNpZNJ6EXHSQj-f4vTm-xLW6F07HswUUomVIRmdLqZOKRiryzhWX3aXHi2kbWWe61ATwz5tmyWj2VUqAz09h1be_gFEI-mUL6HxGpEtRkAteFDSLLv88-SMj0v2r4v25n8XoVHzlMzvlrHUq0_XPSmt4B3t37HZxxbFGlvRXo-7yZ2TVZOWUUrmM7Tg8rQUYTwNoI6ve9RLQCnPBefh9BNxkvVHxervHRrZjeqdItIM_oaL-ZjT3uHqQdECKMiRwovLCmVQyWz7mVXacRTzz7bxx6tXybUE-EZLtgkEBfxqa7feAIl3cp8HBMleiicdi3mAcmG7Uz_z3fW6-g";
    const WRONG_ISSUER_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJFdmlsIENvcnAiLCJhdWQiOiJyYnMiLCJleHAiOjk5OTk5OTk5OTl9.CRfoVqWwqVDJsYU5TZO-6FdymBjvHPymO5oqHt3JKiLD3iv3ENyIvf6syPcOCH8Sou3MeX_hC_s4vBa2SDM2cUc2aQh2BS6x5_mnDPqREMHnY5cU8DCDvbN2_rQ9i3vIjJgtnBMd-_SLHmMVV-DloYQnCE5SV1PRB6dV8NzF8IvsT16uyNq4U0WBUWurzvqXMHhzhGMe2t6LImXRH20MPpvxL-7c7_asGOL0c53wcZ5F5F8um7r8l088nh6Z8UbHbPQgsPzbQ65VLs1dWjfS56sa84VDdK3Uwv3SBvG7kI2Bv9PS8WRe5Ak_x6lGCscJxBPd9_vkUWSfnQSFeoZ_Eg";
    const INVALID_SIG_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJHbG9iYWwgVHJ1c3QgQXV0aG9yaXR5IiwiYXVkIjoicmJzIiwiZXhwIjo5OTk5OTk5OTk5fQ.KwmPu49IzL8RGMryzOIS_upZYtiLiLY77YVuzbtS41WacCotRJzypRhH8aeEqaOXI0N6nxEeS6Zb_A5imqVs8L4Pl0SBR-Yc1execB_2RYevvwV7ZSBYLtfdRJQrGi70VrGcC1LvG35OZvx0QTiWFKafwxDTB2wU-Evg3qVSFHJ8PQNRbep5pr2Sv_GABq7hpLeMlTDSMcLxSGe7laIJVGldH14YiVviobB-nxJ8ldoBKsL9k3WIlTIpp4tty0GzPhzS4wGfoEeqAAY8FAlXmK8HIOz5VM-Kyvxm241o9zdQnLoSQDa0KsHMLY23P8QDqIicMZnUbq7SEY40M7RTGw";
    const MALFORMED_TOKEN: &str = "not.a.valid.token";

    fn setup_test_key() -> String {
        INIT.call_once(|| {
            let temp_dir = std::env::temp_dir();
            let key_path = temp_dir.join("rbs_test_attest_pubkey.pem");
            let mut file = std::fs::File::create(&key_path).expect("Failed to create temp key file");
            file.write_all(TEST_PUBLIC_KEY_PEM.as_bytes()).expect("Failed to write key");
            unsafe {
                TEST_KEY_PATH = Some(key_path.to_string_lossy().to_string());
            }
        });
        unsafe { TEST_KEY_PATH.clone().unwrap() }
    }

    fn create_verifier() -> AttestTokenVerifier {
        let key_path = setup_test_key();
        let config = AttestTokenVerificationConfig {
            public_key_path: Some(key_path),
            jwks_file: None,
            issuer: "Global Trust Authority".to_string(),
            audience: Some("rbs".to_string()),
        };
        AttestTokenVerifier::new(config).expect("failed to create verifier")
    }

    #[tokio::test]
    async fn test_attest_token_valid() {
        let verifier = create_verifier();
        let result = verifier.verify(VALID_TOKEN).await;
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.token_type, TokenType::Attest);
    }

    #[tokio::test]
    async fn test_attest_token_malformed_format() {
        let verifier = create_verifier();
        let result = verifier.verify(MALFORMED_TOKEN).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_attest_token_expired() {
        let verifier = create_verifier();
        let result = verifier.verify(EXPIRED_TOKEN).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[tokio::test]
    async fn test_attest_token_wrong_issuer() {
        let verifier = create_verifier();
        let result = verifier.verify(WRONG_ISSUER_TOKEN).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_attest_token_invalid_signature() {
        let verifier = create_verifier();
        let result = verifier.verify(INVALID_SIG_TOKEN).await;
        assert!(result.is_err());
    }
}

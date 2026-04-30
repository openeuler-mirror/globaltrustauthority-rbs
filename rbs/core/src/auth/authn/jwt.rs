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

//! JWT verification module.

use crate::auth::context::{BearerContext, TokenType};
use crate::auth::error::AuthError;
use crate::auth::authn::jwks::{self, Jwks};
use crate::auth::authn::signature::{decode_jwt_part, verify_jwt_signature};
use chrono::Utc;
use openssl::pkey::{PKey, Public};
use rbs_api_types::config::JwtVerificationConfig;
use serde_json::Value;
use std::fs;

/// JWT verifier for Bearer tokens
#[derive(Debug, Clone)]
pub struct JwtVerifier {
    config: JwtVerificationConfig,
    /// Public key for verification (used when loading from PEM file)
    public_key: Option<PKey<Public>>,
    /// JWKS for verification (used when loading from JWKS file)
    jwks: Option<Jwks>,
}

impl JwtVerifier {
    /// Create a new JwtVerifier from config
    pub fn new(config: JwtVerificationConfig) -> Result<Self, AuthError> {
        if let Some(ref path) = config.public_key_path {
            let public_key_pem = fs::read(path)
                .map_err(|e| AuthError::TokenInvalid {
                    reason: format!("failed to read public key file '{}': {}", path, e)
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

    /// Verify JWT token and return BearerContext
    pub async fn verify(&self, token: &str) -> Result<BearerContext, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::TokenInvalid { reason: "invalid JWT format".to_string() });
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
        let sub = claims.get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing sub claim".to_string() })?
            .to_string();
        let role = claims.get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let exp = claims.get("exp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing exp claim".to_string() })?;
        let nbf = claims.get("nbf").and_then(|v| v.as_i64());

        // Verify issuer
        if iss != self.config.issuer {
            return Err(AuthError::TokenInvalid { reason: format!("issuer mismatch: expected '{}'", self.config.issuer) });
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

        Ok(BearerContext {
            iss,
            sub,
            role,
            claims,
            token_type: TokenType::Bearer,
        })
    }

    /// Get public key based on configuration mode
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

    const VALID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5LCJhdWQiOiJyYnMifQ.WuO6Qi6EoKFWIlKV6omSzrExq_qOmAmWwIAvNGlfLANt0L5aYH9Q6RXJGNWtDAJTzCp8s8VEMXsMxl_UaUol8jHqSjZ3_n6Tm4cwTuKk5mkd2CjNVKlYBelt3d1pOc9z3phWDgz0FAt-kQrryxpzOvjfBBt4iXPddNou3xpt76foaimkFwwDGgBB2ocHrbsvUCDyr_dLNuP7pT5JPLt4d8ErONS_CLh3eqghOvWzAPpkPsHiXZ9fSYGBkiZX__iRdNGJaIlu0Z5OaOPBwPaZwyTwpZF_DA7dCvbrDE_IlVhHRKmFNl9JDUsh2A-zofdFJ4zuAxYDg-KfQoKwE-zKdA";
    const EXPIRED_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxLCJhdWQiOiJyYnMifQ.pB6G4v-OzYTdu9tay-XnxMsjv6G-7k3YVdVPl4gnfA5HjtAx_KvDdBZCleHC_kNWPfmY9q29ITPz3KuPL4Yav9jyekH80UoM8Ls7kRw_i7ufdTFueydIhxFcdkkYaRj2BWv-Kc0PLtTZ2eokDsVgYHpwYFPN1mMeEx27xJd8vfFKhbnOx2PtObshIhFqKv5q0OLkgcBxvakHJJ8a8_0oUuqZJYsu6rSJOvrTG6PXHBptW2MNIVGp8jlZ69E9ImjHevpb5frR9UaXBPi2kbknihNulWM7YWcoaklF0a4aD_bxRj7KlcT7jz3J0ywuQa1EZMwJyc8uZp_SkhTUxLMbJg";
    const WRONG_ISSUER_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V2aWwuY29tIiwic3ViIjoidXNlcjEyMyIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OSwiYXVkIjoicmJzIn0.bvZ2Krw3O1qy-kfTeRjLnEE5_pChJj9JI6X3Cq1FwAh2ZgGs5k3_kHutN_apeAzDc9hqEEZork4DFQhOrs5GYl0khT44LVjVALmJ5xTjoC-BHrgRsdyoHysM69zkmy4VyZV8lh8TCntYgXgIczYsU4Qxp0_XNrZbqh1fmAzKiusSAgkdxO_bF5puEiAMWxGUUcx1n71PjJ4uug2Lb7A9wSfddxX9u1HFiHhD8GIQpOi82NiLR3hBOjccowfa6IVc2F_vdKhxV7OKefjMmkD0Biib2WlEjfMvhZMezAMrQ8pUdpmsdEmFKXo3Hr54O1-w-K7pXEbHryFH0rmopJuYbQ";
    const INVALID_SIG_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5LCJhdWQiOiJyYnMifQ.KwmPu49IzL8RGMryzOIS_upZYtiLiLY77YVuzbtS41WacCotRJzypRhH8aeEqaOXI0N6nxEeS6Zb_A5imqVs8L4Pl0SBR-Yc1execB_2RYevvwV7ZSBYLtfdRJQrGi70VrGcC1LvG35OZvx0QTiWFKafwxDTB2wU-Evg3qVSFHJ8PQNRbep5pr2Sv_GABq7hpLeMlTDSMcLxSGe7laIJVGldH14YiVviobB-nxJ8ldoBKsL9k3WIlTIpp4tty0GzPhzS4wGfoEeqAAY8FAlXmK8HIOz5VM-Kyvxm241o9zdQnLoSQDa0KsHMLY23P8QDqIicMZnUbq7SEY40M7RTGw";
    const MALFORMED_TOKEN: &str = "not.a.valid.jwt.token";
    const MISSING_SUB_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTk5LCJhdWQiOiJyYnMifQ.invalid_signature";

    fn setup_test_key() -> String {
        INIT.call_once(|| {
            let temp_dir = std::env::temp_dir();
            let key_path = temp_dir.join("rbs_test_jwt_pubkey.pem");
            let mut file = std::fs::File::create(&key_path).expect("Failed to create temp key file");
            file.write_all(TEST_PUBLIC_KEY_PEM.as_bytes()).expect("Failed to write key");
            unsafe {
                TEST_KEY_PATH = Some(key_path.to_string_lossy().to_string());
            }
        });
        unsafe { TEST_KEY_PATH.clone().unwrap() }
    }

    fn create_verifier() -> JwtVerifier {
        let key_path = setup_test_key();
        let config = JwtVerificationConfig {
            public_key_path: Some(key_path),
            jwks_file: None,
            issuer: "https://auth.example.com".to_string(),
        };
        JwtVerifier::new(config).expect("failed to create verifier")
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

    #[tokio::test]
    async fn test_jwt_missing_sub_claim() {
        let verifier = create_verifier();
        let result = verifier.verify(MISSING_SUB_TOKEN).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwt_expired_token() {
        let verifier = create_verifier();
        let result = verifier.verify(EXPIRED_TOKEN).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[tokio::test]
    async fn test_jwt_wrong_issuer() {
        let verifier = create_verifier();
        let result = verifier.verify(WRONG_ISSUER_TOKEN).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwt_invalid_signature() {
        let verifier = create_verifier();
        let result = verifier.verify(INVALID_SIG_TOKEN).await;
        assert!(result.is_err());
    }
}

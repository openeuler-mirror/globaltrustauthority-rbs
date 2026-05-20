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

//! Authenticator implementation.

use std::sync::Arc;

use async_trait::async_trait;
use rbs_api_types::config::AuthConfig;

use crate::auth::authn::token::AttestTokenVerifier;
use crate::auth::authn::bearer_token::BearerTokenVerifier;
use crate::auth::authn::{TokenVerifier, UserKeyProvider};
use crate::auth::context::{AuthContext, TokenType};
use crate::auth::error::AuthError;

/// Authentication trait
#[async_trait]
pub trait Auth: Send + Sync {
    /// Authenticate a token and return AuthContext.
    ///
    /// # Arguments
    /// * `token` - The token string (without Bearer/Attest prefix)
    /// * `token_type` - The token type determined by Authorization Header prefix
    ///
    /// # Returns
    /// * `Ok(AuthContext)` on successful authentication
    /// * `Err(AuthError)` on authentication failure
    async fn authenticate(&self, token: &str, token_type: TokenType) -> Result<AuthContext, AuthError>;
}

/// Authenticator implementation.
///
/// BearerToken uses per-user public keys via [`UserKeyProvider`];
/// AttestToken uses the configured public key from `attest_token` config.
#[derive(Clone)]
pub struct Authenticator {
    bearer_verifier: BearerTokenVerifier,
    attest_verifier: AttestTokenVerifier,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator").finish()
    }
}

impl Authenticator {
    /// Create a new Authenticator.
    ///
    /// `key_provider` resolves per-user BearerToken public keys from storage.
    /// AttestToken uses `config.attest_token` for its public key.
    pub fn new(
        config: AuthConfig,
        key_provider: Arc<dyn UserKeyProvider>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            bearer_verifier: BearerTokenVerifier::new(config.bearer_token, key_provider),
            attest_verifier: AttestTokenVerifier::new(config.attest_token)?,
        })
    }
}

#[async_trait]
impl Auth for Authenticator {
    async fn authenticate(&self, token: &str, token_type: TokenType) -> Result<AuthContext, AuthError> {
        log::debug!("Authenticating token type: {:?}", token_type);
        match token_type {
            TokenType::Bearer => {
                let ctx = self.bearer_verifier.verify(token).await?;
                log::info!("Bearer token authenticated for user: {}", ctx.sub);
                Ok(AuthContext::Bearer(ctx))
            }
            TokenType::Attest => {
                let ctx = self.attest_verifier.verify(token).await?;
                log::info!("Attest token authenticated successfully");
                Ok(AuthContext::Attest(ctx))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Once;

    static INIT: Once = Once::new();
    static mut TEST_KEY_PATH: Option<String> = None;

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

    /// Stub UserKeyProvider that returns the test public key for any sub.
    #[derive(Debug)]
    struct StubKeyProvider(String);

    #[async_trait]
    impl UserKeyProvider for StubKeyProvider {
        async fn get_public_key(&self, _sub: &str) -> Result<String, AuthError> {
            Ok(self.0.clone())
        }
    }

    fn setup_test_key() -> String {
        INIT.call_once(|| {
            let temp_dir = std::env::temp_dir();
            let key_path = temp_dir.join("rbs_test_authenticator_pubkey.pem");
            let mut file = std::fs::File::create(&key_path).expect("Failed to create temp key file");
            file.write_all(TEST_RSA_PUBLIC_KEY_PEM.as_bytes())
                .expect("Failed to write key");
            unsafe {
                TEST_KEY_PATH = Some(key_path.to_string_lossy().to_string());
            }
        });
        unsafe { TEST_KEY_PATH.clone().unwrap() }
    }

    fn create_test_authenticator() -> Authenticator {
        let key_path = setup_test_key();
        let config = AuthConfig {
            attest_token: rbs_api_types::config::AttestTokenVerificationConfig {
                public_key_path: Some(key_path),
                jwks_file: None,
                issuer: "Global Trust Authority".to_string(),
                audience: Some("rbs".to_string()),
            },
            bearer_token: rbs_api_types::config::BearerTokenVerificationConfig {
                issuer: "https://auth.example.com".to_string(),
                audience: "globaltrustauthority-rbs".to_string(),
            },
        };
        let key_provider = Arc::new(StubKeyProvider(TEST_RSA_PUBLIC_KEY_PEM.to_string()));
        Authenticator::new(config, key_provider).expect("failed to create authenticator")
    }

    #[tokio::test]
    async fn test_authenticator_bearer_malformed_token() {
        let auth = create_test_authenticator();
        let result = auth.authenticate("invalid.token", TokenType::Bearer).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticator_attest_malformed_token() {
        let auth = create_test_authenticator();
        let result = auth.authenticate("invalid.token", TokenType::Attest).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticator_attest_wrong_issuer() {
        let auth = create_test_authenticator();
        // Token with issuer "Evil Corp" instead of "Global Trust Authority"
        let token = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJFdmlsIENvcnAiLCJhdWQiOiJyYnMiLCJleHAiOjk5OTk5OTk5OTl9.jA8kPO-k0fCzBnGbHK-sNn1xEDn2p3U1XqQOZJmVhVPrDyKfBbZZ8wcNPMiAMeFBGk5VhmJrJcNCLFVOhE8z7p0nL2tX9Yq5vF7PZlW2uJm8Qx9cZP5YjBgK0mL5sHN6MRrJPwJx9F0yY3MJbqzE2VqW-tT0H3TbfO-eQq_OV-TTqbK1JP-kAa9xE1HXF_LTHLwM2yTR_n0V1J5q-p_E1oJ0p0iJXE4_n1JFXp1CF8WGLCZdpSQOxJ-Lm-6R7EwHKKKs0x2e5HW7VHBFMvIJ9aMkx-UaRGpAqXNCVYYrW9qTPWGFBdRq6x4XvVr9qEu9bMPL-4zDQIOU2YDYxVR5g";
        let result = auth.authenticate(token, TokenType::Attest).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_authenticator_creation_missing_config() {
        let config = AuthConfig {
            attest_token: rbs_api_types::config::AttestTokenVerificationConfig {
                public_key_path: None,
                jwks_file: None,
                issuer: "test".to_string(),
                audience: None,
            },
            bearer_token: rbs_api_types::config::BearerTokenVerificationConfig {
                issuer: "test".to_string(),
                audience: "test".to_string(),
            },
        };
        let key_provider = Arc::new(StubKeyProvider(TEST_RSA_PUBLIC_KEY_PEM.to_string()));
        let result = Authenticator::new(config, key_provider);
        assert!(result.is_err());
    }
}

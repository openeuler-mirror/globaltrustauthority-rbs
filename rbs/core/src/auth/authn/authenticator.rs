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

use crate::auth::authn::UserKeyProvider;
use crate::auth::context::{AuthContext, TokenType};
use crate::auth::error::AuthError;
use super::jwt::JwtVerifier;
use super::token::AttestTokenVerifier;
use async_trait::async_trait;
use rbs_api_types::config::{AuthConfig, JwtVerificationConfig};

/// Authentication trait
#[async_trait]
pub trait Auth: Send + Sync {
    /// Authenticate a token and return AuthContext.
    /// - token: the token string (without Bearer/Attest prefix)
    /// - token_type: the token type determined by Authorization Header prefix
    async fn authenticate(&self, token: &str, token_type: TokenType) -> Result<AuthContext, AuthError>;
}

/// Authenticator implementation.
///
/// BearerToken uses per-user public keys via [`UserKeyProvider`];
/// AttestToken uses the configured public key from `attest_token` config.
#[derive(Clone)]
pub struct Authenticator {
    jwt_verifier: JwtVerifier,
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
        // BearerToken issuer is validated but no public key needed from config —
        // per-user keys come from key_provider.
        let jwt_config = JwtVerificationConfig {
            public_key_path: None,
            jwks_file: None,
            issuer: config.attest_token.issuer.clone(),
        };
        Ok(Self {
            jwt_verifier: JwtVerifier::new(jwt_config, key_provider),
            attest_verifier: AttestTokenVerifier::new(config.attest_token)?,
        })
    }
}

#[async_trait]
impl Auth for Authenticator {
    async fn authenticate(&self, token: &str, token_type: TokenType) -> Result<AuthContext, AuthError> {
        match token_type {
            TokenType::Bearer => {
                let ctx = self.jwt_verifier.verify(token).await?;
                Ok(AuthContext::Bearer(ctx))
            }
            TokenType::Attest => {
                let ctx = self.attest_verifier.verify(token).await?;
                Ok(AuthContext::Attest(ctx))
            }
        }
    }
}

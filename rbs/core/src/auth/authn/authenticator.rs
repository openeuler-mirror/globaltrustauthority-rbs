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

use crate::auth::context::{AuthContext, TokenType};
use crate::auth::error::AuthError;
use super::jwt::JwtVerifier;
use super::token::AttestTokenVerifier;
use async_trait::async_trait;
use rbs_api_types::config::AuthConfig;

/// Authentication trait
#[async_trait]
pub trait Auth: Send + Sync {
    /// Authenticate a token and return AuthContext
    /// - token: the token string (without Bearer/Attest prefix)
    /// - token_type: the token type determined by Authorization Header prefix
    async fn authenticate(&self, token: &str, token_type: TokenType) -> Result<AuthContext, AuthError>;
}

/// Authenticator implementation
#[derive(Debug, Clone)]
pub struct Authenticator {
    jwt_verifier: JwtVerifier,
    attest_verifier: AttestTokenVerifier,
}

impl Authenticator {
    /// Create a new Authenticator from config
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        Ok(Self {
            jwt_verifier: JwtVerifier::new(config.bearer_token.clone())?,
            attest_verifier: AttestTokenVerifier::new(config.attest_token.clone())?,
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

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Authenticator implementation.

use crate::auth::{AuthContext, AuthError, AttestTokenVerifier, JwtVerifier};
use async_trait::async_trait;
use rbs_api_types::config::AuthConfig;

/// Authentication trait
#[async_trait]
pub trait Auth: Send + Sync {
    /// Authenticate a token and return AuthContext
    async fn authenticate(&self, token: &str) -> Result<AuthContext, AuthError>;
}

/// Authenticator implementation
#[derive(Debug, Clone)]
pub struct Authenticator {
    config: AuthConfig,
    jwt_verifier: JwtVerifier,
    attest_verifier: AttestTokenVerifier,
}

impl Authenticator {
    /// Create a new Authenticator from config
    pub fn new(config: AuthConfig) -> Self {
        Self {
            jwt_verifier: JwtVerifier::new(config.bearer_token.clone()),
            attest_verifier: AttestTokenVerifier::new(config.attest_token.clone()),
            config,
        }
    }
}

#[async_trait]
impl Auth for Authenticator {
    async fn authenticate(&self, token: &str) -> Result<AuthContext, AuthError> {
        // Extract iss from token to determine type
        let iss = crate::auth::jwt::extract_iss(token)?;

        if iss == self.config.bearer_token.issuer {
            let ctx = self.jwt_verifier.verify(token).await?;
            Ok(AuthContext::Bearer(ctx))
        } else if iss == self.config.attest_token.issuer {
            let ctx = self.attest_verifier.verify(token).await?;
            Ok(AuthContext::Attest(ctx))
        } else {
            Err(AuthError::TokenUnknown)
        }
    }
}

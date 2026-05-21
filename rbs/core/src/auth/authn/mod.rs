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

//! Authentication module.

pub mod authenticator;
pub mod common;
pub mod bearer_token;
pub mod token;

use async_trait::async_trait;
use crate::auth::error::AuthError;

pub use authenticator::{Auth, Authenticator};
pub use bearer_token::BearerTokenVerifier;
pub use token::AttestTokenVerifier;

/// Provides a per-user public key (PEM) for BearerToken signature verification.
#[async_trait]
pub trait UserKeyProvider: Send + Sync + std::fmt::Debug {
    /// Look up the PEM-encoded public key for the given user `sub`.
    async fn get_public_key(&self, sub: &str) -> Result<String, AuthError>;
}

/// Token verifier trait for different token types.
///
/// This trait provides a common interface for token verification,
/// enabling extensible authentication mechanisms.
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    /// The context type returned after successful verification.
    type Context: Send + Sync;

    /// Verify a token and return the authentication context.
    ///
    /// # Arguments
    /// * `token` - The raw token string (without Bearer/Attest prefix)
    ///
    /// # Returns
    /// * `Ok(Context)` on successful verification
    /// * `Err(AuthError)` on verification failure
    async fn verify(&self, token: &str) -> Result<Self::Context, AuthError>;
}

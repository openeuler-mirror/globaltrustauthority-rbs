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
pub mod bearer_token;
pub mod common;
pub mod lockout;
pub mod sm2;
pub mod token;

use crate::auth::error::AuthError;
use async_trait::async_trait;

pub use authenticator::{Auth, Authenticator};
pub use bearer_token::BearerTokenVerifier;
pub use lockout::LockoutTracker;
pub use token::AttestTokenVerifier;

/// Authentication data loaded from the authoritative user store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuthInfo {
    /// PEM-encoded public key used to verify the user's Bearer token.
    pub public_key: String,
    /// Current role from the user store (`"admin"` or `"user"`).
    pub role: String,
}

/// Provides per-user authentication data for BearerToken verification.
#[async_trait]
pub trait UserAuthProvider: Send + Sync + std::fmt::Debug {
    /// Look up the public key and current role for the given user `sub`.
    async fn get_user_auth(&self, sub: &str) -> Result<UserAuthInfo, AuthError>;
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

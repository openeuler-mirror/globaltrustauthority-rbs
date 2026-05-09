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
pub mod jwt;
pub mod jwks;
pub mod signature;
pub mod token;

use async_trait::async_trait;
use crate::auth::error::AuthError;

pub use authenticator::{Auth, Authenticator};
pub use jwt::JwtVerifier;
pub use token::AttestTokenVerifier;

/// Provides a per-user public key (PEM) for BearerToken signature verification.
#[async_trait]
pub trait UserKeyProvider: Send + Sync + std::fmt::Debug {
    /// Look up the PEM-encoded public key for the given user `sub`.
    async fn get_public_key(&self, sub: &str) -> Result<String, AuthError>;
}

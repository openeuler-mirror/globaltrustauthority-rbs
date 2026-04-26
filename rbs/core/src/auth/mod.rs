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

//! Authentication and Authorization module.

mod authenticator;
mod authz;
mod error;
mod jwt;
mod token;

// Re-export auth module types
pub use authenticator::{Auth, Authenticator};
pub use authz::{
    AdminOperation, Authz, AuthzDecision, AuthzError, AuthzFacade, PolicyOperation, ResourceUri,
};
pub use error::AuthError;
pub use jwt::JwtVerifier;
pub use token::AttestTokenVerifier;

// Context types
use serde_json::Value;

/// Token type enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    Bearer,
    Attest,
}

/// Bearer JWT context after successful verification
#[derive(Debug, Clone)]
pub struct BearerContext {
    pub iss: String,
    pub sub: String,
    pub aud: Value,
    pub role: String,
    pub exp: i64,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub jti: Option<String>,
    pub payload: Value,
    pub token_type: TokenType,
}

/// AttestToken context after successful verification
#[derive(Debug, Clone)]
pub struct AttestContext {
    pub claims: Value,
    pub token_type: TokenType,
}

/// Unified authentication context
#[derive(Debug, Clone)]
pub enum AuthContext {
    Bearer(BearerContext),
    Attest(AttestContext),
}

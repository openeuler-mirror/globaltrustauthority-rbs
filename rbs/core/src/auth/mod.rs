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

pub mod authn;
pub mod authz;
pub mod context;
pub mod error;

// Re-export auth module types
pub use authn::{Auth, Authenticator, AttestTokenVerifier, JwtVerifier};
pub use authz::{AdminAction, AuthzDecision, AuthzError, AuthzFacade, RequiredRole};
pub use context::{AttestContext, AuthContext, BearerContext, TokenType};
pub use error::AuthError;

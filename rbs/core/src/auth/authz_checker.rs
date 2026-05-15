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

//! Authorization checker abstraction — decouples our modules from `AuthzFacade`.
//!
//! Production code injects `AuthzCheckerImpl` (wraps `AuthzFacade`).
//! Tests inject `MockAuthzChecker` — no `PolicyEngine` dependency required.

use std::sync::Arc;

use async_trait::async_trait;
use crate::auth::authz::{Action, AuthzError, AuthzFacade, RequiredRole};
use crate::auth::context::AuthContext;
use crate::policy_engine::PolicyEngine;

/// Abstraction over `AuthzFacade` for testability.
#[async_trait]
pub trait AuthzChecker: Send + Sync {
    /// Check a simple management action (create / update / delete / list / get).
    async fn check_action(&self, ctx: &AuthContext, action: Action, role: RequiredRole) -> Result<(), AuthzError>;

    /// Check a resource GET operation.
    /// Bearer token → `owner` is used for ownership verification.
    /// Attest token → `policy` (Rego content) is evaluated against `ctx.claims`.
    async fn check_resource_get(&self, ctx: &AuthContext, owner: &str, policy: &str) -> Result<(), AuthzError>;
}

// ── Production implementation (delegates to AuthzFacade) ──────────────

/// Production `AuthzChecker` — wraps the real `AuthzFacade`.
pub struct AuthzCheckerImpl {
    facade: AuthzFacade,
}

impl AuthzCheckerImpl {
    pub fn new(engine: Arc<dyn PolicyEngine>) -> Self {
        Self { facade: AuthzFacade::new(engine) }
    }
}

#[async_trait]
impl AuthzChecker for AuthzCheckerImpl {
    async fn check_action(&self, ctx: &AuthContext, action: Action, role: RequiredRole) -> Result<(), AuthzError> {
        self.facade.check(ctx).action(action).required_role(role).ensure_allowed().await
    }

    async fn check_resource_get(&self, ctx: &AuthContext, owner: &str, policy: &str) -> Result<(), AuthzError> {
        self.facade.check(ctx).action(Action::Get).required_role(RequiredRole::UserScoped).owner(owner).policy(policy).ensure_allowed().await
    }
}

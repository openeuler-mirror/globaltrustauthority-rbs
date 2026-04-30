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

//! Fluent builder for authorization requests.

use crate::auth::context::AuthContext;
use serde_json::Value;

use super::{AdminAction, AuthzDecision, AuthzError, AuthzFacade, RequiredRole};

/// Fluent builder for constructing authorization requests
pub struct AuthzRequestBuilder<'a> {
    facade: &'a AuthzFacade,
    ctx: &'a AuthContext,
    action: Option<AdminAction>,
    required_role: RequiredRole,
    resource_type: Option<&'a str>,
}

impl<'a> AuthzRequestBuilder<'a> {
    pub(super) fn new(facade: &'a AuthzFacade, ctx: &'a AuthContext) -> Self {
        Self {
            facade,
            ctx,
            action: None,
            required_role: RequiredRole::UserScoped,
            resource_type: None,
        }
    }

    /// Set action type
    pub fn action(mut self, action: AdminAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Set required role level
    pub fn required_role(mut self, role: RequiredRole) -> Self {
        self.required_role = role;
        self
    }

    /// Set resource type
    pub fn resource_type(mut self, resource_type: &'a str) -> Self {
        self.resource_type = Some(resource_type);
        self
    }

    /// Execute authorization and return decision
    pub async fn evaluate(self) -> Result<AuthzDecision, AuthzError> {
        self.facade.evaluate(self).await
    }

    /// Execute authorization, return error on deny
    pub async fn ensure_allowed(self) -> Result<(), AuthzError> {
        match self.evaluate().await? {
            AuthzDecision::Allow => Ok(()),
            AuthzDecision::Deny => Err(AuthzError::Denied),
        }
    }

    /// Build policy engine input
    pub(super) fn build_input(&self) -> Result<Value, AuthzError> {
        let action = self.action.as_ref().ok_or(AuthzError::MissingField("action"))?;
        let resource_type = self.resource_type.ok_or(AuthzError::MissingField("resource_type"))?;

        Ok(serde_json::json!({
            "token_type": self.token_type_str(),
            "sub": self.sub(),
            "role": self.role(),
            "action": action.as_str(),
            "required_role": self.required_role.as_str(),
            "resource_type": resource_type,
        }))
    }

    /// Check if token is AttestToken
    pub(super) fn is_attest_token(&self) -> bool {
        matches!(self.ctx, AuthContext::Attest(_))
    }

    fn token_type_str(&self) -> &'static str {
        match self.ctx {
            AuthContext::Bearer(_) => "Bearer",
            AuthContext::Attest(_) => "Attest",
        }
    }

    fn sub(&self) -> &str {
        match self.ctx {
            AuthContext::Bearer(b) => &b.sub,
            AuthContext::Attest(_) => "",
        }
    }

    fn role(&self) -> &str {
        match self.ctx {
            AuthContext::Bearer(b) => &b.role,
            AuthContext::Attest(_) => "",
        }
    }
}

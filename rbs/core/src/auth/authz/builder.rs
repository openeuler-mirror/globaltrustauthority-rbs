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

use super::{Action, AuthzError, AuthzFacade, RequiredRole};

/// Fluent builder for constructing authorization requests
pub struct AuthzRequestBuilder<'a> {
    facade: &'a AuthzFacade,
    ctx: &'a AuthContext,
    action: Option<Action>,
    required_role: RequiredRole,
    owner: Option<&'a str>,
    policy: Option<&'a str>,
}

impl<'a> AuthzRequestBuilder<'a> {
    pub(super) fn new(facade: &'a AuthzFacade, ctx: &'a AuthContext) -> Self {
        Self {
            facade, ctx, action: None,
            required_role: RequiredRole::UserScoped,
            owner: None, policy: None,
        }
    }

    pub fn action(mut self, action: Action) -> Self { self.action = Some(action); self }
    pub fn required_role(mut self, role: RequiredRole) -> Self { self.required_role = role; self }
    pub fn owner(mut self, owner: &'a str) -> Self { self.owner = Some(owner); self }
    pub fn policy(mut self, policy: &'a str) -> Self { self.policy = Some(policy); self }

    pub async fn ensure_allowed(self) -> Result<(), AuthzError> {
        self.facade.evaluate(self).await
    }

    pub(super) fn build_input(&self) -> Result<Value, AuthzError> {
        let action = self.action.as_ref().ok_or(AuthzError::MissingField("action"))?;
        let mut input = serde_json::json!({
            "token_type": self.token_type_str(),
            "sub": self.sub(),
            "role": self.role(),
            "action": action.as_str(),
            "required_role": self.required_role.as_str(),
        });
        if let Some(owner) = self.owner { input["owner"] = Value::String(owner.to_string()); }
        Ok(input)
    }

    pub(super) fn is_attest_token(&self) -> bool { matches!(self.ctx, AuthContext::Attest(_)) }
    pub(super) fn policy_content(&self) -> Option<&str> { self.policy }
    pub(super) fn attest_claims(&self) -> Option<&Value> {
        match self.ctx { AuthContext::Attest(a) => Some(&a.claims), _ => None }
    }

    fn token_type_str(&self) -> &'static str {
        match self.ctx { AuthContext::Bearer(_) => "Bearer", AuthContext::Attest(_) => "Attest" }
    }
    fn sub(&self) -> &str {
        match self.ctx { AuthContext::Bearer(b) => &b.sub, AuthContext::Attest(_) => "" }
    }
    fn role(&self) -> &str {
        match self.ctx { AuthContext::Bearer(b) => &b.role, AuthContext::Attest(_) => "" }
    }
}

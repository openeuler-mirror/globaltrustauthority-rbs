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

//! Authorization facade implementation.

use crate::policy_engine::evaluate_policy;

use super::builder::AuthzRequestBuilder;
use super::{AuthzDecision, AuthzError};

/// Admin policy Rego content
const ADMIN_POLICY: &str = include_str!("../policies/admin_policy.rego");

/// Authorization facade
#[derive(Debug, Clone)]
pub struct AuthzFacade;

impl AuthzFacade {
    pub fn new() -> Self {
        Self
    }

    /// Start building authorization request
    pub fn check<'a>(&'a self, ctx: &'a crate::auth::context::AuthContext) -> AuthzRequestBuilder<'a> {
        AuthzRequestBuilder::new(self, ctx)
    }

    /// Execute authorization
    pub(super) async fn evaluate(&self, builder: AuthzRequestBuilder<'_>) -> Result<AuthzDecision, AuthzError> {
        // AttestToken not allowed for admin operations
        if builder.is_attest_token() {
            return Ok(AuthzDecision::Deny);
        }

        let input = builder.build_input()?;
        evaluate_policy_generic(&input, ADMIN_POLICY)
    }
}

impl Default for AuthzFacade {
    fn default() -> Self {
        Self::new()
    }
}

fn evaluate_policy_generic(input: &serde_json::Value, policy: &str) -> Result<AuthzDecision, AuthzError> {
    match evaluate_policy(input, policy, true) {
        Ok(result) => {
            let matched = result
                .get("result")
                .and_then(|r| r.get("policy_matched"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if matched {
                Ok(AuthzDecision::Allow)
            } else {
                Ok(AuthzDecision::Deny)
            }
        }
        Err(e) => Err(AuthzError::PolicyEvaluationFailed(e.to_string())),
    }
}

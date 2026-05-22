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

//! Unit tests for `AuthzFacade` -- authorization evaluation with mock engine.
//!
//! These complement `policy_engine_tests.rs` by testing AuthzFacade directly
//! with a mock policy engine to verify behavior that doesn't depend on the
//! real OPA-backed engine.

use rbs_core::auth::context::{AuthContext, AttestContext, BearerContext, TokenType};
use rbs_core::auth::authz::{Action, AuthzError, RequiredRole};
use rbs_core::policy_engine::{PolicyEngine, PolicyEngineError};
use rbs_core::auth::authz::AuthzFacade;
use serde_json::Value;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Mock policy engine (sync, matching PolicyEngine trait)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockPolicyEngine {
    should_allow: bool,
}

impl MockPolicyEngine {
    fn new(should_allow: bool) -> Self {
        Self { should_allow }
    }
}

impl PolicyEngine for MockPolicyEngine {
    fn evaluate(
        &self,
        _input: &Value,
        _policy: &str,
        _safe_mode: bool,
    ) -> Result<Value, PolicyEngineError> {
        Ok(serde_json::json!({ "policy_matched": self.should_allow }))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn admin_bearer() -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "https://auth.example.com".to_string(),
        sub: "Administrator".to_string(),
        role: "admin".to_string(),
        claims: serde_json::Value::Null,
        token_type: TokenType::Bearer,
    })
}

fn user_bearer(sub: &str) -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "https://auth.example.com".to_string(),
        sub: sub.to_string(),
        role: "user".to_string(),
        claims: serde_json::Value::Null,
        token_type: TokenType::Bearer,
    })
}

fn attest_ctx() -> AuthContext {
    AuthContext::Attest(AttestContext {
        claims: serde_json::json!({ "tee-pubkey": "test-key" }),
        token_type: TokenType::Attest,
    })
}

// ===========================================================================
// AuthzFacade with mock engine — admin policy (Bearer tokens)
// ===========================================================================

/// Admin policy evaluation: MockEngine (should_allow=true) + AdminOnly -> Ok.
#[tokio::test]
async fn test_authz_facade_mock_allow_admin_only() {
    let engine = Arc::new(MockPolicyEngine::new(true));
    let facade = AuthzFacade::new(engine);
    let result = facade
        .check(&admin_bearer())
        .action(Action::Delete)
        .required_role(RequiredRole::AdminOnly)
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

/// Admin policy evaluation: MockEngine (should_allow=false) + AdminOnly -> Denied.
#[tokio::test]
async fn test_authz_facade_mock_deny_admin_only() {
    let engine = Arc::new(MockPolicyEngine::new(false));
    let facade = AuthzFacade::new(engine);
    let result = facade
        .check(&admin_bearer())
        .action(Action::Delete)
        .required_role(RequiredRole::AdminOnly)
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::Denied)));
}

/// Admin policy evaluation: MockEngine (should_allow=true) + UserScoped -> Ok.
#[tokio::test]
async fn test_authz_facade_mock_allow_user_scoped() {
    let engine = Arc::new(MockPolicyEngine::new(true));
    let facade = AuthzFacade::new(engine);
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Create)
        .required_role(RequiredRole::UserScoped)
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

/// Admin policy evaluation: MockEngine (should_allow=false) + UserScoped -> Denied.
#[tokio::test]
async fn test_authz_facade_mock_deny_user_scoped() {
    let engine = Arc::new(MockPolicyEngine::new(false));
    let facade = AuthzFacade::new(engine);
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Create)
        .required_role(RequiredRole::UserScoped)
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::Denied)));
}

// ===========================================================================
// AuthzFacade with mock engine — attest tokens (no public .policy() setter)
// ===========================================================================

/// Attest token without policy set -> MissingField("policy").
/// The AuthzFacade::evaluate() for Attest tokens calls builder.policy_content()
/// which returns None when no policy was set via the internal .policy() builder method.
#[tokio::test]
async fn test_authz_facade_attest_without_policy() {
    let engine = Arc::new(MockPolicyEngine::new(true));
    let facade = AuthzFacade::new(engine);
    let ctx = attest_ctx();
    let result = facade.check(&ctx)
        .action(Action::Get)
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::MissingField("policy"))));
}

// ===========================================================================
// AuthzError variants
// ===========================================================================

/// AuthzError::Denied Display
#[test]
fn test_authz_error_denied_display() {
    let err = AuthzError::Denied;
    assert_eq!(err.to_string(), "access denied");
}

/// AuthzError::MissingField Display
#[test]
fn test_authz_error_missing_field_display() {
    let err = AuthzError::MissingField("action");
    assert_eq!(err.to_string(), "missing required field: action");
}

/// AuthzError::PolicyEvaluationFailed Display
#[test]
fn test_authz_error_policy_evaluation_failed_display() {
    let err = AuthzError::PolicyEvaluationFailed("rego syntax error".to_string());
    let msg = err.to_string();
    assert!(msg.contains("policy evaluation failed") || msg.contains("rego syntax error"));
}
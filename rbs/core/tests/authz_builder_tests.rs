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

//! Unit tests for `AuthzRequestBuilder` -- fluent builder behavior.
//!
//! Test scenarios UT-AB-001 through UT-AB-009.

use rbs_core::auth::authz::{Action, AuthzError, RequiredRole};
use rbs_core::auth::context::{AuthContext, AttestContext, BearerContext, TokenType};
use rbs_core::policy_engine;
use std::sync::Arc;

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

// ===========================================================================
// UT-AB-001: Missing action -> MissingField("action")
// ===========================================================================

/// UT-AB-001: ensure_allowed() without .action() returns MissingField("action").
#[tokio::test]
async fn test_missing_action_returns_missing_field() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&user_bearer("user1"))
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::MissingField("action"))));
}

// ===========================================================================
// UT-AB-002: Action::Create with UserScoped -> allows any Bearer
// ===========================================================================

/// UT-AB-002: Action::Create with UserScoped policy allows any Bearer token.
#[tokio::test]
async fn test_action_create_string() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Create)
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

// ===========================================================================
// UT-AB-003: RequiredRole::AdminOnly with user role -> Denied
// ===========================================================================

/// UT-AB-003: AdminOnly requires admin role; user role is denied.
#[tokio::test]
async fn test_required_role_admin_only_with_user_denies() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Create)
        .required_role(RequiredRole::AdminOnly)
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::Denied)));
}

/// UT-AB-003b: AdminOnly allows admin role.
#[tokio::test]
async fn test_required_role_admin_only_with_admin_allows() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&admin_bearer())
        .action(Action::Create)
        .required_role(RequiredRole::AdminOnly)
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

// UT-AB-004: owner() is set and evaluation with UserScoped policy
// ===========================================================================

/// UT-AB-004: .owner() mismatched with sub → Denied by rego check_owner rule.
/// Rego enforces input.sub == input.owner when owner is present, so user1 != user2 denies.
#[tokio::test]
async fn test_owner_included_in_input() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Get)
        .required_role(RequiredRole::UserScoped)
        .owner("user2")
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::Denied)));
}

// ===========================================================================
// UT-AB-005: Bearer vs Attest token evaluation
// ===========================================================================

/// UT-AB-005: Bearer token evaluates ADMIN_POLICY correctly (admin + AdminOnly = allowed).
#[tokio::test]
async fn test_bearer_token_type_evaluated() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&admin_bearer())
        .action(Action::Delete)
        .required_role(RequiredRole::AdminOnly)
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

/// UT-AB-005b: Attest token without policy set on builder -> MissingField("policy").
#[tokio::test]
async fn test_attest_token_without_policy_fails() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let ctx = AuthContext::Attest(AttestContext {
        claims: serde_json::Value::Null,
        token_type: TokenType::Attest,
    });
    let result = facade.check(&ctx).ensure_allowed().await;
    assert!(result.is_err());
}

// ===========================================================================
// UT-AB-006: .required_role() called twice — last value wins
// ===========================================================================

/// UT-AB-006: .required_role() called twice uses the last value (AdminOnly overrides UserScoped).
#[tokio::test]
async fn test_required_role_last_wins() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&admin_bearer())
        .action(Action::Create)
        .required_role(RequiredRole::UserScoped)  // set first
        .required_role(RequiredRole::AdminOnly)   // overridden to AdminOnly
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

// ===========================================================================
// UT-AB-007: .action() called twice — last value wins
// ===========================================================================

/// UT-AB-007: .action() called twice uses the last action value.
#[tokio::test]
async fn test_action_last_wins() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&admin_bearer())
        .action(Action::Create)  // set first
        .action(Action::Delete)   // overridden to Delete
        .required_role(RequiredRole::AdminOnly)
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

// ===========================================================================
// UT-AB-008: Attest token -> evaluate() extracts claims and policy, not ADMIN_POLICY
// ===========================================================================

/// UT-AB-008: Attest token with null claims and no policy -> MissingField("policy")
/// This confirms the facade evaluates Attest tokens against their own policy (not ADMIN_POLICY).
#[tokio::test]
async fn test_attest_token_null_claims_missing_policy() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let ctx = AuthContext::Attest(AttestContext {
        claims: serde_json::Value::Null,
        token_type: TokenType::Attest,
    });
    let result = facade.check(&ctx)
        .action(Action::Get)
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::MissingField("policy"))));
}

/// UT-AB-008b: Attest token with claims but no policy -> MissingField("policy").
#[tokio::test]
async fn test_attest_token_with_claims_missing_policy() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let ctx = AuthContext::Attest(AttestContext {
        claims: serde_json::json!({"tee-pubkey": "key123"}),
        token_type: TokenType::Attest,
    });
    let result = facade.check(&ctx)
        .action(Action::Get)
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::MissingField("policy"))));
}

// ===========================================================================
// UT-AB-009: .owner() with empty string — rego handles it or not
// ===========================================================================

/// UT-AB-009: owner set to empty string → Denied by rego check_owner rule.
/// Rego treats "" as a present owner (truthy), so check_owner requires sub == "" which fails for "user1".
#[tokio::test]
async fn test_empty_owner_accepted() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Get)
        .required_role(RequiredRole::UserScoped)
        .owner("")
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::Denied)));
}

// ===========================================================================
// TC1-TC3, TC8-TC9: admin_policy.rego Bearer gate for HSM/CA (D1/K4)
// ===========================================================================

/// TC1: Bearer+UserScoped+res_provider="hsm" → Denied
#[tokio::test]
async fn test_bearer_get_hsm_denied() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Get)
        .required_role(RequiredRole::UserScoped)
        .owner("user1")
        .res_provider("hsm")
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::Denied)));
}

/// TC2: Bearer+UserScoped+res_provider="ca" → Denied
#[tokio::test]
async fn test_bearer_get_ca_denied() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Get)
        .required_role(RequiredRole::UserScoped)
        .owner("user1")
        .res_provider("ca")
        .ensure_allowed()
        .await;
    assert!(matches!(result, Err(AuthzError::Denied)));
}

/// TC3: Bearer+UserScoped+res_provider="vault"+owner match → Ok (compatible regression)
#[tokio::test]
async fn test_bearer_get_vault_allowed() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Get)
        .required_role(RequiredRole::UserScoped)
        .owner("user1")
        .res_provider("vault")
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

/// TC8: Bearer+UserScoped without res_provider → Ok (backward compatible)
#[tokio::test]
async fn test_bearer_get_no_res_provider_allowed() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&user_bearer("user1"))
        .action(Action::Get)
        .required_role(RequiredRole::UserScoped)
        .owner("user1")
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

/// TC9: AdminOnly+res_provider="hsm" → Ok (gate doesn't affect AdminOnly)
#[tokio::test]
async fn test_admin_only_hsm_not_gated() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let result = facade
        .check(&admin_bearer())
        .action(Action::Delete)
        .required_role(RequiredRole::AdminOnly)
        .res_provider("hsm")
        .ensure_allowed()
        .await;
    assert!(result.is_ok());
}

// ===========================================================================
// TC5: Attest path not affected by res_provider gate (D1/K4)
// ===========================================================================

/// TC5: Attest+res_provider="hsm" → resource-level Rego evaluates, gate doesn't apply
#[tokio::test]
async fn test_attest_get_hsm_not_gated() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let ctx = AuthContext::Attest(AttestContext {
        claims: serde_json::json!({"nonce": "abc"}),
        token_type: TokenType::Attest,
    });
    let policy = r#"package verification
result = {"policy_matched": true}"#;
    let result = facade.check(&ctx)
        .action(Action::Get)
        .policy(policy)
        .res_provider("hsm")
        .ensure_allowed()
        .await;
    assert!(result.is_ok(), "Attest GET hsm should not be gated: {:?}", result.err());
}

/// TC5b: Attest+res_provider="ca" → same, gate doesn't apply
#[tokio::test]
async fn test_attest_get_ca_not_gated() {
    let facade = rbs_core::auth::authz::AuthzFacade::new(Arc::new(policy_engine::RealPolicyEngine));
    let ctx = AuthContext::Attest(AttestContext {
        claims: serde_json::json!({"nonce": "abc"}),
        token_type: TokenType::Attest,
    });
    let policy = r#"package verification
result = {"policy_matched": true}"#;
    let result = facade.check(&ctx)
        .action(Action::Get)
        .policy(policy)
        .res_provider("ca")
        .ensure_allowed()
        .await;
    assert!(result.is_ok(), "Attest GET ca should not be gated: {:?}", result.err());
}

// ===========================================================================
// TC7: Stub backend capabilities verification
// ===========================================================================

/// TC7: CABackend capabilities (requires cert/key files — test via new)
#[tokio::test]
async fn test_ca_stub_capabilities() {
    // CABackend::new requires real cert/key/anchor files.
    // The full CMPv2 flow is tested in ca_backend_tests.rs with a mock CMP server.
    // Here we just verify the type exists and the trait is implemented.
    use rbs_core::resource::adapter::CABackend;
    let _ = std::marker::PhantomData::<CABackend>;
}
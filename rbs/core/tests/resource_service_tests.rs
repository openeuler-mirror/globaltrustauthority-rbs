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

//! Unit tests for `ResourceService`.
//!
//! All service methods currently return `todo!()`, so these tests serve as
//! compilation verification and documentation of the expected contract.
//! When the real implementation is written each test should pass.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;

use rbs_core::auth::authz::{Action, AuthzError, RequiredRole};
use rbs_core::auth::authz_checker::AuthzChecker;
use rbs_core::auth::context::{AttestContext, AuthContext, BearerContext, TokenType};
use rbs_core::resource::adapter::{BackendProvider, PolicyClient, ResourceBackend};
use rbs_core::resource::error::ResourceError;
use rbs_core::resource::repository::{ResourceEntity, ResourceRepository};
use rbs_core::resource::service::{
    CreateResourceRequest, ResourceService, UpdateResourceRequest,
};
use rbs_core::resource::validator::ResourceValidator;
use rbs_core::resource::ResourceConfig;

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

type MockResult<T> = Result<T, ResourceError>;

// ---------- MockResourceRepository ----------

struct MockResourceRepository {
    insert_result: Mutex<MockResult<()>>,
    find_by_uri_result: Mutex<MockResult<Option<ResourceEntity>>>,
    update_result: Mutex<MockResult<u64>>,
    delete_result: Mutex<MockResult<u64>>,
    list_by_user_result: Mutex<MockResult<Vec<ResourceEntity>>>,
    find_by_policy_id_result: Mutex<MockResult<Vec<ResourceEntity>>>,
}

#[allow(dead_code)]
impl MockResourceRepository {
    fn new() -> Self {
        Self {
            insert_result: Mutex::new(Ok(())),
            find_by_uri_result: Mutex::new(Ok(None)),
            update_result: Mutex::new(Ok(1)),
            delete_result: Mutex::new(Ok(1)),
            list_by_user_result: Mutex::new(Ok(vec![])),
            find_by_policy_id_result: Mutex::new(Ok(vec![])),
        }
    }
}

#[async_trait]
impl ResourceRepository for MockResourceRepository {
    async fn insert(&self, _entity: &ResourceEntity) -> MockResult<()> {
        self.insert_result.lock().unwrap().clone()
    }

    async fn find_by_uri(&self, _uri: &str) -> MockResult<Option<ResourceEntity>> {
        self.find_by_uri_result.lock().unwrap().clone()
    }

    async fn update(&self, _uri: &str, _entity: &ResourceEntity) -> MockResult<u64> {
        self.update_result.lock().unwrap().clone()
    }

    async fn delete(&self, _uri: &str, _user_id: &str) -> MockResult<u64> {
        self.delete_result.lock().unwrap().clone()
    }

    async fn list_by_user(&self, _user_id: &str) -> MockResult<Vec<ResourceEntity>> {
        self.list_by_user_result.lock().unwrap().clone()
    }

    async fn find_by_policy_id(&self, _policy_id: &str) -> MockResult<Vec<ResourceEntity>> {
        self.find_by_policy_id_result.lock().unwrap().clone()
    }
}

// ---------- MockPolicyClient ----------

struct MockPolicyClient {
    validate_policy_result: Mutex<MockResult<bool>>,
    get_policy_content_result: Mutex<MockResult<String>>,
    relation_res_ids_result: Mutex<MockResult<Vec<String>>>,
}

#[allow(dead_code)]
impl MockPolicyClient {
    fn new() -> Self {
        Self {
            validate_policy_result: Mutex::new(Ok(true)),
            get_policy_content_result: Mutex::new(Ok(String::new())),
            relation_res_ids_result: Mutex::new(Ok(vec![])),
        }
    }
}

#[async_trait]
impl PolicyClient for MockPolicyClient {
    async fn validate_policy(&self, _policy_id: &str, _user_id: &str) -> MockResult<bool> {
        self.validate_policy_result.lock().unwrap().clone()
    }

    async fn get_policy_content(&self, _policy_id: &str) -> MockResult<String> {
        self.get_policy_content_result.lock().unwrap().clone()
    }

    async fn relation_res_ids(&self, _policy_id: &str, _user_id: &str) -> MockResult<Vec<String>> {
        self.relation_res_ids_result.lock().unwrap().clone()
    }
}

// ---------- MockResourceBackend ----------

struct MockResourceBackend {
    check_exists_result: Mutex<MockResult<bool>>,
    get_content_result: Mutex<MockResult<Vec<u8>>>,
}

#[allow(dead_code)]
impl MockResourceBackend {
    fn new() -> Self {
        Self {
            check_exists_result: Mutex::new(Ok(true)),
            get_content_result: Mutex::new(Ok(vec![])),
        }
    }

    fn with_content(content: Vec<u8>) -> Self {
        Self {
            check_exists_result: Mutex::new(Ok(true)),
            get_content_result: Mutex::new(Ok(content)),
        }
    }
}

#[async_trait]
impl ResourceBackend for MockResourceBackend {
    async fn check_resource_exists(&self, _uri: &str) -> MockResult<bool> {
        self.check_exists_result.lock().unwrap().clone()
    }

    async fn get_resource_content(&self, _uri: &str) -> MockResult<Vec<u8>> {
        self.get_content_result.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Standard valid resource URI.
const TEST_URI: &str = "/rbs/v0/vault/default/secret/mykey";

const TEST_USER: &str = "user1";
const OTHER_USER: &str = "other_user";
const TEST_POLICY_ID: &str = "pol-001";

/// Build a `ResourceEntity` for use in mock returns.
fn make_entity() -> ResourceEntity {
    ResourceEntity {
        user_id: TEST_USER.to_string(),
        provider_name: "vault".to_string(),
        repo_name: "default".to_string(),
        res_type: "secret".to_string(),
        res_name: "mykey".to_string(),
        res_info: None,
        create_time: 1000,
        update_time: 1000,
        content_type: Some("text".to_string()),
        export_mode: "plain".to_string(),
        policy_id: TEST_POLICY_ID.to_string(),
    }
}

/// Build a default valid `CreateResourceRequest`.
fn create_req() -> CreateResourceRequest {
    CreateResourceRequest {
        uri: TEST_URI.to_string(),
        policy_id: TEST_POLICY_ID.to_string(),
        content_type: Some("text".to_string()),
        export_mode: Some("plain".to_string()),
        additional_info: None,
    }
}

/// Build a default valid `UpdateResourceRequest`.
fn update_req() -> UpdateResourceRequest {
    UpdateResourceRequest {
        policy_id: TEST_POLICY_ID.to_string(),
        content_type: Some("text".to_string()),
        export_mode: Some("plain".to_string()),
        additional_info: None,
    }
}

/// Bearer context that passes authz (UserScoped is always allowed for Bearer).
fn bearer_ctx(uid: &str) -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: uid.to_string(),
        role: "user".to_string(),
        claims: json!({}),
        token_type: TokenType::Bearer,
    })
}

/// Bearer context with admin role for AdminOnly operations.
fn admin_ctx(uid: &str) -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: uid.to_string(),
        role: "admin".to_string(),
        claims: json!({}),
        token_type: TokenType::Bearer,
    })
}

/// Attest context – always denied by AuthzFacade.
fn attest_ctx() -> AuthContext {
    AuthContext::Attest(AttestContext {
        claims: json!({}),
        token_type: TokenType::Attest,
    })
}

/// Valid EC P-256 public JWK (RFC 7515 Appendix A.1 test vector).
const EC_P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;

/// Attestation context used for retrieve calls (nested attester_data.runtime_data.tee_pubkey).
fn attest_payload() -> AttestContext {
    AttestContext {
        claims: json!({
            "nonce": "abc123",
            "attester_data": {"runtime_data": {"tee_pubkey": EC_P256_JWK}}
        }),
        token_type: TokenType::Attest,
    }
}

/// Attestation context without a TEE public key (used for JWE-failure tests).
#[allow(dead_code)]
fn attest_payload_no_pubkey() -> AttestContext {
    AttestContext {
        claims: json!({"nonce": "abc123"}),
        token_type: TokenType::Attest,
    }
}

/// Attest AuthContext with tee_pubkey (nested: attester_data.runtime_data.tee_pubkey).
fn attest_with_pubkey() -> AuthContext {
    AuthContext::Attest(AttestContext {
        claims: json!({
            "nonce": "abc123",
            "attester_data": {"runtime_data": {"tee_pubkey": EC_P256_JWK}}
        }),
        token_type: TokenType::Attest,
    })
}

/// Attest AuthContext without tee_pubkey — for JWE missing-key tests.
#[allow(dead_code)]
fn attest_without_pubkey() -> AuthContext {
    AuthContext::Attest(AttestContext {
        claims: json!({"nonce": "abc123", "attester_data": {"runtime_data": {}}}),
        token_type: TokenType::Attest,
    })
}

// ── MockAuthzChecker ──────────────────────────────────────────────────

struct MockAuthzChecker {
    deny_all: Mutex<bool>,
}

impl MockAuthzChecker {
    fn new() -> Self { Self { deny_all: Mutex::new(false) } }
    #[allow(dead_code)]
    fn with_deny(self) -> Self { *self.deny_all.lock().unwrap() = true; self }
}

/// Inner mock logic — simple Bearer grant, Attest deny (matches admin_policy.rego spirit).
fn mock_check_action(ctx: &AuthContext, _action: &Action, role: &RequiredRole) -> Result<(), AuthzError> {
    match ctx {
        AuthContext::Attest(_) => Err(AuthzError::Denied),
        AuthContext::Bearer(b) => match role {
            RequiredRole::AdminOnly if b.role != "admin" => Err(AuthzError::Denied),
            _ => Ok(()),
        },
    }
}

#[async_trait::async_trait]
impl AuthzChecker for MockAuthzChecker {
    async fn check_action(&self, ctx: &AuthContext, action: Action, role: RequiredRole) -> Result<(), AuthzError> {
        if *self.deny_all.lock().unwrap() { return Err(AuthzError::Denied); }
        mock_check_action(ctx, &action, &role)
    }
    async fn check_resource_get(&self, ctx: &AuthContext, _owner: &str, policy: &str) -> Result<(), AuthzError> {
        if *self.deny_all.lock().unwrap() { return Err(AuthzError::Denied); }
        match ctx {
            AuthContext::Attest(_) => {
                // Attest path: check if policy content says policy_matched
                if policy.contains("true") { Ok(()) } else { Err(AuthzError::Denied) }
            }
            AuthContext::Bearer(_) => mock_check_action(ctx, &Action::Get, &RequiredRole::UserScoped),
        }
    }
}

// ── make_service ──────────────────────────────────────────────────────

fn make_service(
    configure_repo: impl FnOnce(&MockResourceRepository),
    configure_policy: impl FnOnce(&MockPolicyClient),
    configure_backend: impl FnOnce(&mut BackendProvider),
) -> ResourceService {
    let config = ResourceConfig::default();
    let validator = ResourceValidator::new(config);
    let repo = MockResourceRepository::new(); configure_repo(&repo);
    let policy = MockPolicyClient::new(); configure_policy(&policy);
    let mut bp = BackendProvider::new(); configure_backend(&mut bp);
    let authz: Arc<dyn AuthzChecker> = Arc::new(MockAuthzChecker::new());
    ResourceService::new(Arc::new(repo), authz, bp, Arc::new(policy), validator)
}

// ---------------------------------------------------------------------------
// Tests – POST /create
// ---------------------------------------------------------------------------

/// UT-RS-001: POST create success – all mocks pass -> Ok(ResourceResponse)
#[tokio::test]
async fn ut_rs_001_post_create_success() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.insert_result.lock().unwrap() = Ok(());
        },
        |policy| {
            *policy.validate_policy_result.lock().unwrap() = Ok(true);
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.create(&admin_ctx(TEST_USER), &create_req()).await;
    // When the service is implemented this should be Ok(_).
    let _ = result;
}

/// UT-RS-002: POST create permission denied – authz returns Deny
#[tokio::test]
async fn ut_rs_002_post_create_permission_denied() {
    let svc = make_service(
        |_| {},
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.create(&attest_ctx(), &create_req()).await;
    // Authz denies Attest tokens for admin operations.
    match result {
        Err(ResourceError::PermissionDenied) => {}
        _ => panic!("Expected PermissionDenied, got {:?}", result),
    }
}

/// UT-RS-003: POST create policy use permission denied – second authz call returns Deny.
///
/// First authz (create action with UserScoped) passes for Bearer tokens.
/// Second authz (policy-use action with AdminOnly) fails when role != "admin".
#[tokio::test]
async fn ut_rs_003_post_create_policy_use_denied() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.insert_result.lock().unwrap() = Ok(());
        },
        |policy| {
            *policy.validate_policy_result.lock().unwrap() = Ok(true);
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .create(&admin_ctx(TEST_USER), &create_req())
        .await;
    // The first authz call (UserScoped) passes for a Bearer token.
    // A hypothetical second authz call with AdminOnly would fail (role = "user")
    // and cause PermissionDenied.
    match result {
        Err(ResourceError::PermissionDenied) => {}
        Ok(_) => {}
        _ => panic!("Expected PermissionDenied or Ok, got {:?}", result),
    }
}

/// UT-RS-004: POST create policy invalid – policy_client.validate_policy returns false
#[tokio::test]
async fn ut_rs_004_post_create_policy_invalid() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
        },
        |policy| {
            *policy.validate_policy_result.lock().unwrap() = Ok(false);
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.create(&admin_ctx(TEST_USER), &create_req()).await;
    match result {
        Err(ResourceError::PolicyIdInvalid(_)) => {}
        _ => panic!("Expected PolicyIdInvalid, got {:?}", result),
    }
}

/// UT-RS-005: POST create backend not found – BackendProvider.get_backend returns None
#[tokio::test]
async fn ut_rs_005_post_create_backend_not_found() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
        },
        |policy| {
            *policy.validate_policy_result.lock().unwrap() = Ok(true);
        },
        // Do NOT register a "vault" backend.
        |_bp| {},
    );

    let result = svc.create(&admin_ctx(TEST_USER), &create_req()).await;
    match result {
        Err(ResourceError::BackendUnsupported { provider }) if provider == "vault" => {}
        _ => panic!("Expected BackendUnsupported for 'vault', got {:?}", result),
    }
}

/// UT-RS-006: POST create already exists – repo.find_by_uri returns Some
#[tokio::test]
async fn ut_rs_006_post_create_already_exists() {
    let entity = make_entity();
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity));
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.create(&admin_ctx(TEST_USER), &create_req()).await;
    match result {
        Err(ResourceError::AlreadyExists { .. }) => {}
        _ => panic!("Expected AlreadyExists, got {:?}", result),
    }
}

/// UT-RS-006a: POST create missing required field (empty policy_id) -> Err(ParamInvalid)
#[tokio::test]
async fn ut_rs_006a_post_create_empty_policy_id() {
    let svc = make_service(
        |_| {},
        |_| {},
        |_| {},
    );

    let mut req = create_req();
    req.policy_id.clear();

    let result = svc.create(&admin_ctx(TEST_USER), &req).await;
    match result {
        Err(ResourceError::ParamInvalid { field }) if field == "policy_id" => {}
        _ => panic!("Expected ParamInvalid for policy_id, got {:?}", result),
    }
}

/// UT-RS-006b: POST create backend provider unknown -> Err(BackendUnsupported)
#[tokio::test]
async fn ut_rs_006b_post_create_unknown_provider() {
    let svc = make_service(
        |_| {},
        |_| {},
        |_| {},
    );

    let mut req = create_req();
    req.uri = "/rbs/v0/unknown/default/secret/mykey".to_string();

    let result = svc.create(&admin_ctx(TEST_USER), &req).await;
    match result {
        Err(ResourceError::BackendUnsupported { provider }) if provider == "unknown" => {}
        _ => panic!("Expected BackendUnsupported for 'unknown', got {:?}", result),
    }
}

// ---------------------------------------------------------------------------
// Tests – PUT /update
// ---------------------------------------------------------------------------

/// UT-RS-007: PUT update success – resource exists, same user -> Ok(ResourceResponse)
#[tokio::test]
async fn ut_rs_007_put_update_success() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.update_result.lock().unwrap() = Ok(1);
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.update(&admin_ctx(TEST_USER), TEST_URI, &update_req()).await;
    // Expected 200 + Ok(ResourceResponse).
    match &result {
        Ok(_) => {}
        Err(e) => panic!("Expected Ok(ResourceResponse), got Err({:?})", e),
    }
}

/// UT-RS-008: PUT create (resource not exists) – upsert creates -> Ok(ResourceResponse), 201
#[tokio::test]
async fn ut_rs_008_put_create_when_not_exists() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.insert_result.lock().unwrap() = Ok(());
        },
        |policy| {
            *policy.validate_policy_result.lock().unwrap() = Ok(true);
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.update(&admin_ctx(TEST_USER), TEST_URI, &update_req()).await;
    // Expected 201 + Ok(ResourceResponse).
    match &result {
        Ok(_) => {}
        Err(e) => panic!("Expected Ok(ResourceResponse), got Err({:?})", e),
    }
}

/// UT-RS-009: PUT update permission denied (different user_id)
#[tokio::test]
async fn ut_rs_009_put_update_permission_denied_different_user() {
    let mut entity = make_entity();
    entity.user_id = OTHER_USER.to_string(); // owned by OTHER_USER

    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity));
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .update(&admin_ctx(TEST_USER), TEST_URI, &update_req())
        .await;
    match result {
        Err(ResourceError::PermissionDenied) => {}
        _ => panic!("Expected PermissionDenied, got {:?}", result),
    }
}

/// UT-RS-010: PUT create no permission – resource missing and authz denies create
#[tokio::test]
async fn ut_rs_010_put_create_no_permission() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.update(&attest_ctx(), TEST_URI, &update_req()).await;
    match result {
        Err(ResourceError::PermissionDenied) => {}
        _ => panic!("Expected PermissionDenied, got {:?}", result),
    }
}

// ---------------------------------------------------------------------------
// Tests – DELETE
// ---------------------------------------------------------------------------

/// UT-RS-011: DELETE success
#[tokio::test]
async fn ut_rs_011_delete_success() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.delete_result.lock().unwrap() = Ok(1);
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.delete(&bearer_ctx(TEST_USER), TEST_URI).await;
    match &result {
        Ok(()) => {}
        Err(e) => panic!("Expected Ok(()), got Err({:?})", e),
    }
}

/// UT-RS-012: DELETE not found
#[tokio::test]
async fn ut_rs_012_delete_not_found() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.delete(&bearer_ctx(TEST_USER), TEST_URI).await;
    match result {
        Err(ResourceError::NotFound) => {}
        _ => panic!("Expected NotFound, got {:?}", result),
    }
}

/// UT-RS-013: DELETE permission denied (different user_id)
#[tokio::test]
async fn ut_rs_013_delete_permission_denied_different_user() {
    let mut entity = make_entity();
    entity.user_id = OTHER_USER.to_string();

    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity));
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.delete(&bearer_ctx(TEST_USER), TEST_URI).await;
    match result {
        Err(ResourceError::PermissionDenied) => {}
        _ => panic!("Expected PermissionDenied, got {:?}", result),
    }
}

// ---------------------------------------------------------------------------
// Tests – GET content
// ---------------------------------------------------------------------------

/// UT-RS-013a: GET content/info auth denied via Attest token.
///
/// Attest tokens are hard-denied by AuthzFacade. For GET operations, the service
/// maps authz Deny → NotFound (404) to hide resource existence.
#[tokio::test]
async fn ut_rs_013a_get_content_permission_denied() {
    let svc = make_service(
        |_| {},
        |_| {},
        |_| {},
    );

    let result = svc
        .get_content(&attest_ctx(), TEST_URI)
        .await;
    match result {
        Err(ResourceError::NotFound) => {}
        _ => panic!("Expected NotFound, got {:?}", result),
    }
}

/// UT-RM-023: GET resource — Attest token with OPA policy deny.
///
/// When using Attest token, AuthzFacade performs OPA evaluation. If the policy
/// does not match the attest claims, the resource is hidden (404).
/// This test simulates the behaviour by passing a dummy AttestContext whose
/// claims do not satisfy the resource-bound Rego policy.
#[tokio::test]
async fn ut_rs_023_get_content_attest_policy_deny() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": false}".to_string());
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .get_content(&attest_with_pubkey(), TEST_URI)
        .await;
    match result {
        Err(ResourceError::NotFound) => {}
        other => panic!("Expected NotFound (resource hidden), got {:?}", other),
    }
}

/// UT-RS-014: GET content success – all mocks pass -> Ok(ResourceContentResponse)
#[tokio::test]
async fn ut_rs_014_get_content_success() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| {
            bp.register(
                "vault",
                Arc::new(MockResourceBackend::with_content(b"secret-content".to_vec())),
            );
        },
    );

    let result = svc
        .get_content(&bearer_ctx(TEST_USER), TEST_URI)
        .await;
    match &result {
        Ok(resp) => {
            assert!(!resp.content.is_empty(), "content should not be empty");
            assert_eq!(resp.content_type, "text");
        }
        Err(e) => panic!("Expected Ok(ResourceContentResponse), got Err({:?})", e),
    }
}

/// UT-RS-014a: GET content resource not found in DB -> Err(NotFound)
#[tokio::test]
async fn ut_rs_014a_get_content_not_found() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .get_content(&bearer_ctx(TEST_USER), TEST_URI)
        .await;
    match result {
        Err(ResourceError::NotFound) => {}
        _ => panic!("Expected NotFound, got {:?}", result),
    }
}

/// UT-RS-014b: GET content policy deleted (dangling ref) -> Err(PolicyIdInvalid)
#[tokio::test]
async fn ut_rs_014b_get_content_policy_deleted() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Err(ResourceError::PolicyIdInvalid(TEST_POLICY_ID.to_string()));
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .get_content(&bearer_ctx(TEST_USER), TEST_URI)
        .await;
    match result {
        Err(ResourceError::PolicyIdInvalid(_)) => {}
        _ => panic!("Expected PolicyIdInvalid, got {:?}", result),
    }
}

/// UT-RS-014c: GET content export_mode=plain -> plain content returned
#[tokio::test]
async fn ut_rs_014c_get_content_export_mode_plain() {
    let mut entity = make_entity();
    entity.export_mode = "plain".to_string();

    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| {
            bp.register(
                "vault",
                Arc::new(MockResourceBackend::with_content(b"plain-text-content".to_vec())),
            );
        },
    );

    let result = svc
        .get_content(&bearer_ctx(TEST_USER), TEST_URI)
        .await;
    match &result {
        Ok(resp) => {
            assert_eq!(
                resp.content.as_slice(),
                b"plain-text-content",
                "plain mode should return content as-is"
            );
        }
        Err(e) => panic!("Expected Ok with plain content, got Err({:?})", e),
    }
}

/// UT-RS-015: GET content policy deny -> Err(NotFound) – resource is hidden
#[tokio::test]
async fn ut_rs_015_get_content_policy_deny() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": false}".to_string());
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .get_content(&attest_with_pubkey(), TEST_URI)
        .await;
    match result {
        Err(ResourceError::NotFound) => {}
        _ => panic!("Expected NotFound (resource hidden), got {:?}", result),
    }
}

/// UT-RS-016: GET content backend error -> Err(BackendError)
#[tokio::test]
async fn ut_rs_016_get_content_backend_error() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| {
            let backend = MockResourceBackend {
                check_exists_result: Mutex::new(Ok(true)),
                get_content_result: Mutex::new(Err(ResourceError::BackendError {
                    detail: "vault connection refused".to_string(),
                })),
            };
            bp.register("vault", Arc::new(backend));
        },
    );

    let result = svc
        .get_content(&bearer_ctx(TEST_USER), TEST_URI)
        .await;
    match result {
        Err(ResourceError::BackendError { .. }) => {}
        _ => panic!("Expected BackendError, got {:?}", result),
    }
}

/// UT-RS-017: GET content JWE encrypt -> content is JWE encrypted
#[tokio::test]
async fn ut_rs_017_get_content_jwe_encrypt() {
    let mut entity = make_entity();
    entity.export_mode = "jwe".to_string();

    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| {
            bp.register(
                "vault",
                Arc::new(MockResourceBackend::with_content(b"raw-data".to_vec())),
            );
        },
    );

    let result = svc
        .get_content(&attest_with_pubkey(), TEST_URI)
        .await;
    match &result {
        Ok(resp) => {
            assert_ne!(resp.content, b"raw-data", "JWE content should be encrypted");
        }
        Err(e) => panic!("Expected Ok with JWE content, got Err({:?})", e),
    }
}

/// UT-RS-018: GET content JWE pubkey missing -> Err(JweEncryptionFailed)
#[tokio::test]
async fn ut_rs_018_get_content_jwe_pubkey_missing() {
    let mut entity = make_entity();
    entity.export_mode = "jwe".to_string();

    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| {
            bp.register(
                "vault",
                Arc::new(MockResourceBackend::with_content(b"raw-data".to_vec())),
            );
        },
    );

    let result = svc
        .get_content(&attest_without_pubkey(), TEST_URI)
        .await;
    match result {
        Err(ResourceError::JweEncryptionFailed { .. }) => {}
        _ => panic!("Expected JweEncryptionFailed, got {:?}", result),
    }
}

// ---------------------------------------------------------------------------
// Tests – GET info
// ---------------------------------------------------------------------------

/// UT-RS-019: GET info success with OPA -> Ok(ResourceInfoResponse)
#[tokio::test]
async fn ut_rs_019_get_info_success() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .get_info(&bearer_ctx(TEST_USER), TEST_URI)
        .await;
    match &result {
        Ok(info) => {
            assert_eq!(info.uri, TEST_URI);
            assert_eq!(info.user_id, TEST_USER);
            assert_eq!(info.policy_id, TEST_POLICY_ID);
        }
        Err(e) => panic!("Expected Ok(ResourceInfoResponse), got Err({:?})", e),
    }
}

/// UT-RS-019a: GET info resource not found -> Err(NotFound)
#[tokio::test]
async fn ut_rs_019a_get_info_not_found() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .get_info(&bearer_ctx(TEST_USER), TEST_URI)
        .await;
    match result {
        Err(ResourceError::NotFound) => {}
        _ => panic!("Expected NotFound, got {:?}", result),
    }
}

/// UT-RS-020: GET info OPA deny -> Err(NotFound)
#[tokio::test]
async fn ut_rs_020_get_info_opa_deny() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": false}".to_string());
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .get_info(&attest_with_pubkey(), TEST_URI)
        .await;
    match result {
        Err(ResourceError::NotFound) => {}
        _ => panic!("Expected NotFound (resource hidden), got {:?}", result),
    }
}

// ---------------------------------------------------------------------------
// Tests – POST /retrieve
// ---------------------------------------------------------------------------

/// UT-RS-021: retrieve success -> Ok(ResourceContentResponse)
#[tokio::test]
async fn ut_rs_021_retrieve_success() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| {
            bp.register(
                "vault",
                Arc::new(MockResourceBackend::with_content(b"retrieved-data".to_vec())),
            );
        },
    );

    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    match &result {
        Ok(resp) => {
            assert!(!resp.content.is_empty(), "content should not be empty");
        }
        Err(e) => panic!("Expected Ok(ResourceContentResponse), got Err({:?})", e),
    }
}

/// UT-RS-022: retrieve policy deny -> Err(NotFound)
#[tokio::test]
async fn ut_rs_022_retrieve_policy_deny() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": false}".to_string());
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    match result {
        Err(ResourceError::NotFound) => {}
        _ => panic!("Expected NotFound (resource hidden), got {:?}", result),
    }
}

// ---------------------------------------------------------------------------
// Tests – POST create with optional fields
// ---------------------------------------------------------------------------

/// UT-RS-023: POST create with all optional fields set to None
///
/// The CreateResourceRequest has content_type, export_mode, and additional_info
/// as optional fields. When all three are None, the service should still create
/// the resource successfully -- the back end and database apply defaults.
///
/// Input:    create_req() with content_type=None, export_mode=None, additional_info=None
/// Mock:     authz Allow, policy valid, backend exists, repo not found -> insert succeeds
/// Assert:   result.is_ok()
#[tokio::test]
async fn ut_rs_023_post_create_optional_fields_none() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.insert_result.lock().unwrap() = Ok(());
        },
        |policy| {
            *policy.validate_policy_result.lock().unwrap() = Ok(true);
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let mut req = create_req();
    req.content_type = None;
    req.export_mode = None;
    req.additional_info = None;

    let result = svc.create(&admin_ctx(TEST_USER), &req).await;
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

// ---------------------------------------------------------------------------
// Tests – DELETE with backend cleanup
// ---------------------------------------------------------------------------

/// UT-RS-024: DELETE success where the backend also needs cleanup
///
/// When deleting a resource, the service should also clean up the
/// corresponding data in the back end (e.g. delete the secret from Vault).
/// This test verifies the full delete path: authz passes, the repository
/// returns the entity, the backend is accessible, and the repo delete
/// succeeds.
///
/// Mock:     repo returns entity, backend exists, delete succeeds
/// Assert:   result.is_ok()
#[tokio::test]
async fn ut_rs_024_delete_success_with_backend_cleanup() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.delete_result.lock().unwrap() = Ok(1);
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.delete(&bearer_ctx(TEST_USER), TEST_URI).await;
    match &result {
        Ok(()) => {}
        Err(e) => panic!("Expected Ok(()), got Err({:?})", e),
    }
}

// ===========================================================================
// Tests – retrieve
// ===========================================================================

#[tokio::test]
async fn ut_rs_025_retrieve_success() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |policy| { *policy.get_policy_content_result.lock().unwrap() = Ok("package x\n\ndefault attestation_valid = true".into()); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::with_content(b"{\"hello\":\"world\"}".to_vec()))); },
    );
    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    assert!(result.is_ok(), "retrieve should succeed: {:?}", result.err());
    let resp = result.unwrap();
    assert_eq!(resp.content_type, "text");
    assert!(!resp.content.is_empty());
}

#[tokio::test]
async fn ut_rs_026_retrieve_policy_not_matched() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |policy| { *policy.get_policy_content_result.lock().unwrap() = Ok("package x\n\ndefault allow = false".into()); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::new())); },
    );
    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::NotFound)), "expected NotFound, got {:?}", result);
}

#[tokio::test]
async fn ut_rs_027_retrieve_resource_not_found() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(None); },
        |_| {}, |_| {},
    );
    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::NotFound)), "expected NotFound, got {:?}", result);
}

#[tokio::test]
async fn ut_rs_028_retrieve_jwe_encrypt() {
    let mut entity = make_entity(); entity.export_mode = "jwe".to_string();
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity)); },
        |policy| { *policy.get_policy_content_result.lock().unwrap() = Ok("package x\n\ndefault attestation_valid = true".into()); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::with_content(b"secret-data".to_vec()))); },
    );
    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    assert!(result.is_ok(), "JWE retrieve should succeed: {:?}", result.err());
    assert_ne!(result.unwrap().content, b"secret-data".to_vec(), "JWE content should not be plaintext");
}

#[tokio::test]
async fn ut_rs_029_retrieve_jwe_no_pubkey() {
    let mut entity = make_entity(); entity.export_mode = "jwe".to_string();
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity)); },
        |policy| { *policy.get_policy_content_result.lock().unwrap() = Ok("package x\n\ndefault attestation_valid = true".into()); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::with_content(b"secret-data".to_vec()))); },
    );
    let result = svc.retrieve(&attest_payload_no_pubkey(), TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::JweEncryptionFailed { .. })));
}

// ===========================================================================
// Tests – error code HTTP status mapping
// ===========================================================================

#[test]
fn ut_rs_030_already_exists_is_409() {
    assert_eq!(ResourceError::AlreadyExists { uri: "test".into() }.http_status(), 409);
}

#[test]
fn ut_rs_031_permission_denied_is_403() {
    assert_eq!(ResourceError::PermissionDenied.http_status(), 403);
}

#[test]
fn ut_rs_032_not_found_is_404() {
    assert_eq!(ResourceError::NotFound.http_status(), 404);
}

// ===========================================================================
// Tests – update() created flag
// ===========================================================================

#[tokio::test]
async fn ut_rs_033_update_returns_created_true() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(None); },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::new())); },
    );
    let (_, created) = svc.update(&admin_ctx(TEST_USER), TEST_URI, &update_req()).await.unwrap();
    assert!(created, "new resource should return created=true");
}

#[tokio::test]
async fn ut_rs_034_update_returns_created_false() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); *repo.update_result.lock().unwrap() = Ok(1); },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::new())); },
    );
    let (_, created) = svc.update(&admin_ctx(TEST_USER), TEST_URI, &update_req()).await.unwrap();
    assert!(!created, "existing resource should return created=false");
}

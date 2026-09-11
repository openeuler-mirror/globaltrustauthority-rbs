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
use base64::Engine;
use serde_json::json;
use zeroize::Zeroizing;

use rbs_core::auth::authz::{Action, AuthzError, RequiredRole};
use rbs_core::auth::authz_checker::AuthzChecker;
use rbs_core::auth::context::{AttestContext, AuthContext, BearerContext, TokenType};
use rbs_core::resource::adapter::{BackendCapabilities, BackendProvider, PolicyClient, ResourceBackend};
use rbs_core::resource::error::ResourceError;
use rbs_core::resource::repository::{ResourceEntity, ResourceRepository};
use rbs_core::resource::{
    CreateResourceRequest, UpdateResourceRequest,
};
use rbs_core::resource::service::{ResourceQuery, ResourceService};
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
    list_by_user_result: Mutex<MockResult<(Vec<ResourceEntity>, u64)>>,
    count_by_user_result: Mutex<MockResult<usize>>,
    create_with_limit_check_result: Mutex<MockResult<()>>,
    find_by_policy_id_result: Mutex<MockResult<Vec<ResourceEntity>>>,
    // Call counters
    delete_call_count: Mutex<u32>,
    create_with_limit_check_call_count: Mutex<u32>,
    update_call_count: Mutex<u32>,
}

#[allow(dead_code)]
impl MockResourceRepository {
    fn new() -> Self {
        Self {
            insert_result: Mutex::new(Ok(())),
            find_by_uri_result: Mutex::new(Ok(None)),
            update_result: Mutex::new(Ok(1)),
            delete_result: Mutex::new(Ok(1)),
            list_by_user_result: Mutex::new(Ok((vec![], 0))),
            count_by_user_result: Mutex::new(Ok(0)),
            create_with_limit_check_result: Mutex::new(Ok(())),
            find_by_policy_id_result: Mutex::new(Ok(vec![])),
            delete_call_count: Mutex::new(0),
            create_with_limit_check_call_count: Mutex::new(0),
            update_call_count: Mutex::new(0),
        }
    }

    fn delete_call_count(&self) -> u32 {
        *self.delete_call_count.lock().unwrap()
    }

    fn create_with_limit_check_call_count(&self) -> u32 {
        *self.create_with_limit_check_call_count.lock().unwrap()
    }

    fn update_call_count(&self) -> u32 {
        *self.update_call_count.lock().unwrap()
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

    async fn update(&self, _uri: &str, _entity: &ResourceEntity, _old_update_time: i64) -> MockResult<u64> {
        *self.update_call_count.lock().unwrap() += 1;
        self.update_result.lock().unwrap().clone()
    }

    async fn delete(&self, _uri: &str, _username: &str) -> MockResult<u64> {
        *self.delete_call_count.lock().unwrap() += 1;
        self.delete_result.lock().unwrap().clone()
    }

    async fn list_by_user(
        &self, _username: &str, _offset: i64, _limit: i64,
    ) -> MockResult<(Vec<ResourceEntity>, u64)> {
        self.list_by_user_result.lock().unwrap().clone()
    }

    async fn count_by_user(&self, _username: &str) -> MockResult<usize> {
        self.count_by_user_result.lock().unwrap().clone()
    }

    async fn create_with_user_limit_check(
        &self, _uri: &str, _entity: &ResourceEntity, _max_per_user: usize,
    ) -> MockResult<()> {
        *self.create_with_limit_check_call_count.lock().unwrap() += 1;
        self.create_with_limit_check_result.lock().unwrap().clone()
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
    async fn validate_policy(&self, _policy_id: &str, _username: &str) -> MockResult<bool> {
        self.validate_policy_result.lock().unwrap().clone()
    }

    async fn get_policy_content(&self, _policy_id: &str) -> MockResult<String> {
        self.get_policy_content_result.lock().unwrap().clone()
    }

    async fn relation_res_ids(&self, _policy_id: &str, _username: &str) -> MockResult<Vec<String>> {
        self.relation_res_ids_result.lock().unwrap().clone()
    }
}

// ---------- MockResourceBackend ----------

use std::sync::atomic::{AtomicU32, Ordering};

struct MockResourceBackend {
    capabilities: Mutex<BackendCapabilities>,
    get_content_result: Mutex<MockResult<Zeroizing<Vec<u8>>>>,
    put_result: Mutex<MockResult<()>>,
    delete_result: Mutex<MockResult<()>>,
    check_exists_result: Mutex<MockResult<bool>>,
    // Call counters
    put_call_count: Mutex<u32>,
    delete_call_count: Mutex<u32>,
    check_exists_call_count: Mutex<u32>,
    get_content_call_count: Mutex<u32>,
    // Capture last put content for zeroize verification
    last_put_content: Mutex<Option<Vec<u8>>>,
    // Sequence counter for order verification
    seq_counter: AtomicU32,
}

#[allow(dead_code)]
impl MockResourceBackend {
    fn new() -> Self {
        Self {
            capabilities: Mutex::new(BackendCapabilities::PUT | BackendCapabilities::DELETE | BackendCapabilities::CHECK),
            get_content_result: Mutex::new(Ok(Zeroizing::new(vec![]))),
            put_result: Mutex::new(Ok(())),
            delete_result: Mutex::new(Ok(())),
            check_exists_result: Mutex::new(Ok(true)),
            put_call_count: Mutex::new(0),
            delete_call_count: Mutex::new(0),
            check_exists_call_count: Mutex::new(0),
            get_content_call_count: Mutex::new(0),
            last_put_content: Mutex::new(None),
            seq_counter: AtomicU32::new(0),
        }
    }

    fn with_content(content: Vec<u8>) -> Self {
        Self {
            get_content_result: Mutex::new(Ok(Zeroizing::new(content))),
            ..Self::new()
        }
    }

    fn with_capabilities(self, caps: BackendCapabilities) -> Self {
        *self.capabilities.lock().unwrap() = caps;
        self
    }

    fn with_put_result(self, result: MockResult<()>) -> Self {
        *self.put_result.lock().unwrap() = result;
        self
    }

    fn with_delete_result(self, result: MockResult<()>) -> Self {
        *self.delete_result.lock().unwrap() = result;
        self
    }

    fn with_check_exists_result(self, result: MockResult<bool>) -> Self {
        *self.check_exists_result.lock().unwrap() = result;
        self
    }

    fn put_call_count(&self) -> u32 {
        *self.put_call_count.lock().unwrap()
    }

    fn delete_call_count(&self) -> u32 {
        *self.delete_call_count.lock().unwrap()
    }

    fn check_exists_call_count(&self) -> u32 {
        *self.check_exists_call_count.lock().unwrap()
    }

    fn get_content_call_count(&self) -> u32 {
        *self.get_content_call_count.lock().unwrap()
    }

    fn last_put_content_zeroized(&self) -> bool {
        self.last_put_content.lock().unwrap()
            .as_ref()
            .map(|c| c.iter().all(|&b| b == 0u8))
            .unwrap_or(false)
    }
}

#[async_trait]
impl ResourceBackend for MockResourceBackend {
    fn capabilities(&self) -> BackendCapabilities {
        *self.capabilities.lock().unwrap()
    }

    async fn get_resource_content(
        &self,
        _desc: &rbs_api_types::ResourceDesc,
        _opts: rbs_api_types::GetResourceOptions,
    ) -> MockResult<Zeroizing<Vec<u8>>> {
        *self.get_content_call_count.lock().unwrap() += 1;
        self.get_content_result.lock().unwrap().clone()
    }

    async fn put_resource_content(
        &self,
        _desc: &rbs_api_types::ResourceDesc,
        data: &[u8],
    ) -> MockResult<()> {
        *self.put_call_count.lock().unwrap() += 1;
        self.seq_counter.store(self.seq_counter.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        *self.last_put_content.lock().unwrap() = Some(data.to_vec());
        self.put_result.lock().unwrap().clone()
    }

    async fn delete_resource(&self, _desc: &rbs_api_types::ResourceDesc) -> MockResult<()> {
        *self.delete_call_count.lock().unwrap() += 1;
        self.seq_counter.store(self.seq_counter.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        self.delete_result.lock().unwrap().clone()
    }

    async fn check_resource_exists(&self, _desc: &rbs_api_types::ResourceDesc) -> MockResult<bool> {
        *self.check_exists_call_count.lock().unwrap() += 1;
        self.seq_counter.store(self.seq_counter.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        self.check_exists_result.lock().unwrap().clone()
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
        username: TEST_USER.to_string(),
        provider_name: "vault".to_string(),
        repo_name: "default".to_string(),
        res_type: "secret".to_string(),
        res_name: "mykey".to_string(),
        res_info: None,
        created_at: 1000,
        updated_at: 1000,
        content_type: Some("text".to_string()),
        export_mode: "jwe".to_string(),
        policy_id: TEST_POLICY_ID.to_string(),
    }
}

/// Build a default valid `CreateResourceRequest`.
fn create_req() -> CreateResourceRequest {
    CreateResourceRequest {
        policy_id: TEST_POLICY_ID.to_string(),
        content_type: Some("text".to_string()),
        export_mode: Some("jwe".to_string()),
        additional_info: None,
        content: None,
    }
}

/// Build a default valid `UpdateResourceRequest`.
fn update_req() -> UpdateResourceRequest {
    UpdateResourceRequest {
        policy_id: Some(TEST_POLICY_ID.to_string()),
        content_type: Some("text".to_string()),
        export_mode: Some("jwe".to_string()),
        additional_info: None,
        content: None,
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

/// Attestation context used for retrieve calls (nested attester_data.runtime_data.tee-pubkey).
fn attest_payload() -> AttestContext {
    AttestContext {
        claims: json!({
            "nonce": "abc123",
            "attester_data": {"runtime_data": {"tee-pubkey": EC_P256_JWK}}
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

/// Attestation context with tee-pubkey at attester_data top level (no runtime_data nesting).
/// Exercises the retrieve fallback path: claims["attester_data"]["tee-pubkey"].
fn attest_payload_top_level_pubkey() -> AttestContext {
    AttestContext {
        claims: json!({
            "nonce": "abc123",
            "attester_data": {"tee-pubkey": EC_P256_JWK}
        }),
        token_type: TokenType::Attest,
    }
}

/// Attest AuthContext with tee-pubkey (nested: attester_data.runtime_data.tee-pubkey).
fn attest_with_pubkey() -> AuthContext {
    AuthContext::Attest(AttestContext {
        claims: json!({
            "nonce": "abc123",
            "attester_data": {"runtime_data": {"tee-pubkey": EC_P256_JWK}}
        }),
        token_type: TokenType::Attest,
    })
}

/// Attest AuthContext without tee-pubkey — for JWE missing-key tests.
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
    /// When set, `check_resource_get` returns `PolicyEvaluationFailed` with this
    /// detail — simulates a resource-bound Rego policy that cannot be evaluated.
    eval_error: Mutex<Option<String>>,
}

impl MockAuthzChecker {
    fn new() -> Self {
        Self { deny_all: Mutex::new(false), eval_error: Mutex::new(None) }
    }
    #[allow(dead_code)]
    fn with_deny(self) -> Self { *self.deny_all.lock().unwrap() = true; self }
    #[allow(dead_code)]
    fn with_eval_error(self, detail: &str) -> Self {
        *self.eval_error.lock().unwrap() = Some(detail.to_string());
        self
    }
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
    async fn check_resource_get(&self, ctx: &AuthContext, _owner: &str, policy: &str, _res_provider: Option<&str>) -> Result<(), AuthzError> {
        if let Some(detail) = self.eval_error.lock().unwrap().clone() {
            return Err(AuthzError::PolicyEvaluationFailed(detail));
        }
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
    make_service_with_authz(|_| {}, configure_repo, configure_policy, configure_backend)
}

/// Like `make_service`, but also allows configuring the `AuthzChecker` mock
/// (e.g. to inject `PolicyEvaluationFailed`).
fn make_service_with_authz(
    configure_authz: impl FnOnce(&MockAuthzChecker),
    configure_repo: impl FnOnce(&MockResourceRepository),
    configure_policy: impl FnOnce(&MockPolicyClient),
    configure_backend: impl FnOnce(&mut BackendProvider),
) -> ResourceService {
    let config = ResourceConfig::default();
    let validator = ResourceValidator::new(config);
    let repo = MockResourceRepository::new(); configure_repo(&repo);
    let policy = MockPolicyClient::new(); configure_policy(&policy);
    let mut bp = BackendProvider::new(); configure_backend(&mut bp);
    let authz = MockAuthzChecker::new(); configure_authz(&authz);
    ResourceService::new(Arc::new(repo), Arc::new(authz), bp, Arc::new(policy), validator)
}

/// Build a service with a custom ResourceConfig (for multi-backend tests).
fn make_service_with_config(
    config: ResourceConfig,
    configure_repo: impl FnOnce(&MockResourceRepository),
    configure_policy: impl FnOnce(&MockPolicyClient),
    configure_backend: impl FnOnce(&mut BackendProvider),
) -> ResourceService {
    let validator = ResourceValidator::new(config);
    let repo = MockResourceRepository::new(); configure_repo(&repo);
    let policy = MockPolicyClient::new(); configure_policy(&policy);
    let mut bp = BackendProvider::new(); configure_backend(&mut bp);
    let authz: Arc<dyn AuthzChecker> = Arc::new(MockAuthzChecker::new());
    ResourceService::new(Arc::new(repo), authz, bp, Arc::new(policy), validator)
}

/// Config supporting vault, hsm, and ca backends with their resource types.
fn test_config() -> ResourceConfig {
    use std::collections::HashMap;
    ResourceConfig {
        max_per_user: 10,
        max_resource_name_len: 32,
        max_repo_name_len: 32,
        max_additional_info_len: 512,
        per_backend_allowed_types: HashMap::from([
            ("vault".to_string(), vec!["secret".to_string(), "cert".to_string()]),
            ("hsm".to_string(), vec!["key".to_string(), "secret".to_string()]),
            ("ca".to_string(), vec!["certificate".to_string(), "cert".to_string()]),
        ]),
        allowed_content_types: vec![
            "jwt".to_string(), "json".to_string(), "text".to_string(),
            "binary".to_string(), "jwk".to_string(), "jwe".to_string(),
        ],
        allowed_export_modes: vec!["jwe".to_string()],
        configured_backends: vec!["vault".to_string(), "hsm".to_string(), "ca".to_string()],
    }
}

// ---------------------------------------------------------------------------
// Tests – POST /create
// ---------------------------------------------------------------------------

/// UT-RS-001: POST create success – all mocks pass -> Ok(ResourceResponse)
#[tokio::test]
async fn test_post_create_success() {
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

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &create_req()).await;
    // When the service is implemented this should be Ok(_).
    let _ = result;
}

/// UT-RS-002: POST create permission denied – authz returns Deny
#[tokio::test]
async fn test_post_create_permission_denied() {
    let svc = make_service(
        |_| {},
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.create(&attest_ctx(), TEST_URI, &create_req()).await;
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
async fn test_post_create_policy_use_denied() {
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
        .create(&admin_ctx(TEST_USER), TEST_URI, &create_req())
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
async fn test_post_create_policy_invalid() {
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

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &create_req()).await;
    match result {
        Err(ResourceError::PolicyIdInvalid(_)) => {}
        _ => panic!("Expected PolicyIdInvalid, got {:?}", result),
    }
}

/// UT-RS-005: POST create backend not found – BackendProvider.get_backend returns None
#[tokio::test]
async fn test_post_create_backend_not_found() {
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

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &create_req()).await;
    match result {
        Err(ResourceError::BackendUnsupported { provider }) if provider == "vault" => {}
        _ => panic!("Expected BackendUnsupported for 'vault', got {:?}", result),
    }
}

/// UT-RS-006: POST create already exists – atomic create returns AlreadyExists
#[tokio::test]
async fn test_post_create_already_exists() {
    let svc = make_service(
        |repo| {
            *repo.create_with_limit_check_result.lock().unwrap() =
                Err(ResourceError::AlreadyExists { uri: TEST_URI.to_string() });
        },
        |_| {},
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &create_req()).await;
    match result {
        Err(ResourceError::AlreadyExists { .. }) => {}
        _ => panic!("Expected AlreadyExists, got {:?}", result),
    }
}

/// UT-RS-006a: POST create missing required field (empty policy_id) -> Err(ParamInvalid)
#[tokio::test]
async fn test_post_create_empty_policy_id() {
    let svc = make_service(
        |_| {},
        |_| {},
        |_| {},
    );

    let mut req = create_req();
    req.policy_id.clear();

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &req).await;
    match result {
        Err(ResourceError::ParamInvalid { field }) if field == "policy_id" => {}
        _ => panic!("Expected ParamInvalid for policy_id, got {:?}", result),
    }
}

/// UT-RS-006b: POST create backend provider unknown -> Err(BackendUnsupported)
#[tokio::test]
async fn test_post_create_unknown_provider() {
    let svc = make_service(
        |_| {},
        |_| {},
        |_| {},
    );

    let req = create_req();

    let result = svc.create(&admin_ctx(TEST_USER), "/rbs/v0/unknown/default/secret/mykey", &req).await;
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
async fn test_put_update_success() {
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
async fn test_put_create_when_not_exists() {
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

/// UT-RS-007a: POST create count exceeded – atomic create returns CountExceed
#[tokio::test]
async fn test_post_create_count_exceeded() {
    let svc = make_service(
        |repo| {
            *repo.create_with_limit_check_result.lock().unwrap() =
                Err(ResourceError::CountExceed { max: 10, current: 10 });
        },
        |policy| {
            *policy.validate_policy_result.lock().unwrap() = Ok(true);
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &create_req()).await;
    match result {
        Err(ResourceError::CountExceed { max, current }) => {
            assert_eq!(max, 10);
            assert_eq!(current, 10);
        }
        other => panic!("Expected CountExceed, got {:?}", other),
    }
}

/// UT-RS-007b: POST create under limit – atomic create returns Ok -> Ok
#[tokio::test]
async fn test_post_create_count_below_limit_ok() {
    let svc = make_service(
        |repo| {
            *repo.create_with_limit_check_result.lock().unwrap() = Ok(());
        },
        |policy| {
            *policy.validate_policy_result.lock().unwrap() = Ok(true);
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &create_req()).await;
    match result {
        Ok(_) => {}
        Err(e) => panic!("Expected Ok, got Err({:?})", e),
    }
}

/// UT-RS-007c: PUT upsert-create count exceeded – atomic create returns CountExceed
#[tokio::test]
async fn test_put_create_count_exceeded() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.create_with_limit_check_result.lock().unwrap() =
                Err(ResourceError::CountExceed { max: 10, current: 10 });
        },
        |policy| {
            *policy.validate_policy_result.lock().unwrap() = Ok(true);
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.update(&admin_ctx(TEST_USER), TEST_URI, &update_req()).await;
    match result {
        Err(ResourceError::CountExceed { max, current }) => {
            assert_eq!(max, 10);
            assert_eq!(current, 10);
        }
        other => panic!("Expected CountExceed, got {:?}", other),
    }
}

/// UT-RS-009: PUT update permission denied (different user_id)
#[tokio::test]
async fn test_put_update_permission_denied_different_user() {
    let mut entity = make_entity();
    entity.username = OTHER_USER.to_string(); // owned by OTHER_USER

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
async fn test_put_create_no_permission() {
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
// Tests – PUT /update with omitted policy_id (keeps existing binding)
// ---------------------------------------------------------------------------

/// UT-RS-010a: PUT update with `policy_id: None` on an existing resource keeps the
/// existing binding and still succeeds (the existing policy is re-validated).
#[tokio::test]
async fn test_put_update_none_policy_keeps_existing_binding() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.update_result.lock().unwrap() = Ok(1);
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::new())); },
    );

    let mut req = update_req();
    req.policy_id = None;

    let result = svc.update(&admin_ctx(TEST_USER), TEST_URI, &req).await;
    match &result {
        Ok(_) => {}
        Err(e) => panic!("Expected Ok with kept binding, got Err({:?})", e),
    }
}

/// UT-RS-010b: PUT update with `policy_id: None` still validates the existing
/// binding — when `validate_policy` returns false, the update is rejected with
/// `PolicyIdInvalid`, proving the kept binding is enforced.
#[tokio::test]
async fn test_put_update_none_policy_validates_existing_binding() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(false); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::new())); },
    );

    let mut req = update_req();
    req.policy_id = None;

    let result = svc.update(&admin_ctx(TEST_USER), TEST_URI, &req).await;
    match result {
        Err(ResourceError::PolicyIdInvalid(_)) => {}
        other => panic!("Expected PolicyIdInvalid, got {:?}", other),
    }
}

/// UT-RS-010c: PUT update with `policy_id: None` on a non-existent resource
/// (upsert create path) is rejected — a brand-new resource requires an explicit policy.
#[tokio::test]
async fn test_put_update_none_policy_new_resource_rejected() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(None); },
        |_| {},
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::new())); },
    );

    let mut req = update_req();
    req.policy_id = None;

    let result = svc.update(&admin_ctx(TEST_USER), TEST_URI, &req).await;
    match result {
        Err(ResourceError::ParamInvalid { field }) if field == "policy_id" => {}
        other => panic!("Expected ParamInvalid {{ policy_id }}, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Tests – DELETE
// ---------------------------------------------------------------------------

/// UT-RS-011: DELETE success
#[tokio::test]
async fn test_delete_success() {
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
async fn test_delete_not_found() {
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
async fn test_delete_permission_denied_different_user() {
    let mut entity = make_entity();
    entity.username = OTHER_USER.to_string();

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
/// maps authz Deny → NotFoundOrDenied (404) to hide resource existence; the body
/// names both causes since it is identical for genuinely missing resources too.
#[tokio::test]
async fn test_get_content_permission_denied() {
    let svc = make_service(
        |_| {},
        |_| {},
        |_| {},
    );

    let result = svc
        .get_content(&attest_ctx(), TEST_URI)
        .await;
    match result {
        Err(ResourceError::NotFoundOrDenied) => {}
        _ => panic!("Expected NotFoundOrDenied, got {:?}", result),
    }
}

/// UT-RM-023: GET resource — Attest token with OPA policy deny.
///
/// When using Attest token, AuthzFacade performs OPA evaluation. If the policy
/// does not match the attest claims, the resource is hidden (404).
/// This test simulates the behaviour by passing a dummy AttestContext whose
/// claims do not satisfy the resource-bound Rego policy.
#[tokio::test]
async fn test_get_content_attest_policy_deny() {
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
        Err(ResourceError::NotFoundOrDenied) => {}
        other => panic!("Expected NotFound (resource hidden), got {:?}", other),
    }
}

/// UT-RS-014: GET content success – all mocks pass -> Ok(ResourceContentResponse)
#[tokio::test]
async fn test_get_content_success() {
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
        .get_content(&attest_with_pubkey(), TEST_URI)
        .await;
    match &result {
        Ok(resp) => {
            assert!(!resp.content.is_empty(), "content should not be empty");
            assert_eq!(resp.content_type.as_deref(), Some("text"));
            assert_eq!(resp.export_mode, "jwe");
        }
        Err(e) => panic!("Expected Ok(ResourceContentResponse), got Err({:?})", e),
    }
}

/// UT-RS-014a: GET content resource not found in DB -> Err(NotFound)
#[tokio::test]
async fn test_get_content_not_found() {
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
        Err(ResourceError::NotFoundOrDenied) => {}
        _ => panic!("Expected NotFound, got {:?}", result),
    }
}

/// UT-RS-014b: GET content policy deleted (dangling ref) -> Err(PolicyIdInvalid)
#[tokio::test]
async fn test_get_content_policy_deleted() {
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

/// UT-RS-015: GET content policy deny -> Err(NotFound) – resource is hidden
#[tokio::test]
async fn test_get_content_policy_deny() {
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
        Err(ResourceError::NotFoundOrDenied) => {}
        _ => panic!("Expected NotFound (resource hidden), got {:?}", result),
    }
}

/// UT-RS-015a: GET content policy *evaluation* failure -> Err(PolicyEvaluationFailed).
///
/// An unevaluable Rego policy is a server-side fault (500), not a hidden
/// resource (404).
#[tokio::test]
async fn test_get_content_policy_evaluation_failed() {
    let svc = make_service_with_authz(
        |authz| { *authz.eval_error.lock().unwrap() = Some("rego compile error".to_string()); },
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package broken; result = ((( ".to_string());
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .get_content(&attest_with_pubkey(), TEST_URI)
        .await;
    match result {
        Err(ResourceError::PolicyEvaluationFailed) => {}
        other => panic!("Expected PolicyEvaluationFailed, got {:?}", other),
    }
}

/// UT-RS-016: GET content backend error -> Err(BackendError)
#[tokio::test]
async fn test_get_content_backend_error() {
    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| {
            let backend = MockResourceBackend::new();
            *backend.get_content_result.lock().unwrap() = Err(ResourceError::BackendError {
                detail: "vault connection refused".to_string(),
            });
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
async fn test_get_content_jwe_encrypt() {
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
            assert_ne!(resp.content.as_bytes(), b"raw-data", "JWE content should be encrypted");
            assert_eq!(resp.export_mode, "jwe");
        }
        Err(e) => panic!("Expected Ok with JWE content, got Err({:?})", e),
    }
}

/// UT-RS-018: GET content JWE pubkey missing -> Err(JweEncryptionFailed)
#[tokio::test]
async fn test_get_content_jwe_pubkey_missing() {
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

/// UT-RS-019: GET info success with OPA -> Ok(ResourceResponse)
#[tokio::test]
async fn test_get_info_success() {
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
            assert_eq!(info.policy_id, TEST_POLICY_ID);
        }
        Err(e) => panic!("Expected Ok(ResourceResponse), got Err({:?})", e),
    }
}

/// UT-RS-019a: GET info resource not found -> Err(NotFound)
#[tokio::test]
async fn test_get_info_not_found() {
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
        Err(ResourceError::NotFoundOrDenied) => {}
        _ => panic!("Expected NotFound, got {:?}", result),
    }
}

/// UT-RS-020: GET info OPA deny -> Err(NotFound)
#[tokio::test]
async fn test_get_info_opa_deny() {
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
        Err(ResourceError::NotFoundOrDenied) => {}
        _ => panic!("Expected NotFound (resource hidden), got {:?}", result),
    }
}

/// UT-RS-020a: GET info policy *evaluation* failure -> Err(PolicyEvaluationFailed).
///
/// An unevaluable Rego policy is a server-side fault (500), not a hidden
/// resource (404).
#[tokio::test]
async fn test_get_info_policy_evaluation_failed() {
    let svc = make_service_with_authz(
        |authz| { *authz.eval_error.lock().unwrap() = Some("rego compile error".to_string()); },
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package broken; result = ((( ".to_string());
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc
        .get_info(&attest_with_pubkey(), TEST_URI)
        .await;
    match result {
        Err(ResourceError::PolicyEvaluationFailed) => {}
        other => panic!("Expected PolicyEvaluationFailed, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Tests – GET /resource (user-scoped list)
// ---------------------------------------------------------------------------

/// UT-RS-024: list success -> Ok(ResourceListResponse) with metadata mapping
/// and pagination echo.
#[tokio::test]
async fn test_list_success() {
    let svc = make_service(
        |repo| {
            *repo.list_by_user_result.lock().unwrap() = Ok((vec![make_entity()], 1));
        },
        |_| {},
        |_| {},
    );

    let result = svc
        .list(&bearer_ctx(TEST_USER), &ResourceQuery { offset: 0, limit: 10 })
        .await;
    match &result {
        Ok(resp) => {
            assert_eq!(resp.total_count, 1);
            assert_eq!(resp.limit, 10);
            assert_eq!(resp.offset, 0);
            assert_eq!(resp.items.len(), 1);
            let item = &resp.items[0];
            assert_eq!(item.uri, TEST_URI);
            assert_eq!(item.provider_name, "vault");
            assert_eq!(item.repository_name, "default");
            assert_eq!(item.resource_type, "secret");
            assert_eq!(item.resource_name, "mykey");
            assert_eq!(item.policy_id, TEST_POLICY_ID);
            assert_eq!(item.export_mode, "jwe");
        }
        Err(e) => panic!("Expected Ok(ResourceListResponse), got Err({:?})", e),
    }
}

/// UT-RS-024a: list empty -> Ok with empty items and total_count 0.
#[tokio::test]
async fn test_list_empty() {
    let svc = make_service(
        |repo| {
            *repo.list_by_user_result.lock().unwrap() = Ok((vec![], 0));
        },
        |_| {},
        |_| {},
    );

    let result = svc
        .list(&bearer_ctx(TEST_USER), &ResourceQuery { offset: 0, limit: 10 })
        .await;
    match &result {
        Ok(resp) => {
            assert!(resp.items.is_empty());
            assert_eq!(resp.total_count, 0);
        }
        Err(e) => panic!("Expected Ok(ResourceListResponse), got Err({:?})", e),
    }
}

/// UT-RS-024b: list authz denied -> Err(PermissionDenied) (403, not the
/// anti-enumeration 404 used by single-resource reads).
#[tokio::test]
async fn test_list_permission_denied() {
    let svc = make_service_with_authz(
        |authz| { *authz.deny_all.lock().unwrap() = true; },
        |_| {},
        |_| {},
        |_| {},
    );

    let result = svc
        .list(&bearer_ctx(TEST_USER), &ResourceQuery { offset: 0, limit: 10 })
        .await;
    match result {
        Err(ResourceError::PermissionDenied) => {}
        other => panic!("Expected PermissionDenied, got {:?}", other),
    }
}

/// UT-RS-024c: list with an Attest context -> Err(PermissionDenied): Attest
/// tokens carry no user subject, so the authz check rejects them (the REST
/// middleware also rejects them before the handler runs).
#[tokio::test]
async fn test_list_attest_token_denied() {
    let svc = make_service(|_| {}, |_| {}, |_| {});

    let result = svc
        .list(&attest_ctx(), &ResourceQuery { offset: 0, limit: 10 })
        .await;
    match result {
        Err(ResourceError::PermissionDenied) => {}
        other => panic!("Expected PermissionDenied, got {:?}", other),
    }
}

/// UT-RS-024d: list repo failure -> Err(BackendError) propagates.
#[tokio::test]
async fn test_list_repo_error() {
    let svc = make_service(
        |repo| {
            *repo.list_by_user_result.lock().unwrap() =
                Err(ResourceError::BackendError { detail: "db down".to_string() });
        },
        |_| {},
        |_| {},
    );

    let result = svc
        .list(&bearer_ctx(TEST_USER), &ResourceQuery { offset: 0, limit: 10 })
        .await;
    match result {
        Err(ResourceError::BackendError { .. }) => {}
        other => panic!("Expected BackendError, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Tests – POST /retrieve
// ---------------------------------------------------------------------------

/// UT-RS-021: retrieve success -> Ok(ResourceContentResponse)
#[tokio::test]
async fn test_retrieve_success() {
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
async fn test_retrieve_policy_deny() {
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
        Err(ResourceError::NotFoundOrDenied) => {}
        _ => panic!("Expected NotFound (resource hidden), got {:?}", result),
    }
}

/// UT-RS-022a: retrieve policy *evaluation* failure -> Err(PolicyEvaluationFailed).
///
/// A Rego policy that cannot be evaluated (broken syntax, safe-mode rejection)
/// is a server-side fault and must surface as a 500, not masquerade as a
/// missing resource (404).
#[tokio::test]
async fn test_retrieve_policy_evaluation_failed() {
    let svc = make_service_with_authz(
        |authz| { *authz.eval_error.lock().unwrap() = Some("rego parse error".to_string()); },
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package broken; result = ((( ".to_string());
        },
        |bp| {
            bp.register("vault", Arc::new(MockResourceBackend::new()));
        },
    );

    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    match result {
        Err(ResourceError::PolicyEvaluationFailed) => {}
        other => panic!("Expected PolicyEvaluationFailed, got {:?}", other),
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
async fn test_post_create_optional_fields_none() {
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

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &req).await;
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
async fn test_delete_success_with_backend_cleanup() {
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
async fn test_retrieve_preserves_content_type() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |policy| { *policy.get_policy_content_result.lock().unwrap() = Ok("package x\n\ndefault attestation_valid = true".into()); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::with_content(b"{\"hello\":\"world\"}".to_vec()))); },
    );
    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    assert!(result.is_ok(), "retrieve should succeed: {:?}", result.err());
    let resp = result.unwrap();
    assert_eq!(resp.content_type.as_deref(), Some("text"));
    assert!(!resp.content.is_empty());
}

#[tokio::test]
async fn test_retrieve_policy_not_matched() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |policy| { *policy.get_policy_content_result.lock().unwrap() = Ok("package x\n\ndefault allow = false".into()); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::new())); },
    );
    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::NotFoundOrDenied)), "expected NotFound, got {:?}", result);
}

#[tokio::test]
async fn test_retrieve_resource_not_found() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(None); },
        |_| {}, |_| {},
    );
    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::NotFoundOrDenied)), "expected NotFound, got {:?}", result);
}

#[tokio::test]
async fn test_retrieve_jwe_encrypt() {
    let mut entity = make_entity(); entity.export_mode = "jwe".to_string();
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity)); },
        |policy| { *policy.get_policy_content_result.lock().unwrap() = Ok("package x\n\ndefault attestation_valid = true".into()); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::with_content(b"secret-data".to_vec()))); },
    );
    let result = svc.retrieve(&attest_payload(), TEST_URI).await;
    assert!(result.is_ok(), "JWE retrieve should succeed: {:?}", result.err());
    assert_ne!(result.unwrap().content.as_bytes(), b"secret-data", "JWE content should not be plaintext");
}

#[tokio::test]
async fn test_retrieve_jwe_no_pubkey() {
    let mut entity = make_entity(); entity.export_mode = "jwe".to_string();
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity)); },
        |policy| { *policy.get_policy_content_result.lock().unwrap() = Ok("package x\n\ndefault attestation_valid = true".into()); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::with_content(b"secret-data".to_vec()))); },
    );
    let result = svc.retrieve(&attest_payload_no_pubkey(), TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::JweEncryptionFailed { .. })));
}

/// UT-RS-021b: retrieve success via attester_data top-level tee-pubkey (fallback path)
///
/// When tee-pubkey lives at claims["attester_data"]["tee-pubkey"] (top-level of
/// attester_data, not nested under runtime_data), the retrieve fallback path
/// must still extract the pubkey and succeed JWE encryption.
#[tokio::test]
async fn test_retrieve_jwe_pubkey_attester_data_top_level() {
    let mut entity = make_entity(); entity.export_mode = "jwe".to_string();
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(entity)); },
        |policy| { *policy.get_policy_content_result.lock().unwrap() = Ok("package x\n\ndefault attestation_valid = true".into()); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::with_content(b"secret-data".to_vec()))); },
    );
    let result = svc.retrieve(&attest_payload_top_level_pubkey(), TEST_URI).await;
    assert!(result.is_ok(), "retrieve via attester_data top-level tee-pubkey should succeed: {:?}", result.err());
    let resp = result.unwrap();
    assert_ne!(resp.content.as_bytes(), b"secret-data", "JWE content should not be plaintext");
}

// ===========================================================================
// Tests – error code HTTP status mapping
// ===========================================================================

#[test]
fn test_already_exists_is_409() {
    assert_eq!(ResourceError::AlreadyExists { uri: "test".into() }.http_status(), 409);
}

#[test]
fn test_permission_denied_is_403() {
    assert_eq!(ResourceError::PermissionDenied.http_status(), 403);
}

#[test]
fn test_not_found_is_404() {
    assert_eq!(ResourceError::NotFound.http_status(), 404);
}

#[test]
fn test_policy_evaluation_failed_is_500() {
    assert_eq!(ResourceError::PolicyEvaluationFailed.http_status(), 500);
    // The external message must not carry the internal evaluation detail.
    assert_eq!(ResourceError::PolicyEvaluationFailed.external_message(), "policy evaluation failed");
}

// ===========================================================================
// Tests – update() created flag
// ===========================================================================

#[tokio::test]
async fn test_update_returns_created_true() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(None); },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::new())); },
    );
    let (_, created) = svc.update(&admin_ctx(TEST_USER), TEST_URI, &update_req()).await.unwrap();
    assert!(created, "new resource should return created=true");
}

#[tokio::test]
async fn test_update_returns_created_false() {
    let svc = make_service(
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); *repo.update_result.lock().unwrap() = Ok(1); },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("vault", Arc::new(MockResourceBackend::new())); },
    );
    let (_, created) = svc.update(&admin_ctx(TEST_USER), TEST_URI, &update_req()).await.unwrap();
    assert!(!created, "existing resource should return created=false");
}

// ===========================================================================
// Tests – TC-P0-01..03: create capability dispatch (D1)
// ===========================================================================

const HSM_URI: &str = "/rbs/v0/hsm/default/key/mykey";
const CA_URI: &str = "/rbs/v0/ca/default/certificate/mycert";

/// TC-P0-01a: create HSM — put_resource_content→insert + content zeroize
///
/// The service gates on capabilities: a PUT backend receives
/// `put_resource_content(desc, content)` once, then `repo.insert`.
#[tokio::test]
async fn test_post_create_hsm_put_insert() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE);
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.insert_result.lock().unwrap() = Ok(());
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let mut req = create_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"raw-key-bytes"));

    let result = svc.create(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    assert!(result.is_ok(), "HSM create should succeed: {:?}", result.err());
    assert_eq!(hsm_ref.put_call_count(), 1, "put_resource_content should be called once");
    assert_eq!(hsm_ref.check_exists_call_count(), 0, "check should not be called for a PUT backend");
    assert!(hsm_ref.last_put_content.lock().unwrap().is_some(), "put content should be captured");
}

/// TC-P0-01b: create HSM — put_resource_content fails after DB reservation
/// → BackendError, the reserved DB row is rolled back via repo.delete (not
/// the backend object, which may belong to a concurrent winner).
#[tokio::test]
async fn test_post_create_hsm_put_fail_natural_rollback() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE)
        .with_put_result(Err(ResourceError::BackendError { detail: "pkcs11 write failed".to_string() }));
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.insert_result.lock().unwrap() = Ok(());
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let mut req = create_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"raw-key-bytes"));

    let result = svc.create(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    match &result {
        Err(ResourceError::BackendError { .. }) => {}
        _ => panic!("Expected BackendError, got {:?}", result),
    }
    assert_eq!(hsm_ref.put_call_count(), 1, "put_resource_content should be called once even on failure");
    assert!(hsm_ref.last_put_content.lock().unwrap().is_some(), "put content should be captured even on failure");
}

/// TC-P0-01c: create HSM — concurrent dup (insert returns AlreadyExists) MUST
/// NOT touch the backend. This is the core TOCTOU fix: the loser's insert
/// fails atomically before any backend mutation, so it can neither clobber
/// nor orphan the winner's HSM object (old flow did put-then-insert-then-delete).
#[tokio::test]
async fn test_post_create_dup_does_not_touch_backend() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE);
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            // Simulate a concurrent winner: the atomic dup-check inside
            // create_with_user_limit_check observes the URI already exists.
            *repo.create_with_limit_check_result.lock().unwrap() =
                Err(ResourceError::AlreadyExists { uri: HSM_URI.to_string() });
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let mut req = create_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"raw-key-bytes"));

    let result = svc.create(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    match &result {
        Err(ResourceError::AlreadyExists { .. }) => {}
        other => panic!("Expected AlreadyExists, got {:?}", other),
    }
    assert_eq!(hsm_ref.put_call_count(), 0, "backend put MUST NOT be called when insert detects a dup (TOCTOU fix)");
    assert_eq!(hsm_ref.delete_call_count(), 0, "backend delete MUST NOT be called on dup (no object was created)");
}

/// TC-P0-01d: create HSM — put fails AFTER DB reservation → reserved DB row
/// is rolled back via repo.delete (compensation deletes the DB row, not the
/// backend object). Verified by holding an Arc to the repo to read counters.
#[tokio::test]
async fn test_post_create_put_fail_rolls_back_db_row() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE)
        .with_put_result(Err(ResourceError::BackendError { detail: "pkcs11 write failed".to_string() }));
    let hsm_ptr = Arc::new(hsm_backend);

    let repo = Arc::new(MockResourceRepository::new());
    *repo.find_by_uri_result.lock().unwrap() = Ok(None);
    *repo.insert_result.lock().unwrap() = Ok(());
    let policy = MockPolicyClient::new();
    *policy.validate_policy_result.lock().unwrap() = Ok(true);
    let mut bp = BackendProvider::new();
    bp.register("hsm", hsm_ptr);
    let config = test_config();
    let validator = ResourceValidator::new(config);
    let authz: Arc<dyn AuthzChecker> = Arc::new(MockAuthzChecker::new());
    let svc = ResourceService::new(repo.clone(), authz, bp, Arc::new(policy), validator);

    let mut req = create_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"raw-key-bytes"));

    let result = svc.create(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    match &result {
        Err(ResourceError::BackendError { .. }) => {}
        other => panic!("Expected BackendError, got {:?}", other),
    }
    assert_eq!(
        repo.delete_call_count(), 1,
        "compensation must delete the reserved DB row when backend put fails"
    );
}

/// TC-P0-02: create CA — empty capabilities → metadata-only insert
///
/// A get-only backend (CA) advertises no PUT/CHECK: the service skips all
/// backend calls and only inserts metadata.
#[tokio::test]
async fn test_post_create_ca_direct_insert() {
    let ca_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::empty());
    let ca_ptr = Arc::new(ca_backend);
    let ca_ref = ca_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.insert_result.lock().unwrap() = Ok(());
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("ca", ca_ptr); },
    );

    let req = create_req(); // No content for CA

    let result = svc.create(&admin_ctx(TEST_USER), CA_URI, &req).await;
    assert!(result.is_ok(), "CA create should succeed: {:?}", result.err());
    assert_eq!(ca_ref.put_call_count(), 0, "put should NOT be called for a get-only backend");
    assert_eq!(ca_ref.check_exists_call_count(), 0, "check should NOT be called for a get-only backend");
}

/// TC-P0-03a: create Vault — CHECK → check_resource_exists→insert
///
/// A CHECK backend verifies existence before the service registers metadata.
#[tokio::test]
async fn test_post_create_vault_check_insert() {
    let vault_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::CHECK);
    let vault_ptr = Arc::new(vault_backend);
    let vault_ref = vault_ptr.clone();

    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.insert_result.lock().unwrap() = Ok(());
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("vault", vault_ptr); },
    );

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &create_req()).await;
    assert!(result.is_ok(), "Vault create should succeed: {:?}", result.err());
    assert_eq!(vault_ref.check_exists_call_count(), 1, "check_resource_exists should be called once for Vault");
    assert_eq!(vault_ref.put_call_count(), 0, "put should NOT be called for a CHECK-only backend");
}

/// TC-P0-03b: create Vault — check_resource_exists returns false → BackendNotFound
#[tokio::test]
async fn test_post_create_vault_check_false() {
    let vault_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::CHECK)
        .with_check_exists_result(Ok(false));
    let vault_ptr = Arc::new(vault_backend);
    let vault_ref = vault_ptr.clone();

    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("vault", vault_ptr); },
    );

    let result = svc.create(&admin_ctx(TEST_USER), TEST_URI, &create_req()).await;
    match &result {
        Err(ResourceError::BackendNotFound) => {}
        _ => panic!("Expected BackendNotFound, got {:?}", result),
    }
    assert_eq!(vault_ref.check_exists_call_count(), 1, "check_resource_exists should be called once");
}

/// TC-P0-01 compatible: create HSM without content → no backend call, metadata-only
///
/// A PUT backend with no content to write skips the backend put entirely;
/// only metadata is registered.
#[tokio::test]
async fn test_post_create_hsm_no_content_param_invalid() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE);
    let hsm_ptr = Arc::new(hsm_backend);

    let svc = make_service_with_config(
        test_config(),
        |_| {},
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let req = create_req(); // No content

    let result = svc.create(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    assert!(result.is_ok(), "create with no content should succeed via the generic mock: {:?}", result.err());
}

// ===========================================================================
// Tests – TC-P1-01: update capability dispatch (D2)
// ===========================================================================

/// TC-P1-01: update CA with content → no PUT capability → BackendOperationUnsupported
///
/// A get-only backend cannot store content: the service rejects a
/// content-bearing update without invoking the backend.
#[tokio::test]
async fn test_put_update_ca_with_content_unsupported() {
    let ca_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::empty());
    let ca_ptr = Arc::new(ca_backend);
    let ca_ref = ca_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |_| {},
        |bp| { bp.register("ca", ca_ptr); },
    );

    let mut req = update_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"new-cert-data"));

    // Use a CA URI
    let result = svc.update(&admin_ctx(TEST_USER), CA_URI, &req).await;
    match &result {
        Err(ResourceError::BackendOperationUnsupported) => {}
        _ => panic!("Expected BackendOperationUnsupported, got {:?}", result),
    }
    assert_eq!(ca_ref.put_call_count(), 0, "put should NOT be called for a get-only backend");
}

/// TC-P1-01b: update HSM with content → put_resource_content → update DB
///
/// The service calls `put_resource_content` with the content, then updates the DB.
#[tokio::test]
async fn test_put_update_hsm_with_content_put_then_update() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE);
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.update_result.lock().unwrap() = Ok(1);
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let mut req = update_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"new-key-bytes"));

    let result = svc.update(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    assert!(result.is_ok(), "HSM update should succeed: {:?}", result.err());
    assert_eq!(hsm_ref.put_call_count(), 1, "put_resource_content should be called once");
    let (_resp, created) = result.unwrap();
    assert!(!created, "existing resource update should return created=false");
}

/// TC-P1-01c: update HSM without content → metadata-only (no backend call)
///
/// Without content there is nothing to put; the service skips the backend and
/// only updates DB metadata.
#[tokio::test]
async fn test_put_update_hsm_no_content_metadata_only() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE);
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.update_result.lock().unwrap() = Ok(1);
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let req = update_req(); // No content

    let result = svc.update(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    assert!(result.is_ok(), "HSM metadata-only update should succeed: {:?}", result.err());
    assert_eq!(hsm_ref.put_call_count(), 0, "put should NOT be called when there is no content");
}

/// TC-P1-01d: update HSM create-via-update with content → put_resource_content → insert
#[tokio::test]
async fn test_put_update_hsm_create_via_update_with_content() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE);
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(None);
            *repo.insert_result.lock().unwrap() = Ok(());
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let mut req = update_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"new-key-bytes"));

    let result = svc.update(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    assert!(result.is_ok(), "HSM create-via-update should succeed: {:?}", result.err());
    assert_eq!(hsm_ref.put_call_count(), 1, "put_resource_content should be called once");
    let (_, created) = result.unwrap();
    assert!(created, "new resource should return created=true");
}

/// TC-P1-01e: update Vault without content → metadata-only → update DB
#[tokio::test]
async fn test_put_update_vault_no_content_check_update() {
    let vault_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::CHECK);
    let vault_ptr = Arc::new(vault_backend);
    let vault_ref = vault_ptr.clone();

    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.update_result.lock().unwrap() = Ok(1);
        },
        |_| {},
        |bp| { bp.register("vault", vault_ptr); },
    );

    let result = svc.update(&admin_ctx(TEST_USER), TEST_URI, &update_req()).await;
    assert!(result.is_ok(), "Vault update should succeed: {:?}", result.err());
    assert_eq!(vault_ref.put_call_count(), 0, "put should NOT be called for a CHECK-only backend without content");
}

// ===========================================================================
// Tests – TC-P0-04, TC-P1-02: delete capability dispatch (D3)
// ===========================================================================

/// TC-P0-04a: delete HSM — backend→DB (先后端后 DB)
#[tokio::test]
async fn test_delete_hsm_backend_then_db() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE);
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.delete_result.lock().unwrap() = Ok(1);
        },
        |_| {},
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let result = svc.delete(&bearer_ctx(TEST_USER), HSM_URI).await;
    assert!(result.is_ok(), "HSM delete should succeed: {:?}", result.err());
    assert_eq!(hsm_ref.delete_call_count(), 1, "backend delete should be called once");
}

/// TC-P0-04b: delete HSM — backend failure → BackendError, DB preserved
#[tokio::test]
async fn test_delete_hsm_backend_fail_db_preserved() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE)
        .with_delete_result(Err(ResourceError::BackendError { detail: "pkcs11 delete failed".to_string() }));
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.delete_result.lock().unwrap() = Ok(1);
        },
        |_| {},
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let result = svc.delete(&bearer_ctx(TEST_USER), HSM_URI).await;
    match &result {
        Err(ResourceError::BackendError { .. }) => {}
        _ => panic!("Expected BackendError, got {:?}", result),
    }
    assert_eq!(hsm_ref.delete_call_count(), 1, "backend delete should be called once even on failure");
    // DB row preserved — repo.delete not called (we verify indirectly via error return)
}

/// TC-P0-04c: delete HSM — idempotent (object already gone → Ok → DB delete)
#[tokio::test]
async fn test_delete_hsm_idempotent() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE); // delete_result defaults to Ok(())
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.delete_result.lock().unwrap() = Ok(1);
        },
        |_| {},
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let result = svc.delete(&bearer_ctx(TEST_USER), HSM_URI).await;
    assert!(result.is_ok(), "HSM idempotent delete should succeed: {:?}", result.err());
    assert_eq!(hsm_ref.delete_call_count(), 1, "backend delete should be called once");
}

/// TC-P1-02a: delete CA — no DELETE capability → DB delete only
///
/// A get-only backend cannot destroy objects; the service skips the backend
/// and only deletes the DB row.
#[tokio::test]
async fn test_delete_ca_db_only() {
    let ca_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::empty());
    let ca_ptr = Arc::new(ca_backend);
    let ca_ref = ca_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.delete_result.lock().unwrap() = Ok(1);
        },
        |_| {},
        |bp| { bp.register("ca", ca_ptr); },
    );

    let result = svc.delete(&bearer_ctx(TEST_USER), CA_URI).await;
    assert!(result.is_ok(), "CA delete should succeed: {:?}", result.err());
    assert_eq!(ca_ref.delete_call_count(), 0, "backend delete should NOT be called for a get-only backend");
}

/// TC-P1-02b: delete Vault — no DELETE capability → DB delete only
#[tokio::test]
async fn test_delete_vault_db_only() {
    let vault_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::CHECK);
    let vault_ptr = Arc::new(vault_backend);
    let vault_ref = vault_ptr.clone();

    let svc = make_service(
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.delete_result.lock().unwrap() = Ok(1);
        },
        |_| {},
        |bp| { bp.register("vault", vault_ptr); },
    );

    let result = svc.delete(&bearer_ctx(TEST_USER), TEST_URI).await;
    assert!(result.is_ok(), "Vault delete should succeed: {:?}", result.err());
    assert_eq!(vault_ref.delete_call_count(), 0, "backend delete should NOT be called for a CHECK-only backend");
}

// ===========================================================================
// Tests – TC-P0-05: get_content GetResourceOptions construction (D4/D8)
// ===========================================================================

/// Attest context with CSR (Base64 DER) for CA tests.
fn attest_with_csr() -> AuthContext {
    AuthContext::Attest(AttestContext {
        claims: json!({
            "nonce": "abc123",
            "attester_data": {"runtime_data": {"tee-pubkey": EC_P256_JWK, "csr": base64::engine::general_purpose::STANDARD.encode(b"der-csr-bytes")}},
        }),
        token_type: TokenType::Attest,
    })
}

/// Attest context without CSR for CA CsrRequired tests.
fn attest_no_csr_with_pubkey() -> AuthContext {
    AuthContext::Attest(AttestContext {
        claims: json!({
            "nonce": "abc123",
            "attester_data": {"runtime_data": {"tee-pubkey": EC_P256_JWK}}
        }),
        token_type: TokenType::Attest,
    })
}

/// TC-P0-05a: CA GET with CSR → GetResourceOptions{csr: Some} → JWE 200
#[tokio::test]
async fn test_get_content_ca_with_csr() {
    let ca_backend = MockResourceBackend::new();
    *ca_backend.get_content_result.lock().unwrap() = Ok(Zeroizing::new(b"cert-data".to_vec()));
    let ca_ptr = Arc::new(ca_backend);
    let ca_ref = ca_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| { bp.register("ca", ca_ptr); },
    );

    let result = svc.get_content(&attest_with_csr(), CA_URI).await;
    assert!(result.is_ok(), "CA GET with CSR should succeed: {:?}", result.err());
    assert_eq!(ca_ref.get_content_call_count(), 1, "get_resource_content should be called once");
}

/// TC-P0-05b: CA GET without CSR → CsrRequired(400)
///
/// CSR enforcement now lives in the backend: the service calls
/// `get_resource_content` with `csr_der: None`, and the CA backend returns
/// `CsrRequired`. The mock simulates that by returning `CsrRequired`.
#[tokio::test]
async fn test_get_content_ca_no_csr() {
    let ca_backend = MockResourceBackend::new();
    *ca_backend.get_content_result.lock().unwrap() = Err(ResourceError::CsrRequired);
    let ca_ptr = Arc::new(ca_backend);
    let ca_ref = ca_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| { bp.register("ca", ca_ptr); },
    );

    let result = svc.get_content(&attest_no_csr_with_pubkey(), CA_URI).await;
    match &result {
        Err(ResourceError::CsrRequired) => {}
        _ => panic!("Expected CsrRequired, got {:?}", result),
    }
    assert_eq!(ca_ref.get_content_call_count(), 1, "get_resource_content should be called once (backend enforces CSR)");
}

/// TC-P0-05c: CA GET authz deny + no CSR → NotFound(404), not CsrRequired(400)
///
/// D8: 404 masks 400 — authz failure is returned before CsrRequired check.
#[tokio::test]
async fn test_get_content_ca_authz_deny_no_csr() {
    let ca_backend = MockResourceBackend::new();
    let ca_ptr = Arc::new(ca_backend);
    let ca_ref = ca_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": false}".to_string());
        },
        |bp| { bp.register("ca", ca_ptr); },
    );

    let result = svc.get_content(&attest_no_csr_with_pubkey(), CA_URI).await;
    match &result {
        Err(ResourceError::NotFoundOrDenied) => {}
        _ => panic!("Expected NotFound (not CsrRequired), got {:?}", result),
    }
    assert_eq!(ca_ref.get_content_call_count(), 0, "backend should not be called when authz fails");
}

/// TC-P0-05d: HSM GET → GetResourceOptions{csr: None} (supports_csr=false)
#[tokio::test]
async fn test_get_content_hsm_no_csr_needed() {
    let hsm_backend = MockResourceBackend::new();
    *hsm_backend.get_content_result.lock().unwrap() = Ok(Zeroizing::new(b"key-data".to_vec()));
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let result = svc.get_content(&attest_with_pubkey(), HSM_URI).await;
    assert!(result.is_ok(), "HSM GET should succeed without CSR: {:?}", result.err());
    assert_eq!(hsm_ref.get_content_call_count(), 1, "get_resource_content should be called once");
}

/// TC-P0-05e: retrieve CA with CSR → same options construction as get_content
#[tokio::test]
async fn test_retrieve_ca_with_csr() {
    let svc = make_service_with_config(
        test_config(),
        |repo| { *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity())); },
        |policy| {
            *policy.get_policy_content_result.lock().unwrap() =
                Ok("package example; result = {\"policy_matched\": true}".to_string());
        },
        |bp| {
            let backend = MockResourceBackend::new();
            *backend.get_content_result.lock().unwrap() = Ok(Zeroizing::new(b"cert-data".to_vec()));
            bp.register("ca", Arc::new(backend));
        },
    );

    let attest_ctx = AttestContext {
        claims: json!({
            "nonce": "abc123",
            "attester_data": {"runtime_data": {"tee-pubkey": EC_P256_JWK, "csr": base64::engine::general_purpose::STANDARD.encode(b"der-csr-bytes")}},
        }),
        token_type: TokenType::Attest,
    };

    let result = svc.retrieve(&attest_ctx, CA_URI).await;
    assert!(result.is_ok(), "CA retrieve with CSR should succeed: {:?}", result.err());
}

// ===========================================================================
// Tests – TC-P2-01: optimistic concurrency conflict
// ===========================================================================

/// TC-P2-01: update with affected==0 → VersionConflict(409), backend NOT touched.
///
/// Simulates concurrent update: repo.update returns 0 affected rows (version
/// mismatch) → VersionConflict. DB-first ordering means the backend put is
/// skipped entirely, so the loser cannot clobber the winner's object.
#[tokio::test]
async fn test_update_optimistic_concurrency_conflict() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE);
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let svc = make_service_with_config(
        test_config(),
        |repo| {
            *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
            *repo.update_result.lock().unwrap() = Ok(0); // 0 affected = conflict
        },
        |policy| { *policy.validate_policy_result.lock().unwrap() = Ok(true); },
        |bp| { bp.register("hsm", hsm_ptr); },
    );

    let mut req = update_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"new-key"));

    let result = svc.update(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    match &result {
        Err(ResourceError::VersionConflict) => {}
        _ => panic!("Expected VersionConflict, got {:?}", result),
    }
    assert_eq!(
        hsm_ref.put_call_count(), 0,
        "backend put MUST NOT be called when optimistic lock fails (TOCTOU fix)"
    );
}

/// TC-P2-03: update — put fails after DB update committed → DB row rolled back.
///
/// DB-first ordering: optimistic-lock update succeeds, then backend put fails
/// → repo.update called again to restore the pre-update state. Verified by
/// holding an Arc to the repo to read update_call_count (2: 1 commit + 1 rollback).
#[tokio::test]
async fn test_put_update_put_fail_rolls_back_db() {
    let hsm_backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT | BackendCapabilities::DELETE)
        .with_put_result(Err(ResourceError::BackendError { detail: "pkcs11 write failed".to_string() }));
    let hsm_ptr = Arc::new(hsm_backend);

    let repo = Arc::new(MockResourceRepository::new());
    *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
    *repo.update_result.lock().unwrap() = Ok(1); // optimistic lock succeeds
    let policy = MockPolicyClient::new();
    *policy.validate_policy_result.lock().unwrap() = Ok(true);
    let mut bp = BackendProvider::new();
    bp.register("hsm", hsm_ptr);
    let config = test_config();
    let validator = ResourceValidator::new(config);
    let authz: Arc<dyn AuthzChecker> = Arc::new(MockAuthzChecker::new());
    let svc = ResourceService::new(repo.clone(), authz, bp, Arc::new(policy), validator);

    let mut req = update_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"new-key"));

    let result = svc.update(&admin_ctx(TEST_USER), HSM_URI, &req).await;
    match &result {
        Err(ResourceError::BackendError { .. }) => {}
        other => panic!("Expected BackendError, got {:?}", other),
    }
    assert_eq!(
        repo.update_call_count(), 2,
        "compensation must roll back the DB update when backend put fails (1 commit + 1 rollback)"
    );
}

// ===========================================================================
// Tests – TC-P1-04: Bearer GET HSM → deny (404 mask)
// ===========================================================================

/// TC-P1-04: Bearer GET HSM with authz deny → NotFound(404)
///
/// D8: authz failure returns NotFound, masking existence. Backend not called.
#[tokio::test]
async fn test_get_content_hsm_bearer_deny() {
    let hsm_backend = MockResourceBackend::new();
    let hsm_ptr = Arc::new(hsm_backend);
    let hsm_ref = hsm_ptr.clone();

    let authz: Arc<dyn AuthzChecker> = Arc::new(MockAuthzChecker::new().with_deny());

    let config = test_config();
    let validator = ResourceValidator::new(config);
    let repo = MockResourceRepository::new();
    *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
    let policy = MockPolicyClient::new();
    let mut bp = BackendProvider::new();
    bp.register("hsm", hsm_ptr);
    let svc = ResourceService::new(Arc::new(repo), authz, bp, Arc::new(policy), validator);

    let result = svc.get_content(&bearer_ctx(TEST_USER), HSM_URI).await;
    match &result {
        Err(ResourceError::NotFoundOrDenied) => {}
        _ => panic!("Expected NotFound (authz deny masked), got {:?}", result),
    }
    assert_eq!(hsm_ref.get_content_call_count(), 0, "backend should not be called when authz denies");
}

/// TC-P2-02: authz deny + CA no CSR → NotFound (not CsrRequired)
///
/// D8: 404 masks 400 — authz failure is returned before CsrRequired check.
/// Complementary to TC-P0-05c, this test explicitly asserts the error is NOT CsrRequired.
#[tokio::test]
async fn test_get_content_ca_authz_deny_no_csr_not_csr_required() {
    let ca_backend = MockResourceBackend::new();
    let ca_ptr = Arc::new(ca_backend);
    let ca_ref = ca_ptr.clone();

    let authz: Arc<dyn AuthzChecker> = Arc::new(MockAuthzChecker::new().with_deny());

    let config = test_config();
    let validator = ResourceValidator::new(config);
    let repo = MockResourceRepository::new();
    *repo.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
    let policy = MockPolicyClient::new();
    let mut bp = BackendProvider::new();
    bp.register("ca", ca_ptr);
    let svc = ResourceService::new(Arc::new(repo), authz, bp, Arc::new(policy), validator);

    let result = svc.get_content(&attest_no_csr_with_pubkey(), CA_URI).await;
    // Must be NotFound, NOT CsrRequired
    match &result {
        Err(ResourceError::NotFoundOrDenied) => {}
        Err(ResourceError::CsrRequired) => panic!("Expected NotFound, got CsrRequired (D8 violation)"),
        _ => panic!("Expected NotFound, got {:?}", result),
    }
    assert_eq!(ca_ref.get_content_call_count(), 0, "backend should not be called when authz fails");
}

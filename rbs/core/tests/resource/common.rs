/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Shared test helpers for resource integration tests.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::json;
use zeroize::Zeroizing;

use rbs_api_types::{GetResourceOptions, ResourceDesc};
use rbs_core::auth::authz::{Action, AuthzError, RequiredRole};
use rbs_core::auth::authz_checker::AuthzChecker;
use rbs_core::auth::context::{AttestContext, AuthContext, BearerContext, TokenType};
use rbs_core::resource::adapter::{BackendCapabilities, BackendProvider, PolicyClient, ResourceBackend};
use rbs_core::resource::error::ResourceError;
use rbs_core::resource::repository::{ResourceEntity, ResourceRepository};
use rbs_core::resource::validator::ResourceValidator;
use rbs_core::resource::{CreateResourceRequest, ResourceConfig, ResourceService, UpdateResourceRequest};

type MockResult<T> = Result<T, ResourceError>;

// ---------------------------------------------------------------------------
// MockResourceRepository
// ---------------------------------------------------------------------------

pub(crate) struct MockResourceRepository {
    pub insert_result: Mutex<MockResult<()>>,
    pub find_by_uri_result: Mutex<MockResult<Option<ResourceEntity>>>,
    pub update_result: Mutex<MockResult<u64>>,
    pub delete_result: Mutex<MockResult<u64>>,
    pub list_result: Mutex<MockResult<(Vec<ResourceEntity>, u64)>>,
    /// Number of `delete` calls — used to assert the create/update rollback.
    /// Shared so a handle can outlive the repository being moved into the service.
    pub delete_calls: Arc<Mutex<u32>>,
}

impl MockResourceRepository {
    pub(crate) fn new() -> Self {
        Self {
            insert_result: Mutex::new(Ok(())),
            find_by_uri_result: Mutex::new(Ok(None)),
            update_result: Mutex::new(Ok(1)),
            delete_result: Mutex::new(Ok(1)),
            list_result: Mutex::new(Ok((vec![], 0))),
            delete_calls: Arc::new(Mutex::new(0)),
        }
    }

    /// Cloneable counter handle, readable after the repository is owned by the service.
    pub(crate) fn delete_call_handle(&self) -> Arc<Mutex<u32>> {
        self.delete_calls.clone()
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
    async fn update(&self, _uri: &str, _entity: &ResourceEntity, _old: i64) -> MockResult<u64> {
        self.update_result.lock().unwrap().clone()
    }
    async fn delete(&self, _uri: &str, _username: &str) -> MockResult<u64> {
        *self.delete_calls.lock().unwrap() += 1;
        self.delete_result.lock().unwrap().clone()
    }
    async fn list_by_user(
        &self, _username: &str, _offset: i64, _limit: i64,
    ) -> MockResult<(Vec<ResourceEntity>, u64)> {
        self.list_result.lock().unwrap().clone()
    }
    async fn find_by_policy_id(&self, _policy_id: &str) -> MockResult<Vec<ResourceEntity>> {
        Ok(vec![])
    }
    async fn count_by_user(&self, _username: &str) -> MockResult<usize> {
        Ok(0)
    }
    async fn create_with_user_limit_check(
        &self,
        _uri: &str,
        _entity: &ResourceEntity,
        _max_per_user: usize,
    ) -> MockResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MockPolicyClient
// ---------------------------------------------------------------------------

pub(crate) struct MockPolicyClient {
    pub validate_result: Mutex<MockResult<bool>>,
    pub get_content_result: Mutex<MockResult<String>>,
}

impl MockPolicyClient {
    pub(crate) fn new() -> Self {
        Self {
            validate_result: Mutex::new(Ok(true)),
            get_content_result: Mutex::new(Ok("package rbs\nallow = true".to_string())),
        }
    }
}

#[async_trait]
impl PolicyClient for MockPolicyClient {
    async fn validate_policy(&self, _id: &str, _uid: &str) -> MockResult<bool> {
        self.validate_result.lock().unwrap().clone()
    }
    async fn get_policy_content(&self, _id: &str) -> MockResult<String> {
        self.get_content_result.lock().unwrap().clone()
    }
    async fn relation_res_ids(&self, _id: &str, _uid: &str) -> MockResult<Vec<String>> {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// MockResourceBackend
// ---------------------------------------------------------------------------

pub(crate) struct MockResourceBackend {
    pub check_exists: Mutex<MockResult<bool>>,
    pub get_content: Mutex<MockResult<Zeroizing<Vec<u8>>>>,
    pub put_result: Mutex<MockResult<()>>,
    pub delete_result: Mutex<MockResult<()>>,
    pub capabilities: Mutex<BackendCapabilities>,
}

impl MockResourceBackend {
    pub(crate) fn new() -> Self {
        Self {
            check_exists: Mutex::new(Ok(true)),
            get_content: Mutex::new(Ok(Zeroizing::new(b"secret-data".to_vec()))),
            put_result: Mutex::new(Ok(())),
            delete_result: Mutex::new(Ok(())),
            capabilities: Mutex::new(BackendCapabilities::CHECK),
        }
    }

    pub(crate) fn with_capabilities(self, caps: BackendCapabilities) -> Self {
        *self.capabilities.lock().unwrap() = caps;
        self
    }

    pub(crate) fn with_put_result(self, result: MockResult<()>) -> Self {
        *self.put_result.lock().unwrap() = result;
        self
    }

    pub(crate) fn with_delete_result(self, result: MockResult<()>) -> Self {
        *self.delete_result.lock().unwrap() = result;
        self
    }
}

#[async_trait]
impl ResourceBackend for MockResourceBackend {
    fn capabilities(&self) -> BackendCapabilities {
        *self.capabilities.lock().unwrap()
    }
    async fn check_resource_exists(&self, _desc: &ResourceDesc) -> MockResult<bool> {
        self.check_exists.lock().unwrap().clone()
    }
    async fn get_resource_content(
        &self,
        _desc: &ResourceDesc,
        _opts: GetResourceOptions,
    ) -> MockResult<Zeroizing<Vec<u8>>> {
        self.get_content.lock().unwrap().clone()
    }
    async fn put_resource_content(&self, _desc: &ResourceDesc, _data: &[u8]) -> MockResult<()> {
        self.put_result.lock().unwrap().clone()
    }
    async fn delete_resource(&self, _desc: &ResourceDesc) -> MockResult<()> {
        self.delete_result.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// MockAuthzChecker
// ---------------------------------------------------------------------------

/// Non-`Denied` error a [`MockAuthzChecker`] can return from
/// `check_resource_get`, used to exercise the server-fault mapping of
/// `read_authz_error` (anything other than `Denied` becomes a 500).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GetErrorKind {
    PolicyEvaluationFailed,
    MissingField,
}

pub(crate) struct MockAuthzChecker {
    pub deny_all: Mutex<bool>,
    pub get_error: Mutex<Option<GetErrorKind>>,
}

impl MockAuthzChecker {
    pub(crate) fn new() -> Self {
        Self { deny_all: Mutex::new(false), get_error: Mutex::new(None) }
    }
    pub(crate) fn denying() -> Self {
        Self { deny_all: Mutex::new(true), get_error: Mutex::new(None) }
    }
    pub(crate) fn with_get_error(self, kind: GetErrorKind) -> Self {
        *self.get_error.lock().unwrap() = Some(kind);
        self
    }
}

#[async_trait]
impl AuthzChecker for MockAuthzChecker {
    async fn check_action(&self, ctx: &AuthContext, _action: Action, role: RequiredRole) -> Result<(), AuthzError> {
        if *self.deny_all.lock().unwrap() {
            return Err(AuthzError::Denied);
        }
        match ctx {
            AuthContext::Attest(_) => Err(AuthzError::Denied),
            AuthContext::Bearer(b) => match role {
                RequiredRole::AdminOnly if b.role != "admin" => Err(AuthzError::Denied),
                _ => Ok(()),
            },
        }
    }
    async fn check_resource_get(&self, ctx: &AuthContext, _owner: &str, policy: &str, _res_provider: Option<&str>) -> Result<(), AuthzError> {
        if *self.deny_all.lock().unwrap() {
            return Err(AuthzError::Denied);
        }
        if let Some(kind) = *self.get_error.lock().unwrap() {
            return Err(match kind {
                GetErrorKind::PolicyEvaluationFailed => {
                    AuthzError::PolicyEvaluationFailed("rego evaluation error".to_string())
                }
                GetErrorKind::MissingField => AuthzError::MissingField("role"),
            });
        }
        match ctx {
            AuthContext::Attest(_) => {
                if policy.contains("true") { Ok(()) } else { Err(AuthzError::Denied) }
            }
        AuthContext::Bearer(_) => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) const TEST_URI: &str = "/rbs/v0/vault/default/secret/mykey";
pub(crate) const TEST_USER: &str = "user1";

pub(crate) fn make_entity() -> ResourceEntity {
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
        policy_id: "pol-001".to_string(),
    }
}

pub(crate) fn create_req() -> CreateResourceRequest {
    CreateResourceRequest {
        policy_id: "pol-001".to_string(),
        content_type: Some("text".to_string()),
        export_mode: Some("jwe".to_string()),
        additional_info: None,
        content: None,
    }
}

pub(crate) fn update_req() -> UpdateResourceRequest {
    UpdateResourceRequest {
        policy_id: Some("pol-001".to_string()),
        content_type: Some("text".to_string()),
        export_mode: Some("jwe".to_string()),
        additional_info: None,
        content: None,
    }
}

pub(crate) fn bearer_ctx(uid: &str) -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: uid.to_string(),
        role: "user".to_string(),
        claims: json!({}),
        token_type: TokenType::Bearer,
    })
}

pub(crate) fn make_service(
    repo: MockResourceRepository,
    policy: MockPolicyClient,
    authz: MockAuthzChecker,
    backend: MockResourceBackend,
) -> ResourceService {
    make_service_with_config(repo, policy, authz, backend, ResourceConfig::default())
}

/// Like [`make_service`], but with an explicit `ResourceConfig`. A backend named
/// in `configured_backends`/`per_backend_allowed_types` but never registered in
/// the `BackendProvider` passes URI validation and fails at backend lookup,
/// which is the "configured provider without an adapter" path.
pub(crate) fn make_service_with_config(
    repo: MockResourceRepository,
    policy: MockPolicyClient,
    authz: MockAuthzChecker,
    backend: MockResourceBackend,
    config: ResourceConfig,
) -> ResourceService {
    let validator = ResourceValidator::new(config);
    let mut bp = BackendProvider::new();
    bp.register("vault", Arc::new(backend));
    ResourceService::new(Arc::new(repo), Arc::new(authz), bp, Arc::new(policy), validator)
}

/// Default config extended with an `hsm` provider (allowed `key` resources)
/// that no test service registers a backend for.
pub(crate) fn config_with_unregistered_hsm() -> ResourceConfig {
    let mut config = ResourceConfig::default();
    config.configured_backends.push("hsm".to_string());
    config.per_backend_allowed_types.insert("hsm".to_string(), vec!["key".to_string()]);
    config
}

/// URI of an `hsm` resource: valid per [`config_with_unregistered_hsm`], but no
/// backend is registered for the provider.
pub(crate) const HSM_URI: &str = "/rbs/v0/hsm/repo1/key/signing-key";

/// Attestation context carrying arbitrary claims.
pub(crate) fn attest_ctx(claims: serde_json::Value) -> AttestContext {
    AttestContext { claims, token_type: TokenType::Attest }
}

/// Default service with all mocks returning success.
pub(crate) fn default_service() -> ResourceService {
    make_service(MockResourceRepository::new(), MockPolicyClient::new(), MockAuthzChecker::new(), MockResourceBackend::new())
}

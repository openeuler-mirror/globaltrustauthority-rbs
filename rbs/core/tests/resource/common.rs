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

use rbs_core::auth::authz::{Action, AuthzError, RequiredRole};
use rbs_core::auth::authz_checker::AuthzChecker;
use rbs_core::auth::context::{AuthContext, BearerContext, TokenType};
use rbs_core::resource::adapter::{BackendProvider, PolicyClient, ResourceBackend};
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
}

impl MockResourceRepository {
    pub(crate) fn new() -> Self {
        Self {
            insert_result: Mutex::new(Ok(())),
            find_by_uri_result: Mutex::new(Ok(None)),
            update_result: Mutex::new(Ok(1)),
            delete_result: Mutex::new(Ok(1)),
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
    async fn update(&self, _uri: &str, _entity: &ResourceEntity, _old: i64) -> MockResult<u64> {
        self.update_result.lock().unwrap().clone()
    }
    async fn delete(&self, _uri: &str, _username: &str) -> MockResult<u64> {
        self.delete_result.lock().unwrap().clone()
    }
    async fn list_by_user(&self, _username: &str) -> MockResult<Vec<ResourceEntity>> {
        Ok(vec![])
    }
    async fn find_by_policy_id(&self, _policy_id: &str) -> MockResult<Vec<ResourceEntity>> {
        Ok(vec![])
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
}

impl MockResourceBackend {
    pub(crate) fn new() -> Self {
        Self {
            check_exists: Mutex::new(Ok(true)),
            get_content: Mutex::new(Ok(Zeroizing::new(b"secret-data".to_vec()))),
        }
    }
}

#[async_trait]
impl ResourceBackend for MockResourceBackend {
    async fn check_resource_exists(&self, _uri: &str) -> MockResult<bool> {
        self.check_exists.lock().unwrap().clone()
    }
    async fn get_resource_content(&self, _uri: &str) -> MockResult<Zeroizing<Vec<u8>>> {
        self.get_content.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// MockAuthzChecker
// ---------------------------------------------------------------------------

pub(crate) struct MockAuthzChecker {
    pub deny_all: Mutex<bool>,
}

impl MockAuthzChecker {
    pub(crate) fn new() -> Self {
        Self { deny_all: Mutex::new(false) }
    }
    pub(crate) fn denying() -> Self {
        Self { deny_all: Mutex::new(true) }
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
    async fn check_resource_get(&self, ctx: &AuthContext, _owner: &str, policy: &str) -> Result<(), AuthzError> {
        if *self.deny_all.lock().unwrap() {
            return Err(AuthzError::Denied);
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
    }
}

pub(crate) fn update_req() -> UpdateResourceRequest {
    UpdateResourceRequest {
        policy_id: Some("pol-001".to_string()),
        content_type: Some("text".to_string()),
        export_mode: Some("jwe".to_string()),
        additional_info: None,
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
    let config = ResourceConfig::default();
    let validator = ResourceValidator::new(config);
    let mut bp = BackendProvider::new();
    bp.register("vault", Arc::new(backend));
    ResourceService::new(Arc::new(repo), Arc::new(authz), bp, Arc::new(policy), validator)
}

/// Default service with all mocks returning success.
pub(crate) fn default_service() -> ResourceService {
    make_service(MockResourceRepository::new(), MockPolicyClient::new(), MockAuthzChecker::new(), MockResourceBackend::new())
}

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

//! Shared test helpers for policy integration tests.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;

use rbs_core::auth::authz::AuthzFacade;
use rbs_core::policy::{
    PolicyConfig, PolicyEntity, PolicyError, PolicyRepository, PolicyValidator,
};
use rbs_core::policy::service::PolicyService;
use rbs_core::policy_engine::RealPolicyEngine;
use rbs_core::resource::adapter::PolicyClient;
use rbs_core::resource::error::ResourceError;
use rbs_core::{AuthContext, BearerContext, TokenType};

// ---------------------------------------------------------------------------
// MockPolicyRepository
// ---------------------------------------------------------------------------

type MockResult<T> = Mutex<Result<T, PolicyError>>;

pub(crate) struct MockPolicyRepository {
    db: Arc<sea_orm::DatabaseConnection>,
    insert: MockResult<()>,
    find_by_id: MockResult<Option<PolicyEntity>>,
    find_by_name_and_user: MockResult<Option<PolicyEntity>>,
    find_by_ids_and_user: MockResult<Vec<PolicyEntity>>,
    list_by_user: MockResult<(Vec<PolicyEntity>, u64)>,
    count_by_user: MockResult<usize>,
    update_with_version: MockResult<u64>,
    delete_by_ids_txn: MockResult<u64>,
    delete: MockResult<()>,
}

fn mock_db() -> Arc<sea_orm::DatabaseConnection> {
    use std::sync::OnceLock;
    static DB: OnceLock<Arc<sea_orm::DatabaseConnection>> = OnceLock::new();
    Arc::clone(DB.get_or_init(|| {
        let db = std::thread::spawn(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(
                sea_orm::Database::connect("sqlite::memory:")
            ).expect("mock in-memory sqlite")
        }).join().unwrap();
        Arc::new(db)
    }))
}

impl MockPolicyRepository {
    pub(crate) fn new() -> Self {
        Self {
            db: mock_db(),
            insert: Mutex::new(Ok(())),
            find_by_id: Mutex::new(Ok(None)),
            find_by_name_and_user: Mutex::new(Ok(None)),
            find_by_ids_and_user: Mutex::new(Ok(Vec::new())),
            list_by_user: Mutex::new(Ok((Vec::new(), 0))),
            count_by_user: Mutex::new(Ok(0)),
            update_with_version: Mutex::new(Ok(0)),
            delete_by_ids_txn: Mutex::new(Ok(0)),
            delete: Mutex::new(Ok(())),
        }
    }

    pub(crate) fn with_find_by_id(self, result: Result<Option<PolicyEntity>, PolicyError>) -> Self {
        *self.find_by_id.lock().unwrap() = result;
        self
    }

    pub(crate) fn with_find_by_name_and_user(self, result: Result<Option<PolicyEntity>, PolicyError>) -> Self {
        *self.find_by_name_and_user.lock().unwrap() = result;
        self
    }

    pub(crate) fn with_find_by_ids_and_user(self, result: Result<Vec<PolicyEntity>, PolicyError>) -> Self {
        *self.find_by_ids_and_user.lock().unwrap() = result;
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_count_by_user(self, result: Result<usize, PolicyError>) -> Self {
        *self.count_by_user.lock().unwrap() = result;
        self
    }

    pub(crate) fn with_update_with_version(self, result: Result<u64, PolicyError>) -> Self {
        *self.update_with_version.lock().unwrap() = result;
        self
    }

    pub(crate) fn with_delete_by_ids_txn(self, result: Result<u64, PolicyError>) -> Self {
        *self.delete_by_ids_txn.lock().unwrap() = result;
        self
    }
}

#[async_trait]
impl PolicyRepository for MockPolicyRepository {
    async fn insert(&self, _entity: &PolicyEntity) -> Result<(), PolicyError> {
        self.insert.lock().unwrap().clone()
    }

    async fn find_by_id(&self, _policy_id: &str) -> Result<Option<PolicyEntity>, PolicyError> {
        self.find_by_id.lock().unwrap().clone()
    }

    async fn find_by_name_and_user(
        &self,
        _name: &str,
        _username: &str,
    ) -> Result<Option<PolicyEntity>, PolicyError> {
        self.find_by_name_and_user.lock().unwrap().clone()
    }

    async fn find_by_ids_and_user(
        &self,
        _policy_ids: &[String],
        _username: &str,
    ) -> Result<Vec<PolicyEntity>, PolicyError> {
        self.find_by_ids_and_user.lock().unwrap().clone()
    }

    async fn list_by_user(
        &self,
        _username: &str,
        _offset: i64,
        _limit: i64,
    ) -> Result<(Vec<PolicyEntity>, u64), PolicyError> {
        self.list_by_user.lock().unwrap().clone()
    }

    async fn count_by_user(&self, _username: &str) -> Result<usize, PolicyError> {
        self.count_by_user.lock().unwrap().clone()
    }

    async fn update_with_version(
        &self,
        _policy_id: &str,
        _expected_version: i32,
        _entity: PolicyEntity,
    ) -> Result<u64, PolicyError> {
        self.update_with_version.lock().unwrap().clone()
    }

    async fn delete_by_ids_txn(
        &self,
        _conn: &sea_orm::DatabaseTransaction,
        _policy_ids: &[String],
        _username: &str,
    ) -> Result<u64, PolicyError> {
        self.delete_by_ids_txn.lock().unwrap().clone()
    }

    async fn delete(&self, _policy_id: &str) -> Result<(), PolicyError> {
        self.delete.lock().unwrap().clone()
    }

    fn db_connection(&self) -> &sea_orm::DatabaseConnection {
        &self.db
    }
}

// ---------------------------------------------------------------------------
// MockPolicyClient
// ---------------------------------------------------------------------------

pub(crate) struct MockPolicyClient {
    relation_res_ids: Mutex<Result<Vec<String>, ResourceError>>,
}

impl MockPolicyClient {
    pub(crate) fn new() -> Self {
        Self { relation_res_ids: Mutex::new(Ok(vec![])) }
    }

    pub(crate) fn with_relation_res_ids(self, result: Result<Vec<String>, ResourceError>) -> Self {
        *self.relation_res_ids.lock().unwrap() = result;
        self
    }
}

#[async_trait]
impl PolicyClient for MockPolicyClient {
    async fn validate_policy(&self, _id: &str, _uid: &str) -> Result<bool, ResourceError> {
        Ok(true)
    }
    async fn get_policy_content(&self, _id: &str) -> Result<String, ResourceError> {
        Ok("package x\n".into())
    }
    async fn relation_res_ids(&self, _id: &str, _uid: &str) -> Result<Vec<String>, ResourceError> {
        self.relation_res_ids.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

pub(crate) fn make_service(repo: MockPolicyRepository) -> PolicyService {
    make_service_with_client(repo, MockPolicyClient::new())
}

pub(crate) fn make_service_with_client(repo: MockPolicyRepository, client: MockPolicyClient) -> PolicyService {
    let config = PolicyConfig::default();
    let validator = PolicyValidator::new(config.clone());
    let authz = AuthzFacade::new(Arc::new(RealPolicyEngine));
    PolicyService::new(Arc::new(repo), authz, Arc::new(client), validator, config)
}

pub(crate) fn bearer_ctx(sub: &str, role: &str) -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".into(),
        sub: sub.into(),
        role: role.into(),
        claims: Value::Null,
        token_type: TokenType::Bearer,
    })
}

pub(crate) fn make_entity(policy_id: &str, username: &str, policy_name: &str) -> PolicyEntity {
    PolicyEntity {
        policy_id: policy_id.into(),
        username: username.into(),
        policy_name: policy_name.into(),
        policy_version: 1,
        policy_content: String::new(),
        content_type: "base64".into(),
        created_at: 0,
        updated_at: 0,
    }
}

/// Base64-encoded "hello".
pub(crate) const HELLO_B64: &str = "aGVsbG8=";

/// Base64-encoded valid Rego policy content.
pub(crate) const VALID_REGO_B64: &str =
    "cGFja2FnZSByYnMKCmRlZmF1bHQgYWxsb3cgPSBmYWxzZQphbGxvdyB7IGlucHV0LnJvbGUgPSAiYWRtaW4iIH0=";

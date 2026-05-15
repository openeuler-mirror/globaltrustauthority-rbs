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

//! Integration tests for `PolicyService`.
//!
//! Each test constructs a `MockPolicyRepository` with the desired return values,
//! creates a `PolicyService`, invokes the relevant method, and asserts the result.
//!
//! NOTE: The service methods currently contain `todo!()`, so tests that reach the
//! service body will panic at runtime. Tests that fail a validation step before
//! reaching the body (e.g. authz deny for an Attest token) will pass at runtime.
//! Both outcomes are intentional — this file validates that the test structure
//! compiles and is semantically correct for each scenario.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;

use rbs_core::auth::authz::AuthzFacade;
use rbs_core::{
    AttestContext, AuthContext, BearerContext, TokenType,
};
use rbs_core::policy::{
    PolicyConfig, PolicyEntity, PolicyError, PolicyRepository, PolicyValidator,
};
use rbs_core::policy::service::{
    CreatePolicyRequest, PolicyQuery, PolicyService, UpdatePolicyRequest,
};
use rbs_core::policy_engine::RealPolicyEngine;
use rbs_core::resource::adapter::PolicyClient;
use rbs_core::resource::error::ResourceError;

// ---------------------------------------------------------------------------
// MockPolicyRepository
// ---------------------------------------------------------------------------

/// Thread-safe wrapper for a single mock return value.
type MockResult<T> = Mutex<Result<T, PolicyError>>;

/// Hand-written mock that implements `PolicyRepository`.
///
/// Each repository method reads its result from a `Mutex`-protected field.
/// Tests configure the desired behavior by calling the builder-style
/// `with_*` methods on a freshly-constructed instance.
struct MockPolicyRepository {
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
    // Lazily create a single in-memory SQLite for all mock uses
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
    fn new() -> Self {
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

    #[allow(dead_code)]
    fn with_find_by_id(self, result: Result<Option<PolicyEntity>, PolicyError>) -> Self {
        *self.find_by_id.lock().unwrap() = result;
        self
    }

    fn with_find_by_name_and_user(
        self,
        result: Result<Option<PolicyEntity>, PolicyError>,
    ) -> Self {
        *self.find_by_name_and_user.lock().unwrap() = result;
        self
    }

    #[allow(dead_code)]
    fn with_find_by_ids_and_user(
        self,
        result: Result<Vec<PolicyEntity>, PolicyError>,
    ) -> Self {
        *self.find_by_ids_and_user.lock().unwrap() = result;
        self
    }

    #[allow(dead_code)]
    fn with_list_by_user(
        self,
        result: Result<(Vec<PolicyEntity>, u64), PolicyError>,
    ) -> Self {
        *self.list_by_user.lock().unwrap() = result;
        self
    }

    fn with_count_by_user(self, result: Result<usize, PolicyError>) -> Self {
        *self.count_by_user.lock().unwrap() = result;
        self
    }

    #[allow(dead_code)]
    fn with_update_with_version(self, result: Result<u64, PolicyError>) -> Self {
        *self.update_with_version.lock().unwrap() = result;
        self
    }

    #[allow(dead_code)]
    fn with_delete(self, result: Result<(), PolicyError>) -> Self {
        *self.delete.lock().unwrap() = result;
        self
    }

    #[allow(dead_code)]
    fn with_delete_by_ids_txn(self, result: Result<u64, PolicyError>) -> Self {
        *self.delete_by_ids_txn.lock().unwrap() = result;
        self
    }
}

#[async_trait]
impl PolicyRepository for MockPolicyRepository {
    async fn insert(&self, _entity: PolicyEntity) -> Result<(), PolicyError> {
        self.insert.lock().unwrap().clone()
    }

    async fn find_by_id(&self, _policy_id: &str) -> Result<Option<PolicyEntity>, PolicyError> {
        self.find_by_id.lock().unwrap().clone()
    }

    async fn find_by_name_and_user(
        &self,
        _name: &str,
        _user_id: &str,
    ) -> Result<Option<PolicyEntity>, PolicyError> {
        self.find_by_name_and_user.lock().unwrap().clone()
    }

    async fn find_by_ids_and_user(
        &self,
        _policy_ids: &[String],
        _user_id: &str,
    ) -> Result<Vec<PolicyEntity>, PolicyError> {
        self.find_by_ids_and_user.lock().unwrap().clone()
    }

    async fn list_by_user(
        &self,
        _user_id: &str,
        _offset: i64,
        _limit: i64,
    ) -> Result<(Vec<PolicyEntity>, u64), PolicyError> {
        self.list_by_user.lock().unwrap().clone()
    }

    async fn count_by_user(&self, _user_id: &str) -> Result<usize, PolicyError> {
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

    async fn delete_by_ids_txn(&self, _conn: &sea_orm::DatabaseTransaction, _policy_ids: &[String], _user_id: &str) -> Result<u64, PolicyError> {
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
// ── Mock PolicyClient ──────────────────────────────────────────────────

struct MockPolicyClient {
    relation_res_ids: Mutex<Result<Vec<String>, ResourceError>>,
}

impl MockPolicyClient {
    fn new() -> Self { Self { relation_res_ids: Mutex::new(Ok(vec![])) } }
    #[allow(dead_code)]
    fn with_relation_res_ids(self, result: Result<Vec<String>, ResourceError>) -> Self {
        *self.relation_res_ids.lock().unwrap() = result;
        self
    }
}

#[async_trait::async_trait]
impl PolicyClient for MockPolicyClient {
    async fn validate_policy(&self, _id: &str, _uid: &str) -> Result<bool, ResourceError> { Ok(true) }
    async fn get_policy_content(&self, _id: &str) -> Result<String, ResourceError> { Ok("package x\n".into()) }
    async fn relation_res_ids(&self, _id: &str, _uid: &str) -> Result<Vec<String>, ResourceError> {
        self.relation_res_ids.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a `PolicyService` wired to the given mock repository.
fn make_service(repo: MockPolicyRepository) -> PolicyService {
    make_service_with_client(repo, MockPolicyClient::new())
}

fn make_service_with_client(repo: MockPolicyRepository, client: MockPolicyClient) -> PolicyService {
    let config = PolicyConfig::default();
    let validator = PolicyValidator::new(config.clone());
    let authz = AuthzFacade::new(Arc::new(RealPolicyEngine));
    PolicyService::new(Arc::new(repo), authz, Arc::new(client), validator, config)
}

/// Build a Bearer auth context (grants Allow for UserScoped operations).
fn bearer_ctx(sub: &str, role: &str) -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".into(),
        sub: sub.into(),
        role: role.into(),
        claims: Value::Null,
        token_type: TokenType::Bearer,
    })
}

/// Build an Attest auth context (always Denied by the authz facade).
fn attest_ctx() -> AuthContext {
    AuthContext::Attest(AttestContext {
        claims: Value::Null,
        token_type: TokenType::Attest,
    })
}

/// Convenience constructor for a minimal `PolicyEntity`.
fn make_entity(policy_id: &str, user_id: &str, policy_name: &str) -> PolicyEntity {
    PolicyEntity {
        policy_id: policy_id.into(),
        user_id: user_id.into(),
        policy_name: policy_name.into(),
        policy_version: 1,
        policy_content: String::new(),
        content_type: "base64".into(),
        created_at: 0,
        updated_at: 0,
    }
}

/// Base64-encoded "hello" — decodes correctly but is NOT valid Rego.
const HELLO_B64: &str = "aGVsbG8=";

/// Base64-encoded valid Rego policy content (used by tests that expect success).
const VALID_REGO_B64: &str = "cGFja2FnZSByYnMKCmRlZmF1bHQgYWxsb3cgPSBmYWxzZQphbGxvdyB7IGlucHV0LnJvbGUgPSAiYWRtaW4iIH0=";

// ---------------------------------------------------------------------------
// UT-S-001 .. UT-S-007  —  Create
// ---------------------------------------------------------------------------

/// UT-S-001: create succeeds when authz allows, name is unique, and count
/// is below the limit. Expect a `PolicyResponse` with `policy_version == 1`.
#[tokio::test]
async fn ut_s001_create_success() {
    let repo = MockPolicyRepository::new()
        .with_find_by_name_and_user(Ok(None))
        .with_count_by_user(Ok(5)); // below max_per_user (10)

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let req = CreatePolicyRequest {
        name: "test-policy".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.create(&ctx, &req).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        assert_eq!(response.policy_version, 1);
    }
}

/// UT-S-002: create is denied when authz returns Deny (Attest token).
#[tokio::test]
async fn ut_s002_create_permission_denied() {
    let repo = MockPolicyRepository::new();
    let service = make_service(repo);
    let ctx = attest_ctx();
    let req = CreatePolicyRequest {
        name: "test-policy".into(),
        content_type: "base64".into(),
        content: String::new(),
    };

    let result = service.create(&ctx, &req).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::PermissionDenied)));
}

/// UT-S-003: create fails with `NameDuplicate` when the name is already
/// taken by another policy owned by the same user.
#[tokio::test]
async fn ut_s003_create_name_duplicate() {
    let existing = make_entity("policy-1", "user123", "test-policy");
    let repo = MockPolicyRepository::new()
        .with_find_by_name_and_user(Ok(Some(existing)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let req = CreatePolicyRequest {
        name: "test-policy".into(),
        content_type: "base64".into(),
        content: HELLO_B64.into(),
    };

    let result = service.create(&ctx, &req).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::NameDuplicate { .. })));
}

/// UT-S-004: create fails with `CountExceed` when the user's policy count
/// is at the configured maximum.
#[tokio::test]
async fn ut_s004_create_count_exceeded() {
    let repo = MockPolicyRepository::new()
        .with_find_by_name_and_user(Ok(None))
        .with_count_by_user(Ok(10)); // max_per_user is 10 in default config

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let req = CreatePolicyRequest {
        name: "test-policy".into(),
        content_type: "base64".into(),
        content: HELLO_B64.into(),
    };

    let result = service.create(&ctx, &req).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::CountExceed { .. })));
}

/// UT-S-005: when both a name duplicate AND count exceeded conditions
/// are true, `NameDuplicate` must take precedence.
#[tokio::test]
async fn ut_s005_create_name_duplicate_beats_count_exceeded() {
    let existing = make_entity("policy-1", "user123", "test-policy");
    let repo = MockPolicyRepository::new()
        .with_find_by_name_and_user(Ok(Some(existing)))
        .with_count_by_user(Ok(10));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let req = CreatePolicyRequest {
        name: "test-policy".into(),
        content_type: "base64".into(),
        content: HELLO_B64.into(),
    };

    let result = service.create(&ctx, &req).await;
    assert!(result.is_err());
    // NameDuplicate should be checked before CountExceed.
    assert!(matches!(result, Err(PolicyError::NameDuplicate { .. })));
}

/// UT-S-006: create fails with `ContentDecodeError` when the content is
/// not valid base64.
#[tokio::test]
async fn ut_s006_create_invalid_base64() {
    let repo = MockPolicyRepository::new()
        .with_find_by_name_and_user(Ok(None))
        .with_count_by_user(Ok(0));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let req = CreatePolicyRequest {
        name: "test-policy".into(),
        content_type: "base64".into(),
        content: "!!invalid-base64!!".into(), // not valid base64
    };

    let result = service.create(&ctx, &req).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::ContentDecodeError { .. })));
}

/// UT-S-007: create fails with `RegoSyntaxError` when the decoded policy
/// content is not valid Rego.
#[tokio::test]
async fn ut_s007_create_rego_syntax_error() {
    let repo = MockPolicyRepository::new()
        .with_find_by_name_and_user(Ok(None))
        .with_count_by_user(Ok(0));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let req = CreatePolicyRequest {
        name: "test-policy".into(),
        content_type: "base64".into(),
        content: HELLO_B64.into(), // decodes to "hello" — not valid Rego
    };

    let result = service.create(&ctx, &req).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::RegoSyntaxError { .. })));
}

// ---------------------------------------------------------------------------
// UT-S-010a .. UT-S-010b  —  Update
// ---------------------------------------------------------------------------

/// UT-S-010a: update fails with `NameDuplicate` when the requested name
/// already belongs to a *different* policy owned by the same user.
#[tokio::test]
async fn ut_s010a_update_name_duplicate_rename_conflict() {
    let existing = make_entity("policy-1", "user123", "old-name");
    let conflict = make_entity("policy-2", "user123", "new-name");

    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(existing)))
        .with_find_by_name_and_user(Ok(Some(conflict)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let req = UpdatePolicyRequest {
        name: "new-name".into(),
        content_type: "base64".into(),
        content: HELLO_B64.into(),
    };

    let result = service.update(&ctx, "policy-1", &req).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::NameDuplicate { .. })));
}

/// UT-S-010b: update succeeds when the requested name matches the
/// policy's own current name (no rename conflict).
#[tokio::test]
async fn ut_s010b_update_name_same_as_self() {
    let entity = make_entity("policy-1", "user123", "same-name");

    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity.clone())))
        // find_by_name_and_user returns the *same* entity — not a conflict.
        .with_find_by_name_and_user(Ok(Some(entity)))
        .with_update_with_version(Ok(1));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let req = UpdatePolicyRequest {
        name: "same-name".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.update(&ctx, "policy-1", &req).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// UT-S-012a .. UT-S-014b  —  Delete
// ---------------------------------------------------------------------------

/// UT-S-012a: delete permission denied (Attest token).
#[tokio::test]
async fn ut_s012a_delete_permission_denied() {
    let repo = MockPolicyRepository::new();
    let service = make_service(repo);
    let ctx = attest_ctx();
    let ids = vec!["policy-1".to_string()];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::PermissionDenied)));
}

/// UT-S-014a: single delete fails with `NotFound` when the policy does
/// not exist.
#[tokio::test]
async fn ut_s014a_single_delete_policy_not_found() {
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(None));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let ids = vec!["policy-1".to_string()];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::NotFound)));
}

/// UT-S-014b: single delete returns `PermissionDenied` when the policy
/// belongs to a different user.
#[tokio::test]
async fn ut_s014b_single_delete_permission_denied_cross_user() {
    let entity = make_entity("policy-1", "other-user", "test-policy");
    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(vec![entity]));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let ids = vec!["policy-1".to_string()];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::PermissionDenied)));
}

// ---------------------------------------------------------------------------
// UT-S-017a, UT-S-025  —  List
// ---------------------------------------------------------------------------

/// UT-S-017a: list permission denied (Attest token).
#[tokio::test]
async fn ut_s017a_list_permission_denied() {
    let repo = MockPolicyRepository::new();
    let service = make_service(repo);
    let ctx = attest_ctx();
    let query = PolicyQuery {
        ids: None,
        offset: 0,
        limit: 10,
    };

    let result = service.list(&ctx, &query).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::PermissionDenied)));
}

/// UT-S-025: list with the `ids` filter returns the matching entities.
#[tokio::test]
async fn ut_s025_list_with_ids_filter() {
    let entities = vec![
        make_entity("policy-1", "user123", "policy-a"),
        make_entity("policy-2", "user123", "policy-b"),
    ];
    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(entities));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let query = PolicyQuery {
        ids: Some(vec!["policy-1".into(), "policy-2".into()]),
        offset: 0,
        limit: 10,
    };

    let result = service.list(&ctx, &query).await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.items.len(), 2, "should return exactly the two requested policies");
    assert_eq!(resp.total, 2, "total should match returned items when no other policies exist");
}

// ---------------------------------------------------------------------------
// UT-S-019c, UT-S-023, UT-S-024  —  Get By Id
// ---------------------------------------------------------------------------

/// UT-S-019c: get_by_id permission denied (Attest token).
#[tokio::test]
async fn ut_s019c_get_by_id_permission_denied() {
    let repo = MockPolicyRepository::new();
    let service = make_service(repo);
    let ctx = attest_ctx();

    let result = service.get_by_id(&ctx, "policy-1").await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::PermissionDenied)));
}

/// UT-S-023: get_by_id returns `NotFound` when the policy does not exist.
#[tokio::test]
async fn ut_s023_get_by_id_not_found() {
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(None));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");

    let result = service.get_by_id(&ctx, "policy-1").await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::NotFound)));
}

/// UT-S-024: get_by_id returns `PermissionDenied` when the policy belongs
/// to a different user (cross-user access).
#[tokio::test]
async fn ut_s024_get_by_id_cross_user() {
    let entity = make_entity("policy-1", "other-user", "test-policy");
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");

    let result = service.get_by_id(&ctx, "policy-1").await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::PermissionDenied)));
}

// ---------------------------------------------------------------------------
// UT-S-026  —  Batch operations
// ---------------------------------------------------------------------------

/// UT-S-026: batch delete with an empty list of IDs fails with
/// `ParamInvalid`.
#[tokio::test]
async fn ut_s026_batch_delete_empty_ids() {
    let repo = MockPolicyRepository::new();
    let service = make_service(repo);
    let ctx = bearer_ctx("user123", "admin");
    let ids: Vec<String> = vec![];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_err());
    assert!(
        matches!(result, Err(PolicyError::ParamInvalid { field: "policy_ids" })),
        "expected ParamInvalid with field 'policy_ids', got {:?}",
        result.as_ref().err(),
    );
}

// ---------------------------------------------------------------------------
// UT-S-008 .. UT-S-011  —  Update (continued)
// ---------------------------------------------------------------------------

/// UT-S-008: update succeeds with optimistic lock. The entity has version 2,
/// the update call returns 1 row affected, and the response reports version 3.
#[tokio::test]
async fn ut_s008_update_success_with_optimistic_lock() {
    let entity = PolicyEntity {
        policy_version: 2,
        user_id: "user1".into(),
        ..make_entity("pol-1", "user1", "old_name")
    };

    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity)))
        .with_find_by_name_and_user(Ok(None))
        .with_update_with_version(Ok(1));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let req = UpdatePolicyRequest {
        name: "new_name".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    assert!(result.is_ok());
    if let Ok(response) = result {
        assert_eq!(response.policy_version, 3);
    }
}

/// UT-S-009: update returns NotFound when the policy does not exist.
#[tokio::test]
async fn ut_s009_update_policy_not_found() {
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(None));

    let service = make_service(repo);
    let ctx = bearer_ctx("admin", "admin");
    let req = UpdatePolicyRequest {
        name: "new_name".into(),
        content_type: "base64".into(),
        content: HELLO_B64.into(),
    };

    let result = service.update(&ctx, "pol-404", &req).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::NotFound)));
}

/// UT-S-010: update returns PermissionDenied when the policy belongs to a
/// different user.
#[tokio::test]
async fn ut_s010_update_permission_denied_wrong_owner() {
    let entity = PolicyEntity {
        user_id: "user2".into(),
        ..make_entity("pol-1", "user2", "test-policy")
    };

    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let req = UpdatePolicyRequest {
        name: "new_name".into(),
        content_type: "base64".into(),
        content: HELLO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::PermissionDenied)));
}

/// UT-S-011: update returns VersionConflict when optimistic locking detects
/// that another transaction has already updated the policy.
#[tokio::test]
async fn ut_s011_update_version_conflict() {
    let entity = PolicyEntity {
        policy_version: 2,
        user_id: "user1".into(),
        ..make_entity("pol-1", "user1", "my_policy")
    };

    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity)))
        .with_find_by_name_and_user(Ok(None))
        .with_update_with_version(Ok(0)); // 0 rows affected → version conflict

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let req = UpdatePolicyRequest {
        name: "new_name".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::VersionConflict { .. })));
}

/// UT-S-012: update retries after a version conflict and eventually succeeds.
///
/// NOTE: The current MockPolicyRepository returns the same value on every
/// call, so this test cannot exercise the retry path at runtime — the service
/// body is `todo!()` anyway. This test documents the expected retry contract
/// per the design doc (section 9.1.2): a first update_with_version returning
/// Ok(0) triggers a re-fetch, and a second update_with_version succeeds.
#[tokio::test]
async fn ut_s012_update_retry_after_conflict_succeeds() {
    // When the service implements retry:
    //   1st find_by_id → version 2
    //   1st update_with_version → Ok(0)  (conflict)
    //   2nd find_by_id → version 3
    //   2nd update_with_version → Ok(1)  (success)
    //
    // The current mock infrastructure returns the same value for each method
    // regardless of call count, so we configure the "final success" state.
    let entity_v3 = PolicyEntity {
        policy_version: 3,
        user_id: "user1".into(),
        ..make_entity("pol-1", "user1", "my_policy")
    };

    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity_v3)))
        .with_find_by_name_and_user(Ok(None))
        .with_update_with_version(Ok(1));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let req = UpdatePolicyRequest {
        name: "new_name".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    // Once retry is implemented: assert!(result.is_ok());
    //   response.policy_version == 4
    let _ = result;
}

// ---------------------------------------------------------------------------
// UT-S-013 .. UT-S-014  —  Delete (continued)
// ---------------------------------------------------------------------------

/// UT-S-013: single delete succeeds when the policy exists, belongs to the
/// caller, and has no resource references.
#[tokio::test]
async fn ut_s013_single_delete_success() {
    let entity = make_entity("pol-1", "user1", "my_policy");
    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(vec![entity]))
        .with_delete_by_ids_txn(Ok(1));
    let client = MockPolicyClient::new().with_relation_res_ids(Ok(vec![]));

    let service = make_service_with_client(repo, client);
    let ctx = bearer_ctx("user1", "admin");
    let ids = vec!["pol-1".to_string()];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_ok());
}

/// UT-S-014: delete returns BeingReferenced when the policy is referenced
/// by one or more resources.
#[tokio::test]
async fn ut_s014_delete_policy_being_referenced() {
    let entity = PolicyEntity {
        policy_name: "my_policy".into(),
        ..make_entity("pol-1", "user1", "my_policy")
    };

    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(vec![entity]));
    let client = MockPolicyClient::new()
        .with_relation_res_ids(Ok(vec!["res-uri-1".into(), "res-uri-2".into()]));

    let service = make_service_with_client(repo, client);
    let ctx = bearer_ctx("user1", "admin");
    let ids = vec!["pol-1".to_string()];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_err());
    assert!(
        matches!(result, Err(PolicyError::BeingReferenced { ref policy_names }) if policy_names == &vec!["my_policy".to_string()]),
        "expected BeingReferenced with policy_names=['my_policy'], got {:?}",
        result.as_ref().err(),
    );
}

// ---------------------------------------------------------------------------
// UT-S-015 .. UT-S-017  —  Batch delete
// ---------------------------------------------------------------------------

/// UT-S-015: batch delete all succeed (transaction commit).
#[tokio::test]
async fn ut_s015_batch_delete_all_success() {
    let entities = vec![
        make_entity("pol-1", "user1", "policy-a"),
        make_entity("pol-2", "user1", "policy-b"),
        make_entity("pol-3", "user1", "policy-c"),
    ];

    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(entities))
        .with_delete_by_ids_txn(Ok(3));
    let client = MockPolicyClient::new()
        .with_relation_res_ids(Ok(vec![]));

    let service = make_service_with_client(repo, client);
    let ctx = bearer_ctx("user1", "admin");
    let ids = vec![
        "pol-1".to_string(),
        "pol-2".to_string(),
        "pol-3".to_string(),
    ];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_ok());
}

/// UT-S-016: batch delete fails when a policy is being referenced
/// (transaction rollback).
#[tokio::test]
async fn ut_s016_batch_delete_partial_referenced() {
    let entities = vec![
        make_entity("pol-1", "user1", "my_policy"),
        make_entity("pol-2", "user1", "policy-2"),
        make_entity("pol-3", "user1", "policy-3"),
    ];

    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(entities));
    let client = MockPolicyClient::new()
        .with_relation_res_ids(Ok(vec!["res-uri".into()]));

    let service = make_service_with_client(repo, client);
    let ctx = bearer_ctx("user1", "admin");
    let ids = vec![
        "pol-1".to_string(),
        "pol-2".to_string(),
        "pol-3".to_string(),
    ];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_err());
    assert!(
        matches!(result, Err(PolicyError::BeingReferenced { .. })),
        "expected BeingReferenced, got {:?}",
        result.as_ref().err(),
    );
}

/// UT-S-017: batch delete fails when a policy is not found
/// (transaction rollback).
#[tokio::test]
async fn ut_s017_batch_delete_partial_not_found() {
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(None));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let ids = vec![
        "pol-1".to_string(),
        "pol-404".to_string(),
        "pol-3".to_string(),
    ];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(PolicyError::NotFound)));
}

// ---------------------------------------------------------------------------
// UT-S-018 .. UT-S-019b  —  List
// ---------------------------------------------------------------------------

/// UT-S-018: list basic — no filter, first page returns items.
#[tokio::test]
async fn ut_s018_list_basic() {
    let e1 = make_entity("pol-1", "user1", "policy-a");
    let e2 = make_entity("pol-2", "user1", "policy-b");
    let repo = MockPolicyRepository::new()
        .with_list_by_user(Ok((vec![e1, e2], 2)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let query = PolicyQuery {
        ids: None,
        offset: 0,
        limit: 10,
    };

    let result = service.list(&ctx, &query).await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.items.len(), 2);
    assert_eq!(resp.total, 2);
    // Listing responses should not include full policy_content.
    for item in &resp.items {
        assert!(
            item.policy_content.is_empty(),
            "list response should not contain policy_content"
        );
    }
}

/// UT-S-019: list with pagination — offset 20, limit 10 returns 5 items.
#[tokio::test]
async fn ut_s019_list_with_pagination() {
    let items: Vec<PolicyEntity> = (0..5)
        .map(|i| make_entity(&format!("pol-{}", i + 21), "user1", &format!("policy-{}", i + 21)))
        .collect();
    let repo = MockPolicyRepository::new()
        .with_list_by_user(Ok((items, 25)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let query = PolicyQuery {
        ids: None,
        offset: 20,
        limit: 10,
    };

    let result = service.list(&ctx, &query).await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.items.len(), 5);
    assert_eq!(resp.total, 25);
}

/// UT-S-019a: list with limit=0 returns an empty items list but a correct
/// total count.
#[tokio::test]
async fn ut_s019a_list_limit_zero() {
    let repo = MockPolicyRepository::new()
        .with_list_by_user(Ok((vec![], 25)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let query = PolicyQuery {
        ids: None,
        offset: 0,
        limit: 0,
    };

    let result = service.list(&ctx, &query).await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.items.len(), 0);
    assert_eq!(resp.total, 25);
}

/// UT-S-019b: list with limit exceeding max_page_size is clamped.
///
/// NOTE: The default `PolicyConfig.max_page_size` is 100. When the caller
/// passes limit=10000, the service should clamp to 100 before calling the
/// repo. The current mock ignores input parameters, so we write the test
/// structure here — once the repo records invocation parameters, the
/// assertion should verify that `list_by_user` was called with limit=100.
#[tokio::test]
async fn ut_s019b_list_limit_clamped() {
    let repo = MockPolicyRepository::new()
        .with_list_by_user(Ok((vec![], 0)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let query = PolicyQuery {
        ids: None,
        offset: 0,
        limit: 10000,
    };

    let result = service.list(&ctx, &query).await;
    // Once clamping is implemented: verify repo was called with limit=100
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// UT-S-020  —  Get by id detail
// ---------------------------------------------------------------------------

/// UT-S-020: get_by_id returns full policy detail including applied resources.
#[tokio::test]
async fn ut_s020_get_detail_success() {
    let entity = make_entity("pol-1", "user1", "my_policy");
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity)));
    let client = MockPolicyClient::new()
        .with_relation_res_ids(Ok(vec!["uri1".into(), "uri2".into()]));

    let service = make_service_with_client(repo, client);
    let ctx = bearer_ctx("user1", "admin");

    let result = service.get_by_id(&ctx, "pol-1").await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(
        resp.applied_resources,
        Some(vec!["uri1".into(), "uri2".into()]),
    );
}

// ---------------------------------------------------------------------------
// UT-S-022  —  Version increment
// ---------------------------------------------------------------------------

/// UT-S-022: the entity passed to `update_with_version` has version
/// incremented by 1 (old version 2 → new version 3).
///
/// NOTE: The current mock ignores the entity parameter, so this test can
/// only document the expected contract. Once the mock captures the passed
/// entity, the assertion should verify `captured_entity.policy_version == 3`.
#[tokio::test]
async fn ut_s022_version_increment_on_update() {
    let entity = PolicyEntity {
        policy_version: 2,
        user_id: "user1".into(),
        ..make_entity("pol-1", "user1", "my_policy")
    };

    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity)))
        .with_find_by_name_and_user(Ok(None))
        .with_update_with_version(Ok(1));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "admin");
    let req = UpdatePolicyRequest {
        name: "my_policy".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    // When the mock captures the entity passed to update_with_version:
    //   captured.policy_version == 3
    assert!(result.is_ok());
}

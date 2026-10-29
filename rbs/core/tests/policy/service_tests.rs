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

//! Service-level tests for `PolicyService` update and delete operations.

use std::sync::Arc;

use base64::Engine as _;

use rbs_core::policy::PolicyError;
use rbs_core::policy::service::{CreatePolicyRequest, PolicyQuery, UpdatePolicyRequest};
use rbs_core::resource::error::ResourceError;

use super::common::*;

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_Update_006 — 更新策略-参数校验失败
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_Update_006
/// Update with a name containing a blacklisted character returns NameInvalid.
#[tokio::test]
async fn test_policy_update_006_name_blacklist_rejected() {
    let repo = MockPolicyRepository::new();
    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "user");
    let req = UpdatePolicyRequest {
        name: "bad<name".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Update_006
/// Update with a non-base64 content_type returns UnsupportedContentType.
#[tokio::test]
async fn test_policy_update_006_content_type_not_base64_rejected() {
    let entity = make_entity("pol-1", "user1", "my_policy");
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "user");
    let req = UpdatePolicyRequest {
        name: "my_policy".into(),
        content_type: "plain".into(),
        content: HELLO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    assert!(matches!(result, Err(PolicyError::UnsupportedContentType { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Update_006
/// Update with decoded content exceeding 128KB returns ContentTooLarge.
#[tokio::test]
async fn test_policy_update_006_content_too_large_rejected() {
    let entity = make_entity("pol-1", "user1", "my_policy");
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity)));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "user");
    let big = "x".repeat(129 * 1024);
    let encoded = base64::engine::general_purpose::STANDARD.encode(big.as_bytes());
    let req = UpdatePolicyRequest {
        name: "my_policy".into(),
        content_type: "base64".into(),
        content: encoded,
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    assert!(matches!(result, Err(PolicyError::ContentTooLarge { .. })));
}

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_Update_007 — 更新策略-三项字段均缺省
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_Update_007
/// When name/content_type/content are all the same as the existing values,
/// the update still executes and policy_version increments by 1.
#[tokio::test]
async fn test_policy_update_007_all_fields_same_version_increments() {
    let entity = rbs_core::policy::PolicyEntity {
        policy_version: 2,
        policy_content: VALID_REGO_B64.into(),
        ..make_entity("pol-1", "user1", "my_policy")
    };
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(entity)))
        .with_find_by_name_and_user(Ok(None))
        .with_update_with_version(Ok(1));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "user");
    let req = UpdatePolicyRequest {
        name: "my_policy".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.policy_version, 3, "version should increment from 2 to 3");
}

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_Delete_001 — 单条删除策略成功
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_Delete_001
/// Deleting a single existing, non-referenced policy succeeds (returns Ok).
#[tokio::test]
async fn test_policy_delete_001_single_delete_success() {
    let entity = make_entity("pol-1", "user1", "my_policy");
    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(vec![entity]))
        .with_delete_by_ids_txn(Ok(1));
    let client = MockPolicyClient::new().with_relation_res_ids(Ok(vec![]));

    let service = make_service_with_client(repo, client);
    let ctx = bearer_ctx("user1", "user");
    let ids = vec!["pol-1".to_string()];

    let result = service.delete(&ctx, &ids).await;
    assert!(result.is_ok());
}

// ===========================================================================
// Error mapping around validation, authorization faults and transaction setup
// ===========================================================================

/// A create whose name fails validation is rejected before the duplicate/quota
/// checks (no repository call is needed).
#[tokio::test]
async fn test_policy_create_invalid_name_rejected() {
    let service = make_service(MockPolicyRepository::new());
    let ctx = bearer_ctx("user1", "user");
    let req = CreatePolicyRequest {
        name: "bad<name".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.create(&ctx, &req).await;
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })), "got {result:?}");
}

/// Update is denied for an Attest token (the authz facade requires a Bearer
/// user subject for policy administration).
#[tokio::test]
async fn test_policy_update_attest_ctx_denied() {
    let service = make_service(MockPolicyRepository::new().with_find_by_id(Ok(Some(make_entity("pol-1", "user1", "my_policy")))));
    let ctx = attest_ctx();
    let req = UpdatePolicyRequest {
        name: "my_policy".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    assert!(matches!(result, Err(PolicyError::PermissionDenied)), "got {result:?}");
}

/// Renaming a policy onto a name already used by another policy of the same
/// user is rejected as NameDuplicate (the conflict check only runs on rename).
#[tokio::test]
async fn test_policy_update_rename_conflict_rejected() {
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(make_entity("pol-1", "user1", "my_policy"))))
        .with_find_by_name_and_user(Ok(Some(make_entity("pol-2", "user1", "taken_name"))));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "user");
    let req = UpdatePolicyRequest {
        name: "taken_name".into(),
        content_type: "base64".into(),
        content: VALID_REGO_B64.into(),
    };

    let result = service.update(&ctx, "pol-1", &req).await;
    assert!(
        matches!(&result, Err(PolicyError::NameDuplicate { name }) if name == "taken_name"),
        "got {result:?}"
    );
}

/// A failing resource-relation lookup during delete aborts the delete with the
/// underlying error (the policy stays referenced-or-unknown, never deleted).
#[tokio::test]
async fn test_policy_delete_relation_check_error() {
    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(vec![make_entity("pol-1", "user1", "my_policy")]));
    let client = MockPolicyClient::new()
        .with_relation_res_ids(Err(ResourceError::BackendError { detail: "db down".into() }));

    let service = make_service_with_client(repo, client);
    let ctx = bearer_ctx("user1", "user");

    let result = service.delete(&ctx, &["pol-1".to_string()]).await;
    assert!(result.is_err(), "relation lookup failure must abort the delete");
}

/// When the transactional delete removes fewer rows than requested (a row
/// vanished between the pre-check and the transaction), the delete is reported
/// as NotFound and rolled back.
#[tokio::test]
async fn test_policy_delete_affected_mismatch_returns_not_found() {
    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(vec![make_entity("pol-1", "user1", "my_policy")]))
        .with_delete_by_ids_txn(Ok(0));

    let service = make_service_with_client(repo, MockPolicyClient::new());
    let ctx = bearer_ctx("user1", "user");

    let result = service.delete(&ctx, &["pol-1".to_string()]).await;
    assert!(matches!(result, Err(PolicyError::NotFound)), "got {result:?}");
}

/// A transaction that cannot even begin surfaces as a database parameter
/// failure (the only 4xx-shaped error the service has for storage faults).
#[tokio::test]
async fn test_policy_delete_txn_begin_error() {
    let db = sea_orm::Database::connect("sqlite::memory:")
        .await
        .expect("sqlite connect");
    db.close_by_ref().await.expect("close pool");

    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(vec![make_entity("pol-1", "user1", "my_policy")]))
        .with_db_connection(Arc::new(db));

    let service = make_service_with_client(repo, MockPolicyClient::new());
    let ctx = bearer_ctx("user1", "user");

    let result = service.delete(&ctx, &["pol-1".to_string()]).await;
    assert!(
        matches!(&result, Err(PolicyError::ParamInvalid { field }) if *field == "db"),
        "got {result:?}"
    );
}

/// An explicitly empty `ids` filter is a valid (empty) query and must not fall
/// through to the unfiltered list.
#[tokio::test]
async fn test_policy_list_empty_ids_filter_returns_empty() {
    let repo = MockPolicyRepository::new()
        .with_find_by_ids_and_user(Ok(vec![make_entity("pol-1", "user1", "my_policy")]));

    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "user");
    let query = PolicyQuery { ids: Some(vec![]), offset: 0, limit: 10 };

    let resp = service.list(&ctx, &query).await.expect("empty filter list");
    assert!(resp.items.is_empty(), "empty id filter must return no items");
    assert_eq!(resp.total_count, 0);
}

/// get_by_id surfaces a failing resource-relation lookup instead of returning
/// a policy without its applied resources.
#[tokio::test]
async fn test_policy_get_by_id_relation_error() {
    let repo = MockPolicyRepository::new()
        .with_find_by_id(Ok(Some(make_entity("pol-1", "user1", "my_policy"))));
    let client = MockPolicyClient::new()
        .with_relation_res_ids(Err(ResourceError::BackendError { detail: "db down".into() }));

    let service = make_service_with_client(repo, client);
    let ctx = bearer_ctx("user1", "user");

    let result = service.get_by_id(&ctx, "pol-1").await;
    assert!(result.is_err(), "relation lookup failure must abort get_by_id");
}

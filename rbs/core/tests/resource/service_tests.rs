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

//! Service-level tests for `ResourceService`.

use serde_json::json;

use rbs_core::auth::context::{AuthContext, BearerContext, TokenType};
use rbs_core::resource::error::ResourceError;
use rbs_core::resource::{CreateResourceRequest, UpdateResourceRequest};

use super::common::*;

const EC_P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;

fn bearer_ctx_no_pubkey() -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: TEST_USER.to_string(),
        role: "user".to_string(),
        claims: json!({}),
        token_type: TokenType::Bearer,
    })
}

fn bearer_ctx_with_pubkey() -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: TEST_USER.to_string(),
        role: "user".to_string(),
        claims: json!({ "enc-pubkey": EC_P256_JWK }),
        token_type: TokenType::Bearer,
    })
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Create_003 — 创建资源-仅必填字段
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_003
/// Create with only policy_id (optional fields omitted) succeeds;
/// export_mode defaults to "jwe", content_type and additional_info are None.
#[tokio::test]
async fn test_res_create_003_only_required_fields() {
    let svc = default_service();
    let ctx = bearer_ctx(TEST_USER);
    let req = CreateResourceRequest {
        policy_id: "pol-001".to_string(),
        content_type: None,
        export_mode: None,
        additional_info: None,
    };

    let result = svc.create(&ctx, TEST_URI, &req).await;
    assert!(result.is_ok(), "create with only policy_id should succeed");
    let resp = result.unwrap();
    assert_eq!(resp.export_mode, "jwe", "default export_mode should be jwe");
    assert!(resp.content_type.is_none(), "content_type should be None");
    assert!(resp.additional_info.is_none(), "additional_info should be None");
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Create_009 — 创建资源-policy_id无效
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_009
/// Create with an invalid policy_id returns PolicyIdInvalid.
#[tokio::test]
async fn test_res_create_009_invalid_policy_id() {
    let repo = MockResourceRepository::new();
    let policy = {
        let p = MockPolicyClient::new();
        *p.validate_result.lock().unwrap() = Ok(false);
        p
    };
    let svc = make_service(repo, policy, MockAuthzChecker::new(), MockResourceBackend::new());
    let ctx = bearer_ctx(TEST_USER);
    let req = create_req();

    let result = svc.create(&ctx, TEST_URI, &req).await;
    assert!(matches!(result, Err(ResourceError::PolicyIdInvalid(_))));
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Create_010 — 创建资源-后端资源不存在
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_010
/// Create when backend reports resource does not exist returns BackendNotFound.
#[tokio::test]
async fn test_res_create_010_backend_not_found() {
    let backend = {
        let b = MockResourceBackend::new();
        *b.check_exists.lock().unwrap() = Ok(false);
        b
    };
    let svc = make_service(MockResourceRepository::new(), MockPolicyClient::new(), MockAuthzChecker::new(), backend);
    let ctx = bearer_ctx(TEST_USER);
    let req = create_req();

    let result = svc.create(&ctx, TEST_URI, &req).await;
    assert!(matches!(result, Err(ResourceError::BackendNotFound)));
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Get_003 — 获取资源-授权拒绝返回404
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Get_003
/// When authz denies get_content, the error is mapped to NotFound (not 403).
#[tokio::test]
async fn test_res_get_003_authz_denied_returns_not_found() {
    let repo = {
        let r = MockResourceRepository::new();
        *r.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        r
    };
    let policy = MockPolicyClient::new();
    let authz = MockAuthzChecker::denying();
    let svc = make_service(repo, policy, authz, MockResourceBackend::new());
    let ctx = bearer_ctx_with_pubkey();

    let result = svc.get_content(&ctx, TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::NotFound)),
        "authz denial should map to NotFound, got {:?}", result.as_ref().err());
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Get_004 — 获取资源-公钥缺失导致JWE失败
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Get_004
/// Bearer context without enc-pubkey causes JweEncryptionFailed.
#[tokio::test]
async fn test_res_get_004_missing_pubkey_jwe_failed() {
    let repo = {
        let r = MockResourceRepository::new();
        *r.find_by_uri_result.lock().unwrap() = Ok(Some(make_entity()));
        r
    };
    let svc = make_service(repo, MockPolicyClient::new(), MockAuthzChecker::new(), MockResourceBackend::new());
    let ctx = bearer_ctx_no_pubkey();

    let result = svc.get_content(&ctx, TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::JweEncryptionFailed { .. })));
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Update_001 — 更新已有资源
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Update_001
/// Update an existing resource (owner matches, optimistic lock passes) returns Ok.
#[tokio::test]
async fn test_res_update_001_existing_resource() {
    let entity = make_entity();
    let repo = {
        let r = MockResourceRepository::new();
        *r.find_by_uri_result.lock().unwrap() = Ok(Some(entity));
        *r.update_result.lock().unwrap() = Ok(1);
        r
    };
    let svc = make_service(repo, MockPolicyClient::new(), MockAuthzChecker::new(), MockResourceBackend::new());
    let ctx = bearer_ctx(TEST_USER);
    let req = update_req();

    let result = svc.update(&ctx, TEST_URI, &req).await;
    assert!(result.is_ok(), "update of existing resource should succeed");
    let (resp, created) = result.unwrap();
    assert!(!created, "should not be a create path");
    assert_eq!(resp.policy_id, "pol-001");
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Update_003 — 更新资源-可选字段缺省取existing值
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Update_003
/// When optional fields (content_type/export_mode/additional_info) are None
/// in the update request, the response retains the existing entity's values.
#[tokio::test]
async fn test_res_update_003_optional_fields_take_existing() {
    let mut entity = make_entity();
    entity.content_type = Some("json".to_string());
    entity.export_mode = "jwe".to_string();
    entity.res_info = Some("existing-info".to_string());

    let repo = {
        let r = MockResourceRepository::new();
        *r.find_by_uri_result.lock().unwrap() = Ok(Some(entity));
        *r.update_result.lock().unwrap() = Ok(1);
        r
    };
    let svc = make_service(repo, MockPolicyClient::new(), MockAuthzChecker::new(), MockResourceBackend::new());
    let ctx = bearer_ctx(TEST_USER);
    let req = UpdateResourceRequest {
        policy_id: Some("pol-001".to_string()),
        content_type: None,
        export_mode: None,
        additional_info: None,
    };

    let result = svc.update(&ctx, TEST_URI, &req).await;
    assert!(result.is_ok());
    let (resp, _) = result.unwrap();
    assert_eq!(resp.content_type, Some("json".to_string()), "content_type should retain existing");
    assert_eq!(resp.export_mode, "jwe", "export_mode should retain existing");
    assert_eq!(resp.additional_info, Some("existing-info".to_string()), "additional_info should retain existing");
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Delete_002 — 删除不存在资源
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Delete_002
/// Deleting a non-existent resource returns NotFound.
#[tokio::test]
async fn test_res_delete_002_not_found() {
    let repo = {
        let r = MockResourceRepository::new();
        *r.find_by_uri_result.lock().unwrap() = Ok(None);
        r
    };
    let svc = make_service(repo, MockPolicyClient::new(), MockAuthzChecker::new(), MockResourceBackend::new());
    let ctx = bearer_ctx(TEST_USER);

    let result = svc.delete(&ctx, TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::NotFound)));
}

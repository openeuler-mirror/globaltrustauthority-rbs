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

use base64::Engine as _;
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
        content: None,
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
/// When authz denies get_content, the error is mapped to NotFoundOrDenied
/// (404), not 403. The read paths return this same variant for a genuinely
/// missing resource, so callers cannot tell "missing" from "denied"
/// (anti-enumeration); the shared body names both causes.
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
    assert!(matches!(result, Err(ResourceError::NotFoundOrDenied)),
        "authz denial should map to NotFoundOrDenied, got {:?}", result.as_ref().err());
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
// RUST_GTA_RBS_TP_RES_List_001 — 查询当前用户所有资源
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_List_001
/// List returns the caller's resources as metadata items with pagination echo;
/// the item URI is rebuilt from the entity's addressing columns.
#[tokio::test]
async fn test_res_list_001_returns_user_resources() {
    let repo = {
        let r = MockResourceRepository::new();
        *r.list_result.lock().unwrap() = Ok((vec![make_entity()], 1));
        r
    };
    let svc = make_service(repo, MockPolicyClient::new(), MockAuthzChecker::new(), MockResourceBackend::new());
    let ctx = bearer_ctx(TEST_USER);

    let result = svc.list(&ctx, &rbs_core::resource::service::ResourceQuery { offset: 0, limit: 10 }).await;
    assert!(result.is_ok(), "list should succeed, got {:?}", result.as_ref().err());
    let resp = result.unwrap();
    assert_eq!(resp.total_count, 1);
    assert_eq!(resp.limit, 10);
    assert_eq!(resp.offset, 0);
    assert_eq!(resp.items.len(), 1);
    assert_eq!(resp.items[0].uri, TEST_URI);
    assert_eq!(resp.items[0].policy_id, "pol-001");
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_List_002 — 查询当前用户所有资源-鉴权拒绝
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_List_002
/// An authz denial on the list action maps to PermissionDenied (403) — unlike
/// single-resource reads, the caller's own inventory does not use the
/// anti-enumeration 404 collapse.
#[tokio::test]
async fn test_res_list_002_authz_denied_returns_403() {
    let repo = MockResourceRepository::new();
    let authz = MockAuthzChecker::denying();
    let svc = make_service(repo, MockPolicyClient::new(), authz, MockResourceBackend::new());
    let ctx = bearer_ctx(TEST_USER);

    let result = svc.list(&ctx, &rbs_core::resource::service::ResourceQuery { offset: 0, limit: 10 }).await;
    assert!(matches!(result, Err(ResourceError::PermissionDenied)),
        "authz denial should map to PermissionDenied, got {:?}", result.as_ref().err());
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
        content: None,
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

// ===========================================================================
// Service error mapping — validation, backend lookup, authorization faults
// ===========================================================================

/// RSA-2048 public JWK (`RSA-OAEP-256`): exercises the RSA branch of the JWE
/// encrypter, which the EC-only fixtures never reach.
const RSA_PUBLIC_JWK: &str = r#"{"kty":"RSA","n":"2gV4W_VYSGUHtGOg8iLxwIZ8d7Bml29h_sHQUbixU-sAvmFZMvFkKed-GC9rMyAsKNyg7b_KZew8wrr7zVxBvysnYXpIoLDqysLHP66B1BPYuqNuFtdR6DcblFvjTcT_3lQ7icSfa14oCUQUYCOmRyjDevNvtCe6P2Bx7NDS5wQK5ib6kJB-be_QsFaISHf2nw8rrvN9em8YBtgULsO-S7VUCfqy9T9CvlitHxqkykAWURv2qzD8z1tgI3oEkRvhSYyXyBxHhAgV6nwtxGGK6C1UKZ4hhcmqIvcTGPJd5hFDo4qJqOqkEG9aP0MQxXelO8XU20xTQ8LEQf1cZIbUUw","e":"AQAB"}"#;

fn bearer_with_claims(claims: serde_json::Value) -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: TEST_USER.to_string(),
        role: "user".to_string(),
        claims,
        token_type: TokenType::Bearer,
    })
}

fn repo_with(entity: Option<rbs_core::resource::repository::ResourceEntity>) -> MockResourceRepository {
    let r = MockResourceRepository::new();
    *r.find_by_uri_result.lock().unwrap() = Ok(entity);
    r
}

/// Create rejects content that is not valid base64 before touching the backend.
#[tokio::test]
async fn test_res_create_invalid_content_base64_rejected() {
    let svc = default_service();
    let ctx = bearer_ctx(TEST_USER);
    let mut req = create_req();
    req.content = Some("not-base64!!!".to_string());

    let result = svc.create(&ctx, TEST_URI, &req).await;
    assert!(
        matches!(&result, Err(ResourceError::ParamInvalid { field }) if *field == "content"),
        "expected ParamInvalid(content), got {:?}", result.as_ref().err()
    );
}

/// An explicitly empty policy_id on update is rejected (it is neither "rebind"
/// nor "keep", and would otherwise unbind the resource).
#[tokio::test]
async fn test_res_update_empty_policy_id_rejected() {
    let svc = make_service(
        repo_with(Some(make_entity())),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
    );
    let ctx = bearer_ctx(TEST_USER);
    let mut req = update_req();
    req.policy_id = Some(String::new());

    let result = svc.update(&ctx, TEST_URI, &req).await;
    assert!(
        matches!(&result, Err(ResourceError::ParamInvalid { field }) if *field == "policy_id"),
        "expected ParamInvalid(policy_id), got {:?}", result.as_ref().err()
    );
}

/// Update rejects content that is not valid base64.
#[tokio::test]
async fn test_res_update_invalid_content_base64_rejected() {
    let svc = make_service(
        repo_with(Some(make_entity())),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
    );
    let ctx = bearer_ctx(TEST_USER);
    let mut req = update_req();
    req.content = Some("not-base64!!!".to_string());

    let result = svc.update(&ctx, TEST_URI, &req).await;
    assert!(
        matches!(&result, Err(ResourceError::ParamInvalid { field }) if *field == "content"),
        "expected ParamInvalid(content), got {:?}", result.as_ref().err()
    );
}

/// Update for a provider that passes URI validation but has no registered
/// backend adapter fails with BackendUnsupported (and never writes the DB).
#[tokio::test]
async fn test_res_update_unregistered_backend_rejected() {
    let svc = make_service_with_config(
        MockResourceRepository::new(),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
        config_with_unregistered_hsm(),
    );
    let ctx = bearer_ctx(TEST_USER);

    let result = svc.update(&ctx, HSM_URI, &update_req()).await;
    assert!(
        matches!(&result, Err(ResourceError::BackendUnsupported { provider }) if provider == "hsm"),
        "expected BackendUnsupported(hsm), got {:?}", result.as_ref().err()
    );
}

/// Create via the update path (upsert): a backend put failure after the DB row
/// is reserved rolls the row back and surfaces the backend error.
#[tokio::test]
async fn test_res_update_create_path_put_failure_rolls_back_row() {
    use rbs_core::resource::adapter::BackendCapabilities;

    let repo = MockResourceRepository::new(); // find_by_uri → None: create path
    let delete_handle = repo.delete_call_handle();
    let backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::PUT)
        .with_put_result(Err(ResourceError::BackendError { detail: "put failed".to_string() }));
    let svc = make_service(repo, MockPolicyClient::new(), MockAuthzChecker::new(), backend);
    let ctx = bearer_ctx(TEST_USER);
    let mut req = update_req();
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(b"payload"));

    let result = svc.update(&ctx, TEST_URI, &req).await;
    assert!(
        matches!(&result, Err(ResourceError::BackendError { detail }) if detail == "put failed"),
        "expected the backend error, got {:?}", result.as_ref().err()
    );
    assert_eq!(*delete_handle.lock().unwrap(), 1, "the reserved DB row must be rolled back");
}

/// Delete is denied at the authorization layer with 403 (not the read-path 404),
/// because the caller targets an operation, not a specific inventory entry.
#[tokio::test]
async fn test_res_delete_authz_denied_returns_403() {
    let svc = make_service(
        repo_with(Some(make_entity())),
        MockPolicyClient::new(),
        MockAuthzChecker::denying(),
        MockResourceBackend::new(),
    );
    let ctx = bearer_ctx(TEST_USER);

    let result = svc.delete(&ctx, TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::PermissionDenied)),
        "expected PermissionDenied, got {:?}", result.as_ref().err());
}

/// Delete for a provider without a registered adapter fails with
/// BackendUnsupported after the ownership check.
#[tokio::test]
async fn test_res_delete_unregistered_backend_rejected() {
    let mut entity = make_entity();
    entity.provider_name = "hsm".to_string();
    let svc = make_service_with_config(
        repo_with(Some(entity)),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
        config_with_unregistered_hsm(),
    );
    let ctx = bearer_ctx(TEST_USER);

    let result = svc.delete(&ctx, HSM_URI).await;
    assert!(
        matches!(&result, Err(ResourceError::BackendUnsupported { provider }) if provider == "hsm"),
        "expected BackendUnsupported(hsm), got {:?}", result.as_ref().err()
    );
}

/// get_content for a provider without a registered adapter fails with
/// BackendUnsupported after policy authorization.
#[tokio::test]
async fn test_res_get_content_unregistered_backend_rejected() {
    let mut entity = make_entity();
    entity.provider_name = "hsm".to_string();
    let svc = make_service_with_config(
        repo_with(Some(entity)),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
        config_with_unregistered_hsm(),
    );
    let ctx = bearer_with_claims(json!({ "enc-pubkey": EC_P256_JWK }));

    let result = svc.get_content(&ctx, HSM_URI).await;
    assert!(
        matches!(&result, Err(ResourceError::BackendUnsupported { provider }) if provider == "hsm"),
        "expected BackendUnsupported(hsm), got {:?}", result.as_ref().err()
    );
}

/// A non-`Denied` authorization error (broken policy / missing input) is a
/// server-side fault: it must map to PolicyEvaluationFailed (500), not to the
/// anti-enumeration 404.
#[tokio::test]
async fn test_res_get_content_policy_fault_maps_to_evaluation_failed() {
    let svc = make_service(
        repo_with(Some(make_entity())),
        MockPolicyClient::new(),
        MockAuthzChecker::new().with_get_error(GetErrorKind::PolicyEvaluationFailed),
        MockResourceBackend::new(),
    );
    let ctx = bearer_with_claims(json!({ "enc-pubkey": EC_P256_JWK }));

    let result = svc.get_content(&ctx, TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::PolicyEvaluationFailed)),
        "expected PolicyEvaluationFailed, got {:?}", result.as_ref().err());
}

/// Any other authorization error variant (e.g. missing claim) also maps to
/// PolicyEvaluationFailed.
#[tokio::test]
async fn test_res_get_content_other_authz_error_maps_to_evaluation_failed() {
    let svc = make_service(
        repo_with(Some(make_entity())),
        MockPolicyClient::new(),
        MockAuthzChecker::new().with_get_error(GetErrorKind::MissingField),
        MockResourceBackend::new(),
    );
    let ctx = bearer_with_claims(json!({ "enc-pubkey": EC_P256_JWK }));

    let result = svc.get_content(&ctx, TEST_URI).await;
    assert!(matches!(result, Err(ResourceError::PolicyEvaluationFailed)),
        "expected PolicyEvaluationFailed, got {:?}", result.as_ref().err());
}

/// retrieve validates the URI before any lookup.
#[tokio::test]
async fn test_res_retrieve_invalid_uri_rejected() {
    let svc = default_service();
    let ctx = attest_ctx(json!({}));

    let result = svc.retrieve(&ctx, "/rbs/v0/vault/default/secret").await;
    assert!(
        matches!(&result, Err(ResourceError::ParamInvalid { field }) if *field == "uri"),
        "expected ParamInvalid(uri), got {:?}", result.as_ref().err()
    );
}

/// retrieve for a provider without a registered adapter fails with
/// BackendUnsupported after policy authorization.
#[tokio::test]
async fn test_res_retrieve_unregistered_backend_rejected() {
    let mut entity = make_entity();
    entity.provider_name = "hsm".to_string();
    let svc = make_service_with_config(
        repo_with(Some(entity)),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
        config_with_unregistered_hsm(),
    );
    let ctx = attest_ctx(json!({}));

    let result = svc.retrieve(&ctx, HSM_URI).await;
    assert!(
        matches!(&result, Err(ResourceError::BackendUnsupported { provider }) if provider == "hsm"),
        "expected BackendUnsupported(hsm), got {:?}", result.as_ref().err()
    );
}

// ===========================================================================
// JWE encryption key handling
// ===========================================================================

/// An RSA JWK supplied as a JSON object claim is serialized back to text and
/// accepted by the RSA-OAEP-256 encrypter (object-valued claims are legal JWKs).
#[tokio::test]
async fn test_res_get_content_rsa_jwk_object_encrypts() {
    let rsajwk: serde_json::Value = serde_json::from_str(RSA_PUBLIC_JWK).unwrap();
    let svc = make_service(
        repo_with(Some(make_entity())),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
    );
    let ctx = bearer_with_claims(json!({ "enc-pubkey": rsajwk }));

    let result = svc.get_content(&ctx, TEST_URI).await;
    assert!(result.is_ok(), "RSA JWK object should encrypt, got {:?}", result.as_ref().err());
    let resp = result.unwrap();
    assert!(!resp.content.is_empty());
    // A compact JWE is five base64url segments separated by '.'.
    let decoded = base64::engine::general_purpose::STANDARD.decode(&resp.content).expect("base64 JWE");
    let compact = String::from_utf8(decoded).expect("utf8 JWE");
    assert_eq!(compact.split('.').count(), 5, "expected a compact JWE, got {compact}");
}

/// A claim that is not a JWK at all fails encryption with JweEncryptionFailed.
#[tokio::test]
async fn test_res_get_content_invalid_jwk_rejected() {
    let svc = make_service(
        repo_with(Some(make_entity())),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
    );
    let ctx = bearer_with_claims(json!({ "enc-pubkey": "this-is-not-a-jwk" }));

    let result = svc.get_content(&ctx, TEST_URI).await;
    match result {
        Err(ResourceError::JweEncryptionFailed { reason }) => {
            assert!(reason.contains("invalid JWK"), "unexpected reason: {reason}");
        }
        other => panic!("expected JweEncryptionFailed(invalid JWK), got {:?}", other.err()),
    }
}

/// A structurally valid JWK with an unsupported key type ("oct") is rejected
/// rather than silently downgraded.
#[tokio::test]
async fn test_res_get_content_unsupported_jwk_key_type_rejected() {
    let svc = make_service(
        repo_with(Some(make_entity())),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
    );
    let ctx = bearer_with_claims(json!({
        "enc-pubkey": { "kty": "oct", "k": "c2VjcmV0LWtleS1tYXRlcmlhbA" }
    }));

    let result = svc.get_content(&ctx, TEST_URI).await;
    match result {
        Err(ResourceError::JweEncryptionFailed { reason }) => {
            assert!(reason.contains("unsupported JWK key type"), "unexpected reason: {reason}");
        }
        other => panic!("expected JweEncryptionFailed, got {:?}", other.err()),
    }
}

/// An EC JWK whose material cannot build an encrypter (invalid point) fails
/// with JweEncryptionFailed instead of panicking.
#[tokio::test]
async fn test_res_get_content_broken_ec_jwk_rejected() {
    let svc = make_service(
        repo_with(Some(make_entity())),
        MockPolicyClient::new(),
        MockAuthzChecker::new(),
        MockResourceBackend::new(),
    );
    let ctx = bearer_with_claims(json!({
        "enc-pubkey": { "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA" }
    }));

    let result = svc.get_content(&ctx, TEST_URI).await;
    match result {
        Err(ResourceError::JweEncryptionFailed { reason }) => {
            // The JWK parses (base64url x/y), but the point cannot build an
            // encrypter — the EC encrypter-creation arm, not a parse failure.
            assert!(reason.contains("EC encrypter"), "unexpected reason: {reason}");
        }
        other => panic!("expected JweEncryptionFailed(EC encrypter), got {:?}", other.err()),
    }
}

/// A failing backend delete aborts the delete before the DB row is removed:
/// the backend object is the source of truth, so the metadata must survive so
/// the delete can be retried.
#[tokio::test]
async fn test_res_delete_backend_error_keeps_db_row() {
    use rbs_core::resource::adapter::BackendCapabilities;

    let repo = repo_with(Some(make_entity()));
    let delete_handle = repo.delete_call_handle();
    let backend = MockResourceBackend::new()
        .with_capabilities(BackendCapabilities::DELETE)
        .with_delete_result(Err(ResourceError::BackendError { detail: "vault down".to_string() }));
    let svc = make_service(repo, MockPolicyClient::new(), MockAuthzChecker::new(), backend);
    let ctx = bearer_ctx(TEST_USER);

    let result = svc.delete(&ctx, TEST_URI).await;
    assert!(
        matches!(&result, Err(ResourceError::BackendError { detail }) if detail == "vault down"),
        "expected the backend error, got {:?}", result.as_ref().err()
    );
    assert_eq!(*delete_handle.lock().unwrap(), 0, "the DB row must not be deleted when the backend fails");
}

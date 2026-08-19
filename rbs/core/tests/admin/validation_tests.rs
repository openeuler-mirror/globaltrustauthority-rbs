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

//! Validation tests for user request types and admin authorization.

use rbs_api_types::error::RbsError;
use rbs_api_types::{AuthType, Role, UserCreateRequest, UserListQuery, UserUpdateRequest, validate_username};
use serde_json::json;
use validator::Validate;

use super::common::*;

// ===========================================================================
// RUST_GTA_RBS_TP_USER_List_002 — 查询用户列表-参数异常与边界值
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_List_002
/// limit=0 fails validation (range min is 1).
#[test]
fn test_user_list_002_limit_zero_rejected() {
    let q = UserListQuery { limit: Some(0), offset: None, role: None, enabled: None };
    assert!(Validate::validate(&q).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_List_002
/// limit=101 fails validation (range max is 100).
#[test]
fn test_user_list_002_limit_101_rejected() {
    let q = UserListQuery { limit: Some(101), offset: None, role: None, enabled: None };
    assert!(Validate::validate(&q).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_List_002
/// offset=-1 fails validation (range min is 0).
#[test]
fn test_user_list_002_offset_negative_rejected() {
    let q = UserListQuery { limit: None, offset: Some(-1), role: None, enabled: None };
    assert!(Validate::validate(&q).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_List_002
/// offset=100001 fails validation (range max is 100000).
#[test]
fn test_user_list_002_offset_100001_rejected() {
    let q = UserListQuery { limit: None, offset: Some(100_001), role: None, enabled: None };
    assert!(Validate::validate(&q).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_List_002
/// Non-enum role "superadmin" is rejected by serde deserialization.
#[test]
fn test_user_list_002_invalid_role_rejected_by_serde() {
    let json_str = r#"{"limit":10,"offset":0,"role":"superadmin"}"#;
    let result: Result<UserListQuery, _> = serde_json::from_str(json_str);
    assert!(result.is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_List_002
/// limit=1 (boundary minimum) passes validation.
#[test]
fn test_user_list_002_limit_1_accepted() {
    let q = UserListQuery { limit: Some(1), offset: None, role: None, enabled: None };
    assert!(Validate::validate(&q).is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_List_002
/// limit=100 (boundary maximum) passes validation.
#[test]
fn test_user_list_002_limit_100_accepted() {
    let q = UserListQuery { limit: Some(100), offset: None, role: None, enabled: None };
    assert!(Validate::validate(&q).is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_List_002
/// offset=100000 (boundary maximum) passes validation.
#[test]
fn test_user_list_002_offset_100000_accepted() {
    let q = UserListQuery { limit: None, offset: Some(100_000), role: None, enabled: None };
    assert!(Validate::validate(&q).is_ok());
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Create_002 — 创建用户-参数异常
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Create_002
/// Empty username is rejected by validation.
#[test]
fn test_user_create_002_empty_username_rejected() {
    let req = create_req_with_pk("", &generate_rsa_pem_b64());
    assert!(Validate::validate(&req).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Create_002
/// Username with 37 characters exceeds max (36) and is rejected.
#[test]
fn test_user_create_002_username_too_long_rejected() {
    let name = "a".repeat(37);
    let req = create_req_with_pk(&name, &generate_rsa_pem_b64());
    assert!(Validate::validate(&req).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Create_002
/// Username with space character is rejected (charset check).
#[test]
fn test_user_create_002_username_with_space_rejected() {
    let req = create_req_with_pk("test user", &generate_rsa_pem_b64());
    assert!(Validate::validate(&req).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Create_002
/// Username with @ character is rejected (charset check).
#[test]
fn test_user_create_002_username_with_at_rejected() {
    let req = create_req_with_pk("test@user", &generate_rsa_pem_b64());
    assert!(Validate::validate(&req).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Create_002
/// Neither public_key nor jwk provided → validate_key_pair rejects.
#[test]
fn test_user_create_002_no_key_material_rejected() {
    let req = UserCreateRequest {
        username: "nokuser".to_string(),
        role: None,
        enabled: None,
        auth_type: AuthType::Jwt,
        public_key: None,
        jwk: None,
    };
    assert!(req.validate_key_pair().is_err());
    let err = req.validate_key_pair().unwrap_err();
    assert!(matches!(err, RbsError::InvalidParameter(msg) if msg.contains("Must provide")));
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Create_002
/// Both public_key and jwk provided → validate_key_pair rejects (mutually exclusive).
#[test]
fn test_user_create_002_both_keys_rejected() {
    let req = UserCreateRequest {
        username: "bothkeys".to_string(),
        role: None,
        enabled: None,
        auth_type: AuthType::Jwt,
        public_key: Some(generate_rsa_pem_b64()),
        jwk: Some(rsa_jwk()),
    };
    let err = req.validate_key_pair().unwrap_err();
    assert!(matches!(err, RbsError::InvalidParameter(msg) if msg.contains("mutually exclusive")));
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Update_002 — 更新用户-权限与字段异常
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Update_002
/// role=Admin in update request is rejected by validation.
#[test]
fn test_user_update_002_role_admin_rejected() {
    let req = UserUpdateRequest {
        role: Some(Role::Admin),
        enabled: None,
        auth_type: None,
        public_key: None,
        jwk: None,
    };
    assert!(Validate::validate(&req).is_err());
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Update_003 — 更新用户-参数异常
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Update_003
/// Both public_key and jwk in update → validate_cross_fields rejects.
#[test]
fn test_user_update_003_both_keys_rejected() {
    let req = UserUpdateRequest {
        role: None,
        enabled: None,
        auth_type: None,
        public_key: Some(generate_rsa_pem_b64()),
        jwk: Some(rsa_jwk()),
    };
    let err = req.validate_cross_fields().unwrap_err();
    assert!(matches!(err, RbsError::InvalidParameter(msg) if msg.contains("mutually exclusive")));
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Update_003
/// Empty update body (no fields) → validate_cross_fields rejects.
#[test]
fn test_user_update_003_empty_body_rejected() {
    let req = UserUpdateRequest {
        role: None,
        enabled: None,
        auth_type: None,
        public_key: None,
        jwk: None,
    };
    let err = req.validate_cross_fields().unwrap_err();
    assert!(matches!(err, RbsError::InvalidParameter(msg) if msg.contains("At least one")));
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Get_002 — 查询用户-异常场景 (username validation)
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Get_002
/// Username with space is rejected by validate_username.
#[test]
fn test_user_get_002_username_with_space_rejected() {
    let result = validate_username("test user");
    assert!(result.is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Get_002
/// Username exceeding 36 characters is rejected by validate_username.
#[test]
fn test_user_get_002_username_too_long_rejected() {
    let result = validate_username(&"a".repeat(37));
    assert!(result.is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Get_002
/// Empty username is rejected by validate_username.
#[test]
fn test_user_get_002_username_empty_rejected() {
    let result = validate_username("");
    assert!(result.is_err());
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Sec_001 — 安全-admin角色保护
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Sec_001
/// role=Admin in create request is rejected by validation.
#[test]
fn test_user_sec_001_create_role_admin_rejected() {
    let req = create_req_role_admin("secadmin", &generate_rsa_pem_b64());
    assert!(Validate::validate(&req).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Sec_001
/// role=Admin in update request is rejected by validation.
#[test]
fn test_user_sec_001_update_role_admin_rejected() {
    let req = UserUpdateRequest {
        role: Some(Role::Admin),
        enabled: None,
        auth_type: None,
        public_key: None,
        jwk: None,
    };
    assert!(Validate::validate(&req).is_err());
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Create_003 — 创建用户-冲突场景 (validation aspect)
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Create_003
/// Valid request passes validate_key_pair (conflict happens at DB level).
#[test]
fn test_user_create_003_valid_request_passes_validation() {
    let req = create_req_with_pk("conflictuser", &generate_rsa_pem_b64());
    assert!(Validate::validate(&req).is_ok());
    assert!(req.validate_key_pair().is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Create_003
/// Both keys provided is rejected by validate_key_pair (would cause conflict
/// at DB level even before reaching the duplicate check).
#[test]
fn test_user_create_003_both_keys_rejected() {
    let req = UserCreateRequest {
        username: "bothkeysconflict".to_string(),
        role: None,
        enabled: None,
        auth_type: AuthType::Jwt,
        public_key: Some(generate_rsa_pem_b64()),
        jwk: Some(rsa_jwk()),
    };
    assert!(req.validate_key_pair().is_err());
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Auth_001 — 认证鉴权-异常场景
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Auth_001
/// User with non-admin role is rejected for list (AdminOnly).
#[tokio::test]
async fn test_user_auth_001_user_role_list_denied() {
    use rbs_core::auth::context::{AuthContext, BearerContext, TokenType};
    ensure_db().await;
    let mgr = make_manager(10);
    mgr.bootstrap_admin().await.ok();
    let ctx = AuthContext::Bearer(BearerContext {
        iss: "test".into(), sub: "nonexistent".into(), role: "user".into(),
        claims: json!({}), token_type: TokenType::Bearer,
    });
    let query = UserListQuery { limit: None, offset: None, role: None, enabled: None };
    let result = mgr.list_users(&query, &ctx).await;
    assert!(result.is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Auth_001
/// Attest token is rejected for user management operations.
#[tokio::test]
async fn test_user_auth_001_attest_token_rejected() {
    use rbs_core::auth::context::{AttestContext, AuthContext, TokenType};
    ensure_db().await;
    let mgr = make_manager(10);
    mgr.bootstrap_admin().await.ok();
    let ctx = AuthContext::Attest(AttestContext {
        claims: json!({}), token_type: TokenType::Attest,
    });
    let query = UserListQuery { limit: None, offset: None, role: None, enabled: None };
    let result = mgr.list_users(&query, &ctx).await;
    assert!(result.is_err(), "Attest token should be rejected for user management");
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_List_003 — 查询用户列表-权限异常
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_List_003
/// Non-admin user calling list_users returns an error.
#[tokio::test]
async fn test_user_list_003_non_admin_denied() {
    use rbs_core::auth::context::{AuthContext, BearerContext, TokenType};
    ensure_db().await;
    let mgr = make_manager(10);
    mgr.bootstrap_admin().await.ok();
    let ctx = AuthContext::Bearer(BearerContext {
        iss: "test".into(), sub: "regularuser".into(), role: "user".into(),
        claims: json!({}), token_type: TokenType::Bearer,
    });
    let query = UserListQuery { limit: None, offset: None, role: None, enabled: None };
    let result = mgr.list_users(&query, &ctx).await;
    assert!(result.is_err());
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_KeyProvider_001 — UserKeyProvider-正常与异常
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_KeyProvider_001
/// get_public_key for non-existent user returns AuthError::TokenInvalid.
#[tokio::test]
async fn test_user_key_provider_001_nonexistent_user() {
    use rbs_core::auth::UserKeyProvider;
    ensure_db().await;
    let mgr = make_manager(10);
    mgr.bootstrap_admin().await.ok();
    let result = mgr.get_public_key("ghost_user").await;
    assert!(result.is_err());
    assert!(matches!(result, Err(rbs_core::AuthError::TokenInvalid { .. })));
}

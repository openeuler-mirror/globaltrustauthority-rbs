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

//! API-level validation tests for policy query parameters and path IDs.

use rbs_api_types::{PolicyListQuery, validate_policy_id};
use rbs_core::policy::PolicyError;
use validator::Validate;

use super::common::*;

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_List_004 — 策略列表查询参数越界
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_List_004
/// limit=0 fails validation (range min is 1).
#[test]
fn test_policy_list_004_limit_zero_rejected() {
    let query = PolicyListQuery { ids: None, limit: Some(0), offset: Some(0) };
    assert!(Validate::validate(&query).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_List_004
/// limit=101 fails validation (range max is 100).
#[test]
fn test_policy_list_004_limit_101_rejected() {
    let query = PolicyListQuery { ids: None, limit: Some(101), offset: Some(0) };
    assert!(Validate::validate(&query).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_List_004
/// offset=-1 fails validation (range min is 0).
#[test]
fn test_policy_list_004_offset_negative_rejected() {
    let query = PolicyListQuery { ids: None, limit: Some(10), offset: Some(-1) };
    assert!(Validate::validate(&query).is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_List_004
/// ids containing a non-UUID value is rejected by validate_policy_id.
#[test]
fn test_policy_list_004_ids_non_uuid_rejected() {
    let result = validate_policy_id("not-a-uuid");
    assert!(result.is_err());
}

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_Get_005 — 查询策略详情-policy_id格式无效
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_Get_005
/// policy_id "not-a-uuid" is rejected (not a valid UUID).
#[test]
fn test_policy_get_005_policy_id_not_uuid_rejected() {
    let result = validate_policy_id("not-a-uuid");
    assert!(result.is_err());
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Get_005
/// policy_id with length > 36 is rejected.
#[test]
fn test_policy_get_005_policy_id_too_long_rejected() {
    let long_id = "a".repeat(37);
    let result = validate_policy_id(&long_id);
    assert!(result.is_err());
}

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_BatchDelete_004 — 批量删除-ids参数无效
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_BatchDelete_004
/// ids parameter ",,," splits into an empty vector after trimming/filtering,
/// and service.delete returns ParamInvalid { field: "policy_ids" }.
#[tokio::test]
async fn test_policy_batch_delete_004_ids_all_empty_param_invalid() {
    let ids: Vec<String> = ",,,".split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert!(ids.is_empty(), "splitting ',,,' should yield an empty vector");

    let repo = MockPolicyRepository::new();
    let service = make_service(repo);
    let ctx = bearer_ctx("user1", "user");

    let result = service.delete(&ctx, &ids).await;
    assert!(
        matches!(result, Err(PolicyError::ParamInvalid { field: "policy_ids" })),
        "expected ParamInvalid{{field:\"policy_ids\"}}, got {:?}", result.as_ref().err()
    );
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_BatchDelete_004
/// ids containing a non-UUID string is rejected by validate_policy_id.
#[test]
fn test_policy_batch_delete_004_ids_non_uuid_rejected() {
    let result = validate_policy_id("not-a-uuid");
    assert!(result.is_err());
}

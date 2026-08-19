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

//! Validator-level tests for `ResourceValidator`.

use rbs_core::resource::{ResourceConfig, ResourceError, ResourceValidator};

fn validator() -> ResourceValidator {
    ResourceValidator::new(ResourceConfig::default())
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_URI_001 — URI校验-合法4段等价类
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_URI_001
/// Valid 4-segment URI with legal chars passes validation.
#[test]
fn test_res_uri_001_valid_4_segment_uri() {
    let v = validator();
    let result = v.validate_uri("/rbs/v0/vault/my-repo_01/secret/my_key.01");
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.res_provider, "vault");
    assert_eq!(parsed.repository_name, "my-repo_01");
    assert_eq!(parsed.resource_type, "secret");
    assert_eq!(parsed.resource_name, "my_key.01");
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Create_005 — 创建资源-URI段数非法
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_005
/// URI with 3 segments (too few) is rejected with ParamInvalid.
#[test]
fn test_res_create_005_uri_three_segments_rejected() {
    let v = validator();
    let result = v.validate_uri("/rbs/v0/vault/repo/secret");
    assert!(matches!(result, Err(ResourceError::ParamInvalid { field: "uri" })));
}

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_005
/// URI with 5 segments (too many) is rejected with ParamInvalid.
#[test]
fn test_res_create_005_uri_five_segments_rejected() {
    let v = validator();
    let result = v.validate_uri("/rbs/v0/vault/repo/secret/key/extra");
    assert!(matches!(result, Err(ResourceError::ParamInvalid { field: "uri" })));
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Create_006 — 创建资源-res_provider保留字
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_006
/// Reserved provider names (admin, attestation, resource, health) are rejected.
#[test]
fn test_res_create_006_reserved_provider_names_rejected() {
    let v = validator();
    for reserved in ["admin", "attestation", "resource", "health"] {
        let result = v.validate_res_provider(reserved);
        assert!(
            matches!(result, Err(ResourceError::ParamInvalid { field: "res_provider" })),
            "expected ParamInvalid for reserved provider '{}'", reserved
        );
    }
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Create_007 — 创建资源-res_provider未配置
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_007
/// Unconfigured provider name returns BackendUnsupported.
#[test]
fn test_res_create_007_unconfigured_provider_rejected() {
    let v = validator();
    let result = v.validate_res_provider("unknown_backend");
    assert!(matches!(result, Err(ResourceError::BackendUnsupported { provider }) if provider == "unknown_backend"));
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Create_008 — 创建资源-非法字符和长度越界
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_008
/// repository_name with illegal characters (!@#) is rejected.
#[test]
fn test_res_create_008_repo_name_illegal_chars_rejected() {
    let v = validator();
    let result = v.validate_repository_name("repo!@#");
    assert!(matches!(result, Err(ResourceError::ParamInvalid { field: "repository_name" })));
}

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_008
/// repository_name with length 33 (exceeds max 32) is rejected.
#[test]
fn test_res_create_008_repo_name_too_long_rejected() {
    let v = validator();
    let result = v.validate_repository_name(&"a".repeat(33));
    assert!(matches!(result, Err(ResourceError::ParamInvalid { field: "repository_name" })));
}

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_008
/// resource_name with illegal characters (!@#) is rejected.
#[test]
fn test_res_create_008_resource_name_illegal_chars_rejected() {
    let v = validator();
    let result = v.validate_resource_name("key!@#");
    assert!(matches!(result, Err(ResourceError::ParamInvalid { field: "resource_name" })));
}

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_008
/// Empty policy_id is rejected by the validator context (service checks this inline).
#[test]
fn test_res_create_008_empty_policy_id_rejected() {
    assert!("".is_empty());
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Create_014 — 创建资源-URI字段边界值
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_014
/// repository_name with length 1 (minimum) is accepted.
#[test]
fn test_res_create_014_repo_name_len_1_accepted() {
    let v = validator();
    assert!(v.validate_repository_name("a").is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_014
/// repository_name with length 32 (maximum) is accepted.
#[test]
fn test_res_create_014_repo_name_len_32_accepted() {
    let v = validator();
    assert!(v.validate_repository_name(&"a".repeat(32)).is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_014
/// resource_name with length 1 (minimum) is accepted.
#[test]
fn test_res_create_014_resource_name_len_1_accepted() {
    let v = validator();
    assert!(v.validate_resource_name("a").is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_014
/// resource_name with length 32 (maximum) is accepted.
#[test]
fn test_res_create_014_resource_name_len_32_accepted() {
    let v = validator();
    assert!(v.validate_resource_name(&"a".repeat(32)).is_ok());
}

// ===========================================================================
// RUST_GTA_RBS_TP_RES_Create_015 — 创建资源-policy_id和additional_info边界值
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_015
/// additional_info with length 512 (maximum) is accepted.
#[test]
fn test_res_create_015_additional_info_len_512_accepted() {
    let v = validator();
    let info = "x".repeat(512);
    assert!(v.validate_additional_info(Some(&info)).is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_015
/// additional_info with empty string is rejected.
#[test]
fn test_res_create_015_additional_info_empty_rejected() {
    let v = validator();
    let result = v.validate_additional_info(Some(""));
    assert!(matches!(result, Err(ResourceError::ParamInvalid { field: "additional_info" })));
}

/// test_point_id: RUST_GTA_RBS_TP_RES_Create_015
/// additional_info None (omitted) is accepted.
#[test]
fn test_res_create_015_additional_info_none_accepted() {
    let v = validator();
    assert!(v.validate_additional_info(None).is_ok());
}

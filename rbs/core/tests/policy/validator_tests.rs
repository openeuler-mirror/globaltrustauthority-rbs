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

//! Validator-level tests for `PolicyValidator`.
//!
//! Tests PolicyValidator::validate_name and decode_and_check_size directly.

use base64::Engine as _;
use rbs_core::policy::{PolicyConfig, PolicyError, PolicyValidator};

fn validator() -> PolicyValidator {
    PolicyValidator::new(PolicyConfig::default())
}

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_Create_002 — 创建策略-名称含黑名单字符
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_002
/// Name containing `<>` characters is rejected with NameInvalid.
#[test]
fn test_policy_create_002_name_blacklist_angle_brackets() {
    let result = validator().validate_name("<script>");
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_002
/// Name containing `"'` characters is rejected with NameInvalid.
#[test]
fn test_policy_create_002_name_blacklist_quotes() {
    let result = validator().validate_name("test\"name'");
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_002
/// Name containing `&|\\/ *?` characters is rejected with NameInvalid.
#[test]
fn test_policy_create_002_name_blacklist_special_chars() {
    for name in ["test&name", "a|b", "a\\b", "a/b", "a*b", "a?b", "a`b"] {
        let result = validator().validate_name(name);
        assert!(
            matches!(result, Err(PolicyError::NameInvalid { .. })),
            "expected NameInvalid for name='{}'", name
        );
    }
}

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_Create_003 — 创建策略-名称长度越界
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_003
/// Name with length 0 (empty) is rejected.
#[test]
fn test_policy_create_003_name_length_zero_rejected() {
    let result = validator().validate_name("");
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_003
/// Name with length 1 (minimum boundary) is accepted.
#[test]
fn test_policy_create_003_name_length_one_accepted() {
    let result = validator().validate_name("x");
    assert!(result.is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_003
/// Name with length 255 (maximum boundary) is accepted.
#[test]
fn test_policy_create_003_name_length_255_accepted() {
    let name = "a".repeat(255);
    let result = validator().validate_name(&name);
    assert!(result.is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_003
/// Name with length 256 (exceeds max) is rejected.
#[test]
fn test_policy_create_003_name_length_256_rejected() {
    let name = "a".repeat(256);
    let result = validator().validate_name(&name);
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_Create_004 — 创建策略-content_type非base64
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_004
/// content_type "plain" is rejected with UnsupportedContentType.
#[test]
fn test_policy_create_004_content_type_plain_rejected() {
    let result = validator().decode_and_check_size("plain", "dGVzdA==");
    assert!(matches!(result, Err(PolicyError::UnsupportedContentType { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_004
/// content_type empty string is rejected with UnsupportedContentType.
#[test]
fn test_policy_create_004_content_type_empty_rejected() {
    let result = validator().decode_and_check_size("", "dGVzdA==");
    assert!(matches!(result, Err(PolicyError::UnsupportedContentType { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_004
/// content_type "text" is rejected with UnsupportedContentType.
#[test]
fn test_policy_create_004_content_type_text_rejected() {
    let result = validator().decode_and_check_size("text", "dGVzdA==");
    assert!(matches!(result, Err(PolicyError::UnsupportedContentType { .. })));
}

// ===========================================================================
// RUST_GTA_RBS_TP_Policy_Create_005 — 创建策略-content校验失败
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_005
/// Empty content is rejected with ContentDecodeError.
#[test]
fn test_policy_create_005_content_empty_rejected() {
    let result = validator().decode_and_check_size("base64", "");
    assert!(matches!(result, Err(PolicyError::ContentDecodeError { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_005
/// Invalid base64 content is rejected with ContentDecodeError.
#[test]
fn test_policy_create_005_content_invalid_base64_rejected() {
    let result = validator().decode_and_check_size("base64", "!!!invalid!!!");
    assert!(matches!(result, Err(PolicyError::ContentDecodeError { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_005
/// Decoded content that is not valid UTF-8 is rejected with ContentDecodeError.
#[test]
fn test_policy_create_005_content_non_utf8_rejected() {
    let binary = vec![0x00u8, 0x89, 0x50, 0x4E, 0x47];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&binary);
    let result = validator().decode_and_check_size("base64", &encoded);
    assert!(matches!(result, Err(PolicyError::ContentDecodeError { .. })));
}

/// test_point_id: RUST_GTA_RBS_TP_Policy_Create_005
/// Decoded content exceeding 128KB is rejected with ContentTooLarge.
#[test]
fn test_policy_create_005_content_too_large_rejected() {
    let big = "x".repeat(129 * 1024);
    let encoded = base64::engine::general_purpose::STANDARD.encode(big.as_bytes());
    let result = validator().decode_and_check_size("base64", &encoded);
    assert!(matches!(result, Err(PolicyError::ContentTooLarge { .. })));
}

// ===========================================================================
// RUST_GTA_RBS_TP_Validator_Name_001 — 策略名称校验-黑名单字符全覆盖
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_Validator_Name_001
/// Each blacklisted character is individually rejected by validate_name.
#[test]
fn test_validator_name_001_blacklist_full_coverage() {
    let blacklist = ['<', '>', '"', '\'', '&', '|', '\\', '/', '*', '?', '`'];
    for &ch in &blacklist {
        let name = format!("a{}b", ch);
        let result = validator().validate_name(&name);
        assert!(
            matches!(result, Err(PolicyError::NameInvalid { .. })),
            "expected NameInvalid for name containing '{}'", ch
        );
    }
}

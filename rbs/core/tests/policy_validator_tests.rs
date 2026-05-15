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

//! Unit tests for `PolicyValidator` — pure validation functions, no mocking needed.
//!
//! Scenarios UT-V-001 through UT-V-016.

use rbs_core::policy::*;
use base64::Engine as _;

// ============ validate_name tests (UT-V-001 through UT-V-007) ============

/// UT-V-001: name containing '<' character is rejected.
#[test]
fn test_validate_name_rejects_lt_char() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.validate_name("<script>");
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

/// UT-V-002: name containing '>' character is rejected.
#[test]
fn test_validate_name_rejects_gt_char() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.validate_name("bad>");
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

/// UT-V-003: name containing '"' character is rejected.
#[test]
fn test_validate_name_rejects_double_quote_char() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.validate_name("bad\"name");
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

/// UT-V-004: empty name is rejected.
#[test]
fn test_validate_name_rejects_empty() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.validate_name("");
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

/// UT-V-005: name with length 256 exceeds the 255 max and is rejected.
#[test]
fn test_validate_name_rejects_exceeding_max_len() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let long_name = "a".repeat(256);
    let result = validator.validate_name(&long_name);
    assert!(matches!(result, Err(PolicyError::NameInvalid { .. })));
}

/// UT-V-006: name with length 255 is at the boundary and is accepted.
#[test]
fn test_validate_name_accepts_max_len_boundary() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let boundary_name = "a".repeat(255);
    let result = validator.validate_name(&boundary_name);
    assert!(result.is_ok());
}

/// UT-V-007: name with length 1 is at the minimum boundary and is accepted.
#[test]
fn test_validate_name_accepts_min_len_boundary() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.validate_name("x");
    assert!(result.is_ok());
}

// ============ decode_and_check_size tests (UT-V-008 through UT-V-011, UT-V-014 through UT-V-016) ============

/// UT-V-008: unsupported content_type "gzip" is rejected.
#[test]
fn test_decode_and_check_size_rejects_unsupported_content_type() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.decode_and_check_size("gzip", "dGVzdA==");
    assert!(matches!(result, Err(PolicyError::UnsupportedContentType { .. })));
}

/// UT-V-009: invalid base64 content is rejected.
#[test]
fn test_decode_and_check_size_rejects_invalid_base64() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.decode_and_check_size("base64", "!!!invalid!!!");
    assert!(matches!(result, Err(PolicyError::ContentDecodeError { .. })));
}

/// UT-V-010: decoded content of 129KB exceeds the 128KB max and is rejected.
#[test]
fn test_decode_and_check_size_rejects_content_too_large() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let big = "x".repeat(129 * 1024);
    let encoded = base64::engine::general_purpose::STANDARD.encode(big.as_bytes());
    let result = validator.decode_and_check_size("base64", &encoded);
    assert!(matches!(result, Err(PolicyError::ContentTooLarge { .. })));
}

/// UT-V-011: decoded content of exactly 128KB is at the boundary and is accepted.
#[test]
fn test_decode_and_check_size_accepts_max_size_boundary() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let big = "x".repeat(128 * 1024);
    let encoded = base64::engine::general_purpose::STANDARD.encode(big.as_bytes());
    let result = validator.decode_and_check_size("base64", &encoded);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), big);
}

/// UT-V-014: empty base64 string is rejected as invalid content.
#[test]
fn test_decode_and_check_size_rejects_empty_string() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.decode_and_check_size("base64", "");
    assert!(matches!(result, Err(PolicyError::ContentDecodeError { .. })));
}

/// UT-V-015: content_type "Base64" (capital B) is rejected — case-sensitive match.
#[test]
fn test_decode_and_check_size_rejects_case_sensitive_content_type() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.decode_and_check_size("Base64", "dGVzdA==");
    assert!(matches!(result, Err(PolicyError::UnsupportedContentType { .. })));
}

/// UT-V-016: base64 decodes to valid bytes that are not valid UTF-8 and is rejected.
#[test]
fn test_decode_and_check_size_rejects_non_utf8_content() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let binary = vec![0x00, 0x89, 0x50, 0x4E, 0x47]; // non-UTF8 bytes (PNG header)
    let encoded = base64::engine::general_purpose::STANDARD.encode(&binary);
    let result = validator.decode_and_check_size("base64", &encoded);
    assert!(matches!(result, Err(PolicyError::ContentDecodeError { .. })));
}

// ============ validate_rego_syntax tests (UT-V-012, UT-V-013) ============

/// UT-V-012: Rego that does not start with "package" is rejected.
#[test]
fn test_validate_rego_syntax_rejects_invalid_syntax() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let result = validator.validate_rego_syntax("hello world");
    assert!(matches!(result, Err(PolicyError::RegoSyntaxError { .. })));
}

/// UT-V-013: well-formed Rego with "package" and "allow" rule is accepted.
#[test]
fn test_validate_rego_syntax_accepts_valid_syntax() {
    let validator = PolicyValidator::new(PolicyConfig::default());
    let rego = "package rbs\n\ndefault allow = false\nallow { input.role == \"admin\" }";
    let result = validator.validate_rego_syntax(rego);
    assert!(result.is_ok());
}

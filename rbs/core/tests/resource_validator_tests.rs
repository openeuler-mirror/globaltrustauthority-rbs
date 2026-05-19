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

//! Unit tests for `ResourceValidator` -- pure validation functions.
//!
//! Test scenarios UT-RV-001 through UT-RV-035.

use rbs_core::resource::{ParsedUri, ResourceConfig, ResourceError, ResourceValidator};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validator() -> ResourceValidator {
    ResourceValidator::new(ResourceConfig::default())
}

// ===========================================================================
// resource_name  (UT-RV-001 .. 005, 032)
// ===========================================================================

/// UT-RV-001: resource_name with space -> Err(ParamInvalid {field: "resource_name"})
#[test]
fn ut_rv_001() {
    let v = validator();
    let result = v.validate_resource_name("my key");
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "resource_name" })
    ));
}

/// UT-RV-002: resource_name with Chinese chars -> Err(ParamInvalid)
#[test]
fn ut_rv_002() {
    let v = validator();
    let result = v.validate_resource_name("caf\u{00e9}"); // non-ASCII character
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "resource_name" })
    ));
}

/// UT-RV-003: resource_name length 33 (>32) -> Err(ParamInvalid)
#[test]
fn ut_rv_003() {
    let v = validator();
    let result = v.validate_resource_name(&"a".repeat(33));
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "resource_name" })
    ));
}

/// UT-RV-004: resource_name valid with -_. -> Ok(())
#[test]
fn ut_rv_004() {
    let v = validator();
    let result = v.validate_resource_name("valid-name_01.suffix");
    assert!(result.is_ok());
}

/// UT-RV-005: resource_name length 32 (boundary) -> Ok(())
#[test]
fn ut_rv_005() {
    let v = validator();
    let name = "a".repeat(32);
    let result = v.validate_resource_name(&name);
    assert!(result.is_ok());
}

/// UT-RV-032: resource_name length 1 (boundary) -> Ok(())
#[test]
fn ut_rv_032() {
    let v = validator();
    let result = v.validate_resource_name("a");
    assert!(result.is_ok());
}

// ===========================================================================
// resource_type  (UT-RV-006 .. 008)
// ===========================================================================

/// UT-RV-006: resource_type "key" (invalid) -> Err(ParamInvalid {field: "resource_type"})
#[test]
fn ut_rv_006() {
    let v = validator();
    let result = v.validate_resource_type("key");
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "resource_type" })
    ));
}

/// UT-RV-007: resource_type "secret" -> Ok(())
#[test]
fn ut_rv_007() {
    let v = validator();
    let result = v.validate_resource_type("secret");
    assert!(result.is_ok());
}

/// UT-RV-008: resource_type "cert" -> Ok(())
#[test]
fn ut_rv_008() {
    let v = validator();
    let result = v.validate_resource_type("cert");
    assert!(result.is_ok());
}

// ===========================================================================
// content_type  (UT-RV-009, 010, 023 .. 027)
// ===========================================================================

/// UT-RV-009: content_type "xml" (invalid) -> Err(ParamInvalid {field: "content_type"})
#[test]
fn ut_rv_009() {
    let v = validator();
    let result = v.validate_content_type("xml");
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "content_type" })
    ));
}

/// UT-RV-010: content_type "jwe" -> Ok(())
#[test]
fn ut_rv_010() {
    let v = validator();
    let result = v.validate_content_type("jwe");
    assert!(result.is_ok());
}

/// UT-RV-023: content_type "jwt" -> Ok(())
#[test]
fn ut_rv_023() {
    let v = validator();
    let result = v.validate_content_type("jwt");
    assert!(result.is_ok());
}

/// UT-RV-024: content_type "json" -> Ok(())
#[test]
fn ut_rv_024() {
    let v = validator();
    let result = v.validate_content_type("json");
    assert!(result.is_ok());
}

/// UT-RV-025: content_type "text" -> Ok(())
#[test]
fn ut_rv_025() {
    let v = validator();
    let result = v.validate_content_type("text");
    assert!(result.is_ok());
}

/// UT-RV-026: content_type "binary" -> Ok(())
#[test]
fn ut_rv_026() {
    let v = validator();
    let result = v.validate_content_type("binary");
    assert!(result.is_ok());
}

/// UT-RV-027: content_type "jwk" -> Ok(())
#[test]
fn ut_rv_027() {
    let v = validator();
    let result = v.validate_content_type("jwk");
    assert!(result.is_ok());
}

// ===========================================================================
// export_mode  (UT-RV-011, 012, 028)
// ===========================================================================

/// UT-RV-011: export_mode "gzip" (invalid) -> Err(ParamInvalid {field: "export_mode"})
#[test]
fn ut_rv_011() {
    let v = validator();
    let result = v.validate_export_mode("gzip");
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "export_mode" })
    ));
}

/// UT-RV-012: export_mode "jwe" -> Ok(())
#[test]
fn ut_rv_012() {
    let v = validator();
    let result = v.validate_export_mode("jwe");
    assert!(result.is_ok());
}

/// UT-RV-028: export_mode "plain" (removed) -> Err(ParamInvalid {field: "export_mode"})
#[test]
fn ut_rv_028() {
    let v = validator();
    let result = v.validate_export_mode("plain");
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "export_mode" })
    ));
}

// ===========================================================================
// additional_info  (UT-RV-013 .. 015, 033 .. 035)
// ===========================================================================

/// UT-RV-013: additional_info valid plaintext -> Ok(())
#[test]
fn ut_rv_013() {
    let v = validator();
    let result = v.validate_additional_info(Some("hello world"));
    assert!(result.is_ok());
}

/// UT-RV-014: additional_info >512 chars -> Err(ParamInvalid)
#[test]
fn ut_rv_014() {
    let v = validator();
    let raw = "x".repeat(513);
    let result = v.validate_additional_info(Some(&raw));
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "additional_info" })
    ));
}

/// UT-RV-015: additional_info None -> Ok(())
#[test]
fn ut_rv_015() {
    let v = validator();
    let result = v.validate_additional_info(None);
    assert!(result.is_ok());
}

/// UT-RV-033: additional_info Some("") (empty string) -> Err(ParamInvalid)
#[test]
fn ut_rv_033() {
    let v = validator();
    let result = v.validate_additional_info(Some(""));
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "additional_info" })
    ));
}

/// UT-RV-034: additional_info valid plaintext -> Ok(())
#[test]
fn ut_rv_034() {
    let v = validator();
    let result = v.validate_additional_info(Some("valid plaintext info"));
    assert!(result.is_ok());
}

// ===========================================================================
// repository_name  (UT-RV-016, 017, 029 .. 031)
// ===========================================================================

/// UT-RV-016: repository_name "my repo" (space) -> Err(ParamInvalid {field: "repository_name"})
#[test]
fn ut_rv_016() {
    let v = validator();
    let result = v.validate_repository_name("my repo");
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "repository_name" })
    ));
}

/// UT-RV-017: repository_name "my-repo_01" -> Ok(())
#[test]
fn ut_rv_017() {
    let v = validator();
    let result = v.validate_repository_name("my-repo_01");
    assert!(result.is_ok());
}

/// UT-RV-029: repository_name length 1 -> Ok(())
#[test]
fn ut_rv_029() {
    let v = validator();
    let result = v.validate_repository_name("a");
    assert!(result.is_ok());
}

/// UT-RV-030: repository_name length 32 -> Ok(())
#[test]
fn ut_rv_030() {
    let v = validator();
    let name = "a".repeat(32);
    let result = v.validate_repository_name(&name);
    assert!(result.is_ok());
}

/// UT-RV-031: repository_name length 33 -> Err(ParamInvalid)
#[test]
fn ut_rv_031() {
    let v = validator();
    let result = v.validate_repository_name(&"a".repeat(33));
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "repository_name" })
    ));
}

// ===========================================================================
// res_provider  (UT-RV-018)
// ===========================================================================

/// UT-RV-018: res_provider "unknown" -> Err(BackendUnsupported)
#[test]
fn ut_rv_018() {
    let v = validator();
    let result = v.validate_res_provider("unknown");
    assert!(matches!(
        result,
        Err(ResourceError::BackendUnsupported { provider }) if provider == "unknown"
    ));
}

// ===========================================================================
// URI validation  (UT-RV-019 .. 022a)
// ===========================================================================

/// UT-RV-019: full URI "/rbs/v0/vault/my-repo/secret/my_key" -> Ok(ParsedUri{...})
#[test]
fn ut_rv_019() {
    let v = validator();
    let result = v.validate_uri("/rbs/v0/vault/my-repo/secret/my_key");
    assert!(result.is_ok());
    let parsed: ParsedUri = result.unwrap();
    assert_eq!(parsed.res_provider, "vault");
    assert_eq!(parsed.repository_name, "my-repo");
    assert_eq!(parsed.resource_type, "secret");
    assert_eq!(parsed.resource_name, "my_key");
}

/// UT-RV-020: URI too few segments "/rbs/v0/vault/repo" -> Err(ParamInvalid {field: "uri"})
#[test]
fn ut_rv_020() {
    let v = validator();
    let result = v.validate_uri("/rbs/v0/vault/repo");
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "uri" })
    ));
}

/// UT-RV-021: URI too many segments "/rbs/v0/vault/repo/secret/key/extra" -> Err(ParamInvalid)
#[test]
fn ut_rv_021() {
    let v = validator();
    let result = v.validate_uri("/rbs/v0/vault/repo/secret/key/extra");
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "uri" })
    ));
}

/// UT-RV-022: URI res_provider is reserved word "admin" -> Err(ParamInvalid {field: "res_provider"})
///
/// URI: "/rbs/v0/admin/repo/secret/key"
/// "admin" is in the reserved_providers list and should be rejected.
#[test]
fn ut_rv_022() {
    let v = validator();
    let result = v.validate_uri("/rbs/v0/admin/repo/secret/key");
    assert!(matches!(
        result,
        Err(ResourceError::ParamInvalid { field: "res_provider" })
    ));
}

/// UT-RV-022a: URI empty segment (double slash) "/rbs/v0/vault//secret/key" -> Err(ParamInvalid)
///
/// An empty repository_name segment ("") triggers a ParamInvalid error.
#[test]
fn ut_rv_022a() {
    let v = validator();
    let result = v.validate_uri("/rbs/v0/vault//secret/key");
    assert!(matches!(result, Err(ResourceError::ParamInvalid { .. })));
}

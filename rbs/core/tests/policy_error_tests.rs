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

//! Unit tests for `PolicyError` -- http_status mapping and external_message.

use rbs_core::policy::error::PolicyError;

// ===========================================================================
// http_status tests
// ===========================================================================

/// PermissionDenied -> 403
#[test]
fn test_permission_denied_http_status() {
    assert_eq!(PolicyError::PermissionDenied.http_status(), 403);
}

/// NameInvalid -> 400
#[test]
fn test_name_invalid_http_status() {
    assert_eq!(
        PolicyError::NameInvalid { reason: "bad chars".to_string() }.http_status(),
        400
    );
}

/// NameDuplicate -> 400
#[test]
fn test_name_duplicate_http_status() {
    assert_eq!(
        PolicyError::NameDuplicate { name: "my-policy".to_string() }.http_status(),
        400
    );
}

/// CountExceed -> 400
#[test]
fn test_count_exceed_http_status() {
    assert_eq!(
        PolicyError::CountExceed { max: 10, current: 11 }.http_status(),
        400
    );
}

/// UnsupportedContentType -> 400
#[test]
fn test_unsupported_content_type_http_status() {
    assert_eq!(
        PolicyError::UnsupportedContentType { content_type: "gzip".to_string() }.http_status(),
        400
    );
}

/// ContentDecodeError -> 400
#[test]
fn test_content_decode_error_http_status() {
    assert_eq!(
        PolicyError::ContentDecodeError { reason: "invalid base64".to_string() }.http_status(),
        400
    );
}

/// ContentTooLarge -> 400
#[test]
fn test_content_too_large_http_status() {
    assert_eq!(
        PolicyError::ContentTooLarge { size_kb: 200, max_kb: 128 }.http_status(),
        400
    );
}

/// ParamInvalid -> 400
#[test]
fn test_param_invalid_http_status() {
    assert_eq!(
        PolicyError::ParamInvalid { field: "name" }.http_status(),
        400
    );
}

/// BeingReferenced -> 409
#[test]
fn test_being_referenced_http_status() {
    assert_eq!(
        PolicyError::BeingReferenced { policy_names: vec!["pol1".to_string()] }.http_status(),
        409
    );
}

/// NotFound -> 404
#[test]
fn test_not_found_http_status() {
    assert_eq!(PolicyError::NotFound.http_status(), 404);
}

/// VersionConflict -> 409
#[test]
fn test_version_conflict_http_status() {
    assert_eq!(
        PolicyError::VersionConflict { expected: 2, current: 3 }.http_status(),
        409
    );
}

/// BackendError -> 502
#[test]
fn test_backend_error_http_status() {
    assert_eq!(
        PolicyError::BackendError { detail: "connection lost".to_string() }.http_status(),
        502
    );
}

// ===========================================================================
// external_message tests
// ===========================================================================

/// BackendError.external_message() hides detail and returns generic message.
#[test]
fn test_external_message_backend_error_hides_detail() {
    let err = PolicyError::BackendError { detail: "connection lost".to_string() };
    assert_eq!(err.external_message(), "internal database error");
}

/// PermissionDenied.external_message() returns the error string.
#[test]
fn test_external_message_permission_denied() {
    let err = PolicyError::PermissionDenied;
    assert_eq!(err.external_message(), "permission denied");
}

/// NotFound.external_message() returns the error string.
#[test]
fn test_external_message_not_found() {
    let err = PolicyError::NotFound;
    assert_eq!(err.external_message(), "policy not found");
}

/// NameInvalid.external_message() returns the error string.
#[test]
fn test_external_message_name_invalid() {
    let err = PolicyError::NameInvalid { reason: "contains slash".to_string() };
    assert_eq!(err.external_message(), "policy name is invalid: contains slash");
}

// ===========================================================================
// From<ResourceError>
// ===========================================================================

/// ResourceError converts to PolicyError::ParamInvalid{field: "resource"}
#[test]
fn test_from_resource_error() {
    let resource_err = rbs_core::resource::error::ResourceError::NotFound;
    let policy_err: PolicyError = resource_err.into();
    assert!(matches!(policy_err, PolicyError::ParamInvalid { field: "resource" }));
}
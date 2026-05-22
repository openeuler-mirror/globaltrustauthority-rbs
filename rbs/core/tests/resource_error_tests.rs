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

//! Unit tests for `ResourceError` -- http_status mapping and external_message.

use rbs_core::resource::error::ResourceError;

// ===========================================================================
// http_status tests
// ===========================================================================

/// PermissionDenied -> 403
#[test]
fn test_permission_denied_http_status() {
    assert_eq!(ResourceError::PermissionDenied.http_status(), 403);
}

/// AlreadyExists -> 409
#[test]
fn test_already_exists_http_status() {
    assert_eq!(
        ResourceError::AlreadyExists { uri: "/rbs/v0/vault/repo/secret/key".to_string() }.http_status(),
        409
    );
}

/// VersionConflict -> 409
#[test]
fn test_version_conflict_http_status() {
    assert_eq!(ResourceError::VersionConflict.http_status(), 409);
}

/// ParamInvalid -> 400
#[test]
fn test_param_invalid_http_status() {
    assert_eq!(
        ResourceError::ParamInvalid { field: "resource_name" }.http_status(),
        400
    );
}

/// PolicyIdInvalid -> 400
#[test]
fn test_policy_id_invalid_http_status() {
    assert_eq!(
        ResourceError::PolicyIdInvalid("bad-id".to_string()).http_status(),
        400
    );
}

/// BackendNotFound -> 400
#[test]
fn test_backend_not_found_http_status() {
    assert_eq!(ResourceError::BackendNotFound.http_status(), 400);
}

/// BackendUnsupported -> 400
#[test]
fn test_backend_unsupported_http_status() {
    assert_eq!(
        ResourceError::BackendUnsupported { provider: "unknown".to_string() }.http_status(),
        400
    );
}

/// JweEncryptionFailed -> 400
#[test]
fn test_jwe_encryption_failed_http_status() {
    assert_eq!(
        ResourceError::JweEncryptionFailed { reason: "key error".to_string() }.http_status(),
        400
    );
}

/// NotFound -> 404
#[test]
fn test_not_found_http_status() {
    assert_eq!(ResourceError::NotFound.http_status(), 404);
}

/// BackendError -> 502
#[test]
fn test_backend_error_http_status() {
    assert_eq!(
        ResourceError::BackendError { detail: "connection timeout".to_string() }.http_status(),
        502
    );
}

// ===========================================================================
// external_message tests
// ===========================================================================

/// external_message returns the error string for all variants.
#[test]
fn test_external_message_permission_denied() {
    let err = ResourceError::PermissionDenied;
    assert_eq!(err.external_message(), "permission denied");
}

#[test]
fn test_external_message_not_found() {
    let err = ResourceError::NotFound;
    assert_eq!(err.external_message(), "resource not found");
}

#[test]
fn test_external_message_backend_error() {
    let err = ResourceError::BackendError { detail: "internal detail".to_string() };
    assert_eq!(err.external_message(), "backend error: internal detail");
}

#[test]
fn test_external_message_backend_unsupported() {
    let err = ResourceError::BackendUnsupported { provider: "vault".to_string() };
    assert_eq!(err.external_message(), "backend unsupported: vault");
}
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

//! Integration tests for error types — exhaustive mapping coverage.

use rbs_api_types::{
    error::{ErrorClass, Retryable, RbsError},
};

// ── error_class ──

#[test]
fn error_class_authn() {
    assert_eq!(RbsError::AuthnMissingToken.error_class(), ErrorClass::Authn);
    assert_eq!(RbsError::AuthnInvalidToken.error_class(), ErrorClass::Authn);
    assert_eq!(RbsError::AuthnExpiredToken.error_class(), ErrorClass::Authn);
}

#[test]
fn error_class_authz() {
    assert_eq!(RbsError::AuthzDenied.error_class(), ErrorClass::Authz);
    assert_eq!(RbsError::AuthzInsufficientPermissions.error_class(), ErrorClass::Authz);
}

#[test]
fn error_class_param() {
    assert_eq!(RbsError::ParamMissing { param: "x" }.error_class(), ErrorClass::Param);
    assert_eq!(RbsError::ParamInvalid { param: "y" }.error_class(), ErrorClass::Param);
    assert_eq!(RbsError::ParamMalformed.error_class(), ErrorClass::Param);
    assert_eq!(RbsError::InvalidParameter("z".to_string()).error_class(), ErrorClass::Param);
    assert_eq!(RbsError::NotImplemented.error_class(), ErrorClass::Param);
}

#[test]
fn error_class_resource() {
    assert_eq!(RbsError::ResourceNotFound.error_class(), ErrorClass::Resource);
    assert_eq!(RbsError::ResourceConflict.error_class(), ErrorClass::Resource);
    assert_eq!(RbsError::ResourceGone.error_class(), ErrorClass::Resource);
    assert_eq!(RbsError::ResourceQuotaExceeded.error_class(), ErrorClass::Resource);
}

#[test]
fn error_class_provider() {
    assert_eq!(RbsError::AttestationProviderUnavailable.error_class(), ErrorClass::Provider);
    assert_eq!(RbsError::ResourceProviderUnavailable.error_class(), ErrorClass::Provider);
    assert_eq!(RbsError::ProviderTimeout.error_class(), ErrorClass::Provider);
    assert_eq!(RbsError::ProviderNotFound("p".to_string()).error_class(), ErrorClass::Provider);
    assert_eq!(RbsError::PolicyEvaluationError("e".to_string()).error_class(), ErrorClass::Provider);
}

#[test]
fn error_class_dependency() {
    assert_eq!(
        RbsError::DependencyUnavailable { service: "db" }.error_class(),
        ErrorClass::Dependency
    );
}

#[test]
fn error_class_rate_limit() {
    assert_eq!(RbsError::RateLimitExceeded.error_class(), ErrorClass::RateLimit);
}

#[test]
fn error_class_internal() {
    assert_eq!(RbsError::InternalError.error_class(), ErrorClass::Internal);
    assert_eq!(
        RbsError::InternalUnexpected { context: "ctx".to_string() }.error_class(),
        ErrorClass::Internal
    );
}

// ── http_status ──

#[test]
fn http_status_authn() {
    assert_eq!(RbsError::AuthnMissingToken.http_status(), 401);
    assert_eq!(RbsError::AuthnInvalidToken.http_status(), 401);
    assert_eq!(RbsError::AuthnExpiredToken.http_status(), 401);
}

#[test]
fn http_status_authz() {
    assert_eq!(RbsError::AuthzDenied.http_status(), 403);
    assert_eq!(RbsError::AuthzInsufficientPermissions.http_status(), 403);
}

#[test]
fn http_status_param() {
    assert_eq!(RbsError::ParamMissing { param: "x" }.http_status(), 400);
    assert_eq!(RbsError::ParamInvalid { param: "y" }.http_status(), 400);
    assert_eq!(RbsError::ParamMalformed.http_status(), 400);
    assert_eq!(RbsError::InvalidParameter("z".to_string()).http_status(), 400);
    assert_eq!(RbsError::NotImplemented.http_status(), 501);
}

#[test]
fn http_status_resource() {
    assert_eq!(RbsError::ResourceNotFound.http_status(), 404);
    assert_eq!(RbsError::ResourceConflict.http_status(), 409);
    assert_eq!(RbsError::ResourceGone.http_status(), 404);
    assert_eq!(RbsError::ResourceQuotaExceeded.http_status(), 409);
}

#[test]
fn http_status_provider_and_dependency() {
    assert_eq!(RbsError::AttestationProviderUnavailable.http_status(), 503);
    assert_eq!(RbsError::ResourceProviderUnavailable.http_status(), 503);
    assert_eq!(RbsError::ProviderTimeout.http_status(), 503);
    assert_eq!(RbsError::ProviderNotFound("p".to_string()).http_status(), 503);
    assert_eq!(RbsError::PolicyEvaluationError("e".to_string()).http_status(), 503);
    assert_eq!(RbsError::DependencyUnavailable { service: "db" }.http_status(), 503);
}

#[test]
fn http_status_rate_limit() {
    assert_eq!(RbsError::RateLimitExceeded.http_status(), 429);
}

#[test]
fn http_status_internal() {
    assert_eq!(RbsError::InternalError.http_status(), 500);
    assert_eq!(RbsError::InternalUnexpected { context: "c".to_string() }.http_status(), 500);
}

// ── retryable ──

#[test]
fn retryable_no() {
    assert_eq!(RbsError::ResourceNotFound.retryable(), Retryable::No);
    assert_eq!(RbsError::AuthzDenied.retryable(), Retryable::No);
    assert_eq!(RbsError::AuthnInvalidToken.retryable(), Retryable::No);
    assert_eq!(RbsError::ParamMissing { param: "x" }.retryable(), Retryable::No);
    assert_eq!(RbsError::ParamInvalid { param: "y" }.retryable(), Retryable::No);
    assert_eq!(RbsError::ParamMalformed.retryable(), Retryable::No);
    assert_eq!(RbsError::InvalidParameter("z".to_string()).retryable(), Retryable::No);
    assert_eq!(RbsError::NotImplemented.retryable(), Retryable::No);
    assert_eq!(RbsError::ResourceConflict.retryable(), Retryable::No);
    assert_eq!(RbsError::AuthzInsufficientPermissions.retryable(), Retryable::No);
    assert_eq!(RbsError::ResourceQuotaExceeded.retryable(), Retryable::No);
}

#[test]
fn retryable_yes() {
    assert_eq!(RbsError::RateLimitExceeded.retryable(), Retryable::Yes);
    assert_eq!(RbsError::DependencyUnavailable { service: "db" }.retryable(), Retryable::Yes);
    assert_eq!(RbsError::ProviderTimeout.retryable(), Retryable::Yes);
}

#[test]
fn retryable_idempotent() {
    assert_eq!(RbsError::AuthnMissingToken.retryable(), Retryable::Idempotent);
    assert_eq!(RbsError::AuthnExpiredToken.retryable(), Retryable::Idempotent);
    assert_eq!(RbsError::ResourceGone.retryable(), Retryable::Idempotent);
    assert_eq!(RbsError::AttestationProviderUnavailable.retryable(), Retryable::Idempotent);
    assert_eq!(RbsError::ResourceProviderUnavailable.retryable(), Retryable::Idempotent);
    assert_eq!(RbsError::InternalError.retryable(), Retryable::Idempotent);
    assert_eq!(RbsError::InternalUnexpected { context: "c".to_string() }.retryable(), Retryable::Idempotent);
}

// ── external_message ──

#[test]
fn external_message_all_variants() {
    assert_eq!(RbsError::AuthnMissingToken.external_message(), "missing authentication");
    assert_eq!(RbsError::AuthnInvalidToken.external_message(), "invalid authentication");
    assert_eq!(RbsError::AuthnExpiredToken.external_message(), "authentication expired");
    assert_eq!(RbsError::AuthzDenied.external_message(), "access denied");
    assert_eq!(RbsError::AuthzInsufficientPermissions.external_message(), "insufficient permissions");
    assert_eq!(RbsError::ParamMissing { param: "x" }.external_message(), "missing required parameter");
    assert_eq!(RbsError::ParamInvalid { param: "y" }.external_message(), "invalid parameter");
    assert_eq!(RbsError::ParamMalformed.external_message(), "malformed request");
    assert_eq!(RbsError::InvalidParameter("z".to_string()).external_message(), "invalid parameter");
    assert_eq!(RbsError::NotImplemented.external_message(), "not implemented");
    assert_eq!(RbsError::ResourceNotFound.external_message(), "resource not found");
    assert_eq!(RbsError::ResourceConflict.external_message(), "resource conflict");
    assert_eq!(RbsError::ResourceGone.external_message(), "resource no longer available");
    assert_eq!(RbsError::ResourceQuotaExceeded.external_message(), "resource quota exceeded");
    assert_eq!(RbsError::AttestationProviderUnavailable.external_message(), "service temporarily unavailable");
    assert_eq!(RbsError::ResourceProviderUnavailable.external_message(), "service temporarily unavailable");
    assert_eq!(RbsError::ProviderTimeout.external_message(), "service temporarily unavailable");
    assert_eq!(RbsError::ProviderNotFound("p".to_string()).external_message(), "service temporarily unavailable");
    assert_eq!(RbsError::PolicyEvaluationError("e".to_string()).external_message(), "service temporarily unavailable");
    assert_eq!(RbsError::DependencyUnavailable { service: "db" }.external_message(), "service dependency unavailable");
    assert_eq!(RbsError::RateLimitExceeded.external_message(), "rate limit exceeded");
    assert_eq!(RbsError::InternalError.external_message(), "internal server error");
    assert_eq!(RbsError::InternalUnexpected { context: "c".to_string() }.external_message(), "internal server error");
}

// ── serialization ──

#[test]
fn rbs_error_serialize_produces_external_message() {
    let json = serde_json::to_string(&RbsError::AuthnMissingToken).unwrap();
    assert_eq!(json, "\"missing authentication\"");
    let json = serde_json::to_string(&RbsError::InternalError).unwrap();
    assert_eq!(json, "\"internal server error\"");
    let json = serde_json::to_string(&RbsError::RateLimitExceeded).unwrap();
    assert_eq!(json, "\"rate limit exceeded\"");
}
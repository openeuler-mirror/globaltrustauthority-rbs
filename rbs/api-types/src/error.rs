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

//! RBS unified error types.
//!
//! Internal error representation; maps to HTTP status and stable error codes
//! for external responses.

use serde::Serialize;
use thiserror::Error;

/// Error class categories for external error reporting.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Authentication failure.
    Authn,
    /// Authorization failure.
    Authz,
    /// Invalid request parameters.
    Param,
    /// Resource not found or unavailable.
    Resource,
    /// Provider/backend error.
    Provider,
    /// Dependency unavailable.
    Dependency,
    /// Rate limiting.
    RateLimit,
    /// Internal server error.
    Internal,
}

/// Stable error code for programmatic error handling.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StableCode {
    // Authn errors
    AuthnMissingToken,
    AuthnInvalidToken,
    AuthnExpiredToken,
    // Authz errors
    AuthzDenied,
    AuthzInsufficientPermissions,
    // Param errors
    ParamMissing,
    ParamInvalid,
    ParamMalformed,
    InvalidParameter,
    NotImplemented,
    // Resource errors
    ResourceNotFound,
    ResourceConflict,
    ResourceGone,
    // Provider errors
    ProviderUnavailable,
    ProviderTimeout,
    // Dependency errors
    DependencyUnavailable,
    // Rate limit
    RateLimitExceeded,
    // Internal
    InternalError,
    InternalUnexpected,
}

/// HTTP status code associated with an error.
#[derive(Debug, Clone, Copy)]
pub enum HttpStatus {
    Ok = 200,
    Created = 201,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    NotImplemented = 501,
    Conflict = 409,
    TooManyRequests = 429,
    InternalServerError = 500,
    ServiceUnavailable = 503,
}

impl From<StableCode> for HttpStatus {
    fn from(code: StableCode) -> Self {
        match code {
            StableCode::AuthnMissingToken
            | StableCode::AuthnInvalidToken
            | StableCode::AuthnExpiredToken => HttpStatus::Unauthorized,
            StableCode::AuthzDenied | StableCode::AuthzInsufficientPermissions => {
                HttpStatus::Forbidden
            }
            StableCode::ParamMissing | StableCode::ParamInvalid | StableCode::ParamMalformed
            | StableCode::InvalidParameter => {
                HttpStatus::BadRequest
            }
            StableCode::NotImplemented => HttpStatus::NotImplemented,
            StableCode::ResourceNotFound | StableCode::ResourceGone => HttpStatus::NotFound,
            StableCode::ResourceConflict => HttpStatus::Conflict,
            StableCode::RateLimitExceeded => HttpStatus::TooManyRequests,
            StableCode::ProviderUnavailable
            | StableCode::ProviderTimeout
            | StableCode::DependencyUnavailable => HttpStatus::ServiceUnavailable,
            StableCode::InternalError | StableCode::InternalUnexpected => {
                HttpStatus::InternalServerError
            }
        }
    }
}

impl From<ErrorClass> for HttpStatus {
    fn from(class: ErrorClass) -> Self {
        match class {
            ErrorClass::Authn => HttpStatus::Unauthorized,
            ErrorClass::Authz => HttpStatus::Forbidden,
            ErrorClass::Param => HttpStatus::BadRequest,
            ErrorClass::Resource => HttpStatus::NotFound,
            ErrorClass::Provider | ErrorClass::Dependency => HttpStatus::ServiceUnavailable,
            ErrorClass::RateLimit => HttpStatus::TooManyRequests,
            ErrorClass::Internal => HttpStatus::InternalServerError,
        }
    }
}

/// Whether a client should retry the request.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Retryable {
    Yes,
    No,
    Idempotent,
}

impl From<StableCode> for Retryable {
    fn from(code: StableCode) -> Self {
        match code {
            StableCode::ResourceNotFound
            | StableCode::AuthzDenied
            | StableCode::AuthnInvalidToken
            | StableCode::ParamMissing
            | StableCode::ParamInvalid
            | StableCode::ParamMalformed
            | StableCode::InvalidParameter
            | StableCode::NotImplemented
            | StableCode::ResourceConflict
            | StableCode::AuthzInsufficientPermissions => Retryable::No,
            StableCode::RateLimitExceeded
            | StableCode::ProviderTimeout
            | StableCode::DependencyUnavailable => Retryable::Yes,
            StableCode::AuthnMissingToken
            | StableCode::AuthnExpiredToken
            | StableCode::ResourceGone
            | StableCode::ProviderUnavailable
            | StableCode::InternalError
            | StableCode::InternalUnexpected => Retryable::Idempotent,
        }
    }
}

/// RbsError is the unified internal error type.
///
/// It carries enough context to map to an HTTP response with a stable error code
/// without leaking internal implementation details.
#[derive(Debug, Error)]
pub enum RbsError {
    // Authentication errors
    #[error("missing authentication token")]
    AuthnMissingToken,

    #[error("invalid authentication token")]
    AuthnInvalidToken,

    #[error("authentication token expired")]
    AuthnExpiredToken,

    // Authorization errors
    #[error("authorization denied")]
    AuthzDenied,

    #[error("insufficient permissions")]
    AuthzInsufficientPermissions,

    // Parameter errors
    #[error("missing required parameter: {param}")]
    ParamMissing { param: &'static str },

    #[error("invalid parameter value: {param}")]
    ParamInvalid { param: &'static str },

    #[error("malformed request body")]
    ParamMalformed,

    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("not implemented")]
    NotImplemented,

    // Resource errors
    #[error("resource not found")]
    ResourceNotFound,

    #[error("resource conflict")]
    ResourceConflict,

    #[error("resource gone")]
    ResourceGone,

    // Provider errors
    #[error("attestation provider unavailable")]
    AttestationProviderUnavailable,

    #[error("resource provider unavailable")]
    ResourceProviderUnavailable,

    #[error("provider timeout")]
    ProviderTimeout,

    #[error("provider not found: {0}")]
    ProviderNotFound(String),

    // Dependency errors
    #[error("dependency unavailable: {service}")]
    DependencyUnavailable { service: &'static str },

    // Rate limit
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    // Policy evaluation errors
    #[error("policy evaluation error: {0}")]
    PolicyEvaluationError(String),

    // Internal errors
    #[error("internal server error")]
    InternalError,

    #[error("unexpected error: {context}")]
    InternalUnexpected { context: String },
}

impl RbsError {
    /// Returns the error class for this error.
    pub fn error_class(&self) -> ErrorClass {
        match self {
            Self::AuthnMissingToken | Self::AuthnInvalidToken | Self::AuthnExpiredToken => {
                ErrorClass::Authn
            }
            Self::AuthzDenied | Self::AuthzInsufficientPermissions => ErrorClass::Authz,
            Self::ParamMissing { .. }
            | Self::ParamInvalid { .. }
            | Self::ParamMalformed
            | Self::InvalidParameter(_)
            | Self::NotImplemented => ErrorClass::Param,
            Self::ResourceNotFound | Self::ResourceConflict | Self::ResourceGone => {
                ErrorClass::Resource
            }
            Self::AttestationProviderUnavailable
            | Self::ResourceProviderUnavailable
            | Self::ProviderTimeout
            | Self::ProviderNotFound(_)
            | Self::PolicyEvaluationError(_) => ErrorClass::Provider,
            Self::DependencyUnavailable { .. } => ErrorClass::Dependency,
            Self::RateLimitExceeded => ErrorClass::RateLimit,
            Self::InternalError | Self::InternalUnexpected { .. } => ErrorClass::Internal,
        }
    }

    /// Returns the stable error code for external error reporting.
    pub fn stable_code(&self) -> StableCode {
        match self {
            Self::AuthnMissingToken => StableCode::AuthnMissingToken,
            Self::AuthnInvalidToken => StableCode::AuthnInvalidToken,
            Self::AuthnExpiredToken => StableCode::AuthnExpiredToken,
            Self::AuthzDenied => StableCode::AuthzDenied,
            Self::AuthzInsufficientPermissions => StableCode::AuthzInsufficientPermissions,
            Self::ParamMissing { .. } => StableCode::ParamMissing,
            Self::ParamInvalid { .. } => StableCode::ParamInvalid,
            Self::ParamMalformed => StableCode::ParamMalformed,
            Self::InvalidParameter(_) => StableCode::InvalidParameter,
            Self::NotImplemented => StableCode::NotImplemented,
            Self::ResourceNotFound => StableCode::ResourceNotFound,
            Self::ResourceConflict => StableCode::ResourceConflict,
            Self::ResourceGone => StableCode::ResourceGone,
            Self::AttestationProviderUnavailable
            | Self::ResourceProviderUnavailable
            | Self::ProviderTimeout
            | Self::ProviderNotFound(_)
            | Self::PolicyEvaluationError(_) => StableCode::ProviderUnavailable,
            Self::DependencyUnavailable { .. } => StableCode::DependencyUnavailable,
            Self::RateLimitExceeded => StableCode::RateLimitExceeded,
            Self::InternalError => StableCode::InternalError,
            Self::InternalUnexpected { .. } => StableCode::InternalUnexpected,
        }
    }

    /// Returns the HTTP status code for this error.
    pub fn http_status(&self) -> u16 {
        let status: HttpStatus = self.stable_code().into();
        status as u16
    }

    /// Returns whether the error is retryable.
    pub fn retryable(&self) -> Retryable {
        self.stable_code().into()
    }

    /// Returns the error message suitable for external display.
    ///
    /// Does not leak internal implementation details.
    pub fn external_message(&self) -> &'static str {
        match self {
            Self::AuthnMissingToken { .. } => "missing authentication",
            Self::AuthnInvalidToken { .. } => "invalid authentication",
            Self::AuthnExpiredToken { .. } => "authentication expired",
            Self::AuthzDenied => "access denied",
            Self::AuthzInsufficientPermissions => "insufficient permissions",
            Self::ParamMissing { .. } => "missing required parameter",
            Self::ParamInvalid { .. } => "invalid parameter",
            Self::ParamMalformed => "malformed request",
            Self::InvalidParameter(_) => "invalid parameter",
            Self::NotImplemented => "not implemented",
            Self::ResourceNotFound => "resource not found",
            Self::ResourceConflict => "resource conflict",
            Self::ResourceGone => "resource no longer available",
            Self::AttestationProviderUnavailable
            | Self::ResourceProviderUnavailable
            | Self::ProviderTimeout
            | Self::ProviderNotFound(_)
            | Self::PolicyEvaluationError(_) => "service temporarily unavailable",
            Self::DependencyUnavailable { .. } => "service dependency unavailable",
            Self::RateLimitExceeded => "rate limit exceeded",
            Self::InternalError | Self::InternalUnexpected { .. } => "internal server error",
        }
    }
}

impl Serialize for RbsError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.external_message().serialize(serializer)
    }
}

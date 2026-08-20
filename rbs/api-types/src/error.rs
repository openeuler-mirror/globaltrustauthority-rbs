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
//! Also includes [`ErrorBody`] — the HTTP error response payload struct.

use serde::{Deserialize, Serialize};
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
    AuthzSelfUpdateFieldRestricted,
    AuthzBuiltInAdminProtected,
    AuthzAdminRoleNotAssignable,
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
    ResourceQuotaExceeded,
    ManagementProviderNotFound,
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
            StableCode::AuthzDenied
            | StableCode::AuthzInsufficientPermissions
            | StableCode::AuthzSelfUpdateFieldRestricted
            | StableCode::AuthzBuiltInAdminProtected
            | StableCode::AuthzAdminRoleNotAssignable => {
                HttpStatus::Forbidden
            }
            StableCode::ParamMissing | StableCode::ParamInvalid | StableCode::ParamMalformed
            | StableCode::InvalidParameter => {
                HttpStatus::BadRequest
            }
            StableCode::NotImplemented => HttpStatus::NotImplemented,
            StableCode::ResourceNotFound
            | StableCode::ResourceGone
            | StableCode::ManagementProviderNotFound => HttpStatus::NotFound,
            StableCode::ResourceConflict | StableCode::ResourceQuotaExceeded => HttpStatus::Conflict,
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
            | StableCode::AuthzInsufficientPermissions
            | StableCode::AuthzSelfUpdateFieldRestricted
            | StableCode::AuthzBuiltInAdminProtected
            | StableCode::AuthzAdminRoleNotAssignable
            | StableCode::ResourceQuotaExceeded
            | StableCode::ManagementProviderNotFound => Retryable::No,
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

    /// A non-admin self-update attempted to modify a protected field
    /// (`role` or `enabled`). `field` identifies which field was rejected.
    #[error("self-update may not modify '{field}'")]
    SelfUpdateFieldRestricted { field: &'static str },

    /// An update attempted to modify a protected field of the built-in
    /// `Administrator` account (its `role` or `enabled`). `field` identifies
    /// which field was rejected. Applies to all callers, including the
    /// built-in admin itself, to prevent lock-out/demotion.
    #[error("cannot modify '{field}' of the built-in administrator")]
    BuiltInAdminProtected { field: &'static str },

    /// An update attempted to assign the `admin` role to a non-built-in user.
    /// The `admin` role is pre-configured and not API-assignable; only the
    /// built-in Administrator holding `role: "admin"` (a no-op) is permitted.
    #[error("admin role is pre-configured and not API-assignable")]
    AdminRoleNotAssignable,

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

    #[error("user owns {policies} policy(ies) and {resources} resource(s)")]
    UserHasDependents { policies: u64, resources: u64 },

    #[error("resource gone")]
    ResourceGone,

    #[error("resource quota exceeded")]
    ResourceQuotaExceeded,

    #[error("management provider not found: {0}")]
    ManagementProviderNotFound(String),

    // Provider errors
    #[error("attestation provider unavailable")]
    AttestationProviderUnavailable,

    #[error("attestation provider error: {body}")]
    AttestationProviderError { status: u16, body: String },

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
            Self::AuthzDenied
            | Self::AuthzInsufficientPermissions
            | Self::SelfUpdateFieldRestricted { .. }
            | Self::BuiltInAdminProtected { .. }
            | Self::AdminRoleNotAssignable => ErrorClass::Authz,
            Self::ParamMissing { .. }
            | Self::ParamInvalid { .. }
            | Self::ParamMalformed
            | Self::InvalidParameter(_)
            | Self::NotImplemented => ErrorClass::Param,
            Self::ResourceNotFound
            | Self::ResourceConflict
            | Self::ResourceGone
            | Self::ResourceQuotaExceeded
            | Self::UserHasDependents { .. }
            | Self::ManagementProviderNotFound(_) => {
                ErrorClass::Resource
            }
            Self::AttestationProviderUnavailable
            | Self::AttestationProviderError { .. }
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
            Self::SelfUpdateFieldRestricted { .. } => StableCode::AuthzSelfUpdateFieldRestricted,
            Self::BuiltInAdminProtected { .. } => StableCode::AuthzBuiltInAdminProtected,
            Self::AdminRoleNotAssignable => StableCode::AuthzAdminRoleNotAssignable,
            Self::ParamMissing { .. } => StableCode::ParamMissing,
            Self::ParamInvalid { .. } => StableCode::ParamInvalid,
            Self::ParamMalformed => StableCode::ParamMalformed,
            Self::InvalidParameter(_) => StableCode::InvalidParameter,
            Self::NotImplemented => StableCode::NotImplemented,
            Self::ResourceNotFound => StableCode::ResourceNotFound,
            Self::ResourceConflict => StableCode::ResourceConflict,
            Self::UserHasDependents { .. } => StableCode::ResourceConflict,
            Self::ResourceGone => StableCode::ResourceGone,
            Self::ResourceQuotaExceeded => StableCode::ResourceQuotaExceeded,
            Self::ManagementProviderNotFound(_) => StableCode::ManagementProviderNotFound,
            Self::AttestationProviderUnavailable
            | Self::AttestationProviderError { .. }
            | Self::ResourceProviderUnavailable
            | Self::ProviderNotFound(_)
            | Self::PolicyEvaluationError(_) => StableCode::ProviderUnavailable,
            Self::ProviderTimeout => StableCode::ProviderTimeout,
            Self::DependencyUnavailable { .. } => StableCode::DependencyUnavailable,
            Self::RateLimitExceeded => StableCode::RateLimitExceeded,
            Self::InternalError => StableCode::InternalError,
            Self::InternalUnexpected { .. } => StableCode::InternalUnexpected,
        }
    }

    /// Returns the HTTP status code for this error.
    ///
    /// `AttestationProviderError` forwards GTA's HTTP status verbatim so the
    /// caller sees the same status the attestation backend returned (e.g. 400,
    /// 500). All other variants derive their status from the stable error code.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::AttestationProviderError { status, .. } => *status,
            _ => {
                let status: HttpStatus = self.stable_code().into();
                status as u16
            }
        }
    }

    /// Returns whether the error is retryable.
    pub fn retryable(&self) -> Retryable {
        self.stable_code().into()
    }

    /// Returns the error message suitable for external display.
    ///
    /// Does not leak internal implementation details.
    /// Returns `String` because some variants (e.g. `ManagementProviderNotFound`)
    /// include dynamic context such as the provider name.
    pub fn external_message(&self) -> String {
        match self {
            Self::AuthnMissingToken { .. } => "missing authentication".to_string(),
            Self::AuthnInvalidToken { .. } => "invalid authentication".to_string(),
            Self::AuthnExpiredToken { .. } => "authentication expired".to_string(),
            Self::AuthzDenied => "access denied".to_string(),
            Self::AuthzInsufficientPermissions => "insufficient permissions".to_string(),
            Self::SelfUpdateFieldRestricted { field } => {
                format!("self-update may not modify '{field}'")
            }
            Self::BuiltInAdminProtected { field } => {
                format!("cannot modify '{field}' of the built-in administrator")
            }
            Self::AdminRoleNotAssignable => {
                "admin role is pre-configured and not API-assignable".to_string()
            }
            Self::ParamMissing { .. } => "missing required parameter".to_string(),
            Self::ParamInvalid { .. } => "invalid parameter".to_string(),
            Self::ParamMalformed => "malformed request".to_string(),
            Self::InvalidParameter(_) => "invalid parameter".to_string(),
            Self::NotImplemented => "not implemented".to_string(),
            Self::ResourceNotFound => "resource not found".to_string(),
            Self::ResourceConflict => "resource conflict".to_string(),
            Self::UserHasDependents { .. } => "user has dependents".to_string(),
            Self::ResourceGone => "resource no longer available".to_string(),
            Self::ResourceQuotaExceeded => "resource quota exceeded".to_string(),
            Self::AttestationProviderError { body, .. } => {
                format!("attestation provider error: {}", body)
            }
            Self::AttestationProviderUnavailable
            | Self::ResourceProviderUnavailable
            | Self::ProviderTimeout
            | Self::ProviderNotFound(_)
            | Self::PolicyEvaluationError(_) => "service temporarily unavailable".to_string(),
            Self::DependencyUnavailable { .. } => "service dependency unavailable".to_string(),
            Self::RateLimitExceeded => "rate limit exceeded".to_string(),
            Self::InternalError | Self::InternalUnexpected { .. } => "internal server error".to_string(),
            Self::ManagementProviderNotFound(name) => {
                format!("management provider not found: {}", name)
            }
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

// ── HTTP error response body ──────────────────────────────────────────────

/// Error payload for HTTP error responses (e.g. 500).
#[derive(Clone, Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    /// Error string for the caller: may be a stable code, a short machine-oriented label,
    /// or a concise human-readable message. Must not include stack traces or secrets.
    pub error: String,
}

impl ErrorBody {
    /// Creates a new error body with the given message.
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }
}

impl From<&str> for ErrorBody {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for ErrorBody {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&RbsError> for ErrorBody {
    fn from(e: &RbsError) -> Self {
        ErrorBody::new(e.external_message())
    }
}

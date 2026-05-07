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

//! User management types with validation.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

use crate::error::RbsError;

/// Request body for POST /rbs/v0/users (create user).
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(rename_all = "snake_case")]
pub struct UserCreateRequest {
    /// Login or unique handle. Immutable.
    #[validate(length(min = 1, max = 36), custom(function = "validate_username_chars"))]
    pub username: String,

    /// Optional role name; only "user" is allowed (admin is pre-configured).
    #[validate(custom(function = "validate_user_role"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,

    /// Whether the account is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Authentication type (currently only "jwt").
    #[validate(custom(function = "validate_auth_type"))]
    pub auth_type: String,

    /// PEM-encoded public key (mutually exclusive with `jwk`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// JWK public key object (mutually exclusive with `public_key`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
}

impl UserCreateRequest {
    /// Cross-field validation: `public_key` / `jwk` mutual exclusion.
    pub fn validate_key_pair(&self) -> Result<(), RbsError> {
        let has_pk = self.public_key.as_deref().map_or(false, |s| !s.is_empty());
        let has_jwk = self.jwk.is_some();

        if !has_pk && !has_jwk {
            return Err(RbsError::InvalidParameter(
                "Must provide either public_key or jwk".to_string(),
            ));
        }
        if has_pk && has_jwk {
            return Err(RbsError::InvalidParameter(
                "public_key and jwk are mutually exclusive".to_string(),
            ));
        }
        Ok(())
    }
}

/// Request body for PUT /rbs/v0/users/{username} (update user).
///
/// All fields are optional, but at least one must be provided.
/// `username` is NOT in the request body — it is immutable.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(rename_all = "snake_case")]
pub struct UserUpdateRequest {
    /// Replace role (semantics per implementation).
    #[validate(custom(function = "validate_user_role"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,

    /// Whether the account can authenticate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Authentication type (currently only "jwt").
    #[validate(custom(function = "validate_opt_auth_type"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,

    /// PEM-encoded public key (mutually exclusive with `jwk`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// JWK public key object (mutually exclusive with `public_key`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
}

impl UserUpdateRequest {
    /// Cross-field: at least one field required + public_key/jwk mutual exclusion.
    pub fn validate(&self) -> Result<(), RbsError> {
        if self.role.is_none()
            && self.enabled.is_none()
            && self.auth_type.is_none()
            && self.public_key.is_none()
            && self.jwk.is_none()
        {
            return Err(RbsError::InvalidParameter(
                "At least one update field is required".to_string(),
            ));
        }

        let has_pk = self.public_key.as_deref().map_or(false, |s| !s.is_empty());
        let has_jwk = self.jwk.is_some();

        if has_pk && has_jwk {
            return Err(RbsError::InvalidParameter(
                "public_key and jwk are mutually exclusive".to_string(),
            ));
        }
        Ok(())
    }
}

// ── Validation helpers (used by #[validate]) ──

/// Allowed values for `auth_type`. Add new types here.
const VALID_AUTH_TYPES: &[&str] = &["jwt"];

/// Allowed values for `role`. Add new roles here.
const VALID_ROLES: &[&str] = &["user"];

fn validate_auth_type(auth_type: &str) -> Result<(), validator::ValidationError> {
    if VALID_AUTH_TYPES.contains(&auth_type) {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("invalid_auth_type");
        err.message = Some(format!(
            "auth_type must be one of [{}]",
            VALID_AUTH_TYPES.join(", ")
        ).into());
        Err(err)
    }
}

fn validate_opt_auth_type(auth_type: &str) -> Result<(), validator::ValidationError> {
    validate_auth_type(auth_type)
}

fn validate_user_role(role: &str) -> Result<(), validator::ValidationError> {
    if VALID_ROLES.contains(&role) {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("invalid_role");
        err.message = Some(format!(
            "role must be one of [{}]",
            VALID_ROLES.join(", ")
        ).into());
        Err(err)
    }
}

fn validate_username_chars(username: &str) -> Result<(), validator::ValidationError> {
    if username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("invalid_username");
        err.message = Some("username must only contain [a-zA-Z0-9_-]".into());
        Err(err)
    }
}

/// Response for user retrieval, creation, and update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserResponse {
    /// Stable user ID (UUID).
    pub id: String,
    /// Human-facing login or handle.
    pub username: String,
    /// User role.
    pub role: String,
    /// Whether the account is enabled.
    pub enabled: bool,
    /// Creation time (RFC 3339).
    pub created_at: String,
    /// Last modification time (RFC 3339).
    pub updated_at: String,
}

/// Paginated response for GET /rbs/v0/users.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserListResponse {
    /// Page of users.
    pub items: Vec<UserResponse>,
    /// Total matching users (not only this page).
    pub total_count: i64,
    /// Effective page size (may mirror request `limit`).
    pub limit: i64,
    /// Effective skip count (may mirror request `offset`).
    pub offset: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request_valid() {
        let req = UserCreateRequest {
            username: "alice".to_string(),
            role: None,
            enabled: None,
            auth_type: "jwt".to_string(),
            public_key: Some("key".to_string()),
            jwk: None,
        };
        assert!(validator::Validate::validate(&req).is_ok());
        assert!(req.validate_key_pair().is_ok());
    }

    #[test]
    fn test_create_request_role_admin_rejected() {
        let req = UserCreateRequest {
            username: "alice".to_string(),
            role: Some("admin".to_string()),
            enabled: None,
            auth_type: "jwt".to_string(),
            public_key: Some("key".to_string()),
            jwk: None,
        };
        assert!(validator::Validate::validate(&req).is_err());
    }

    #[test]
    fn test_create_request_missing_key() {
        let req = UserCreateRequest {
            username: "alice".to_string(),
            role: None,
            enabled: None,
            auth_type: "jwt".to_string(),
            public_key: None,
            jwk: None,
        };
        assert!(validator::Validate::validate(&req).is_ok());
        assert!(req.validate_key_pair().is_err());
    }

    #[test]
    fn test_username_length() {
        assert!(validator::Validate::validate(&UserCreateRequest {
            username: "".to_string(),
            role: None,
            enabled: None,
            auth_type: "jwt".to_string(),
            public_key: Some("key".to_string()),
            jwk: None,
        }).is_err());

        assert!(validator::Validate::validate(&UserCreateRequest {
            username: "a".repeat(37),
            role: None,
            enabled: None,
            auth_type: "jwt".to_string(),
            public_key: Some("key".to_string()),
            jwk: None,
        }).is_err());
    }
}

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

// ── Enums ──

/// User role. `Admin` is pre-configured and cannot be created via the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    User,
}

/// Authentication type. Add new types here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Jwt,
}

// ── Request / response types ──

/// Request body for POST /rbs/v0/users (create user).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct UserCreateRequest {
    /// Login or unique handle. Immutable.
    #[validate(length(min = 1, max = 36), custom(function = "validate_username_chars"))]
    pub username: String,

    /// Optional role; only `user` is allowed via API (admin is pre-configured).
    #[validate(custom(function = "validate_create_role"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,

    /// Whether the account is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Authentication type.
    pub auth_type: AuthType,

    /// Base64-encoded PEM public key (mutually exclusive with `jwk`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// JWK public key JSON object (mutually exclusive with `public_key`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
}

impl UserCreateRequest {
    /// Cross-field validation: `public_key` / `jwk` mutual exclusion.
    pub fn validate_key_pair(&self) -> Result<(), RbsError> {
        let has_pk = self.public_key.as_deref().map_or(false, |s| !s.is_empty());
        let has_jwk = self.jwk.as_ref().map_or(false, |s| !s.is_null());

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
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct UserUpdateRequest {
    /// New role (admin users only).
    #[validate(custom(function = "validate_update_role"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,

    /// Whether the account can authenticate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Authentication type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<AuthType>,

    /// Base64-encoded PEM public key (mutually exclusive with `jwk`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// JWK public key JSON object (mutually exclusive with `public_key`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
}

impl UserUpdateRequest {
    /// Cross-field: at least one field required + public_key/jwk mutual exclusion.
    pub fn validate_cross_fields(&self) -> Result<(), RbsError> {
        let has_role = self.role.is_some();
        let has_enabled = self.enabled.is_some();
        let has_auth_type = self.auth_type.is_some();
        let has_public_key = self.public_key.as_ref().map_or(false, |s| !s.is_empty());
        let has_jwk = self.jwk.as_ref().map_or(false, |s| !s.is_null());

        // Reject empty update: {} with no fields provided
        if !has_role && !has_enabled && !has_auth_type && !has_public_key && !has_jwk {
            return Err(RbsError::InvalidParameter(
                "At least one update field is required".to_string(),
            ));
        }

        if has_public_key && has_jwk {
            return Err(RbsError::InvalidParameter(
                "public_key and jwk are mutually exclusive".to_string(),
            ));
        }
        Ok(())
    }
}

/// Response for user retrieval, creation, and update.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct UserResponse {
    /// Stable user ID (UUID).
    pub id: String,
    /// Human-facing login or handle.
    pub username: String,
    /// User role.
    pub role: Role,
    /// Whether the account is enabled.
    pub enabled: bool,
    /// Creation time (RFC 3339).
    pub created_at: String,
    /// Last modification time (RFC 3339).
    pub updated_at: String,
}

/// Query parameters for GET /rbs/v0/users (list users).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct UserListQuery {
    /// Page size.
    #[validate(range(min = 1, max = 100))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,

    /// Offset.
    #[validate(range(min = 0, max = 100_000))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,

    /// Filter by role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,

    /// Filter by enabled status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// Paginated response for GET /rbs/v0/users.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct UserListResponse {
    /// Page of users.
    pub users: Vec<UserResponse>,
    /// Total matching users (not only this page).
    pub total_count: i64,
    /// Effective page size (may mirror request `limit`).
    pub limit: i64,
    /// Effective skip count (may mirror request `offset`).
    pub offset: i64,
}

// ── Validation helpers (used by #[validate]) ──

fn validate_create_role(role: &Role) -> Result<(), validator::ValidationError> {
    if *role == Role::Admin {
        let mut err = validator::ValidationError::new("invalid_role");
        err.message = Some("role must be 'user' (admin is pre-configured)".into());
        Err(err)
    } else {
        Ok(())
    }
}

fn validate_update_role(role: &Role) -> Result<(), validator::ValidationError> {
    if *role == Role::Admin {
        let mut err = validator::ValidationError::new("invalid_role");
        err.message = Some("role must be 'user' (admin is pre-configured)".into());
        Err(err)
    } else {
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request_valid() {
        let json = serde_json::json!({
            "username": "alice",
            "auth_type": "jwt",
            "public_key": "key"
        });
        let req: UserCreateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.auth_type, AuthType::Jwt);
        assert!(validator::Validate::validate(&req).is_ok());
        assert!(req.validate_key_pair().is_ok());
    }

    #[test]
    fn test_create_request_role_admin_rejected() {
        let json = serde_json::json!({
            "username": "alice",
            "auth_type": "jwt",
            "role": "admin",
            "public_key": "key"
        });
        let req: UserCreateRequest = serde_json::from_value(json).unwrap();
        assert!(validator::Validate::validate(&req).is_err());
    }

    #[test]
    fn test_create_request_missing_key() {
        let json = serde_json::json!({
            "username": "alice",
            "auth_type": "jwt"
        });
        let req: UserCreateRequest = serde_json::from_value(json).unwrap();
        assert!(validator::Validate::validate(&req).is_ok());
        assert!(req.validate_key_pair().is_err());
    }

    #[test]
    fn test_invalid_role_rejected_by_serde() {
        let json = serde_json::json!({
            "username": "alice",
            "auth_type": "jwt",
            "role": "superuser",
            "public_key": "key"
        });
        let result: std::result::Result<UserCreateRequest, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_auth_type_rejected_by_serde() {
        let json = serde_json::json!({
            "username": "alice",
            "auth_type": "invalid",
            "public_key": "key"
        });
        let result: std::result::Result<UserCreateRequest, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    // ── UserListQuery validation ──

    #[test]
    fn list_query_valid_no_filters() {
        let q = UserListQuery { limit: None, offset: None, role: None, enabled: None };
        assert!(validator::Validate::validate(&q).is_ok());
    }

    #[test]
    fn list_query_valid_with_filters() {
        let q = UserListQuery { limit: Some(10), offset: Some(0), role: Some(Role::User), enabled: Some(true) };
        assert!(validator::Validate::validate(&q).is_ok());
    }

    #[test]
    fn list_query_limit_below_min() {
        let q = UserListQuery { limit: Some(0), offset: None, role: None, enabled: None };
        assert!(validator::Validate::validate(&q).is_err());
    }

    #[test]
    fn list_query_limit_above_max() {
        let q = UserListQuery { limit: Some(101), offset: None, role: None, enabled: None };
        assert!(validator::Validate::validate(&q).is_err());
    }

    #[test]
    fn list_query_offset_below_min() {
        let q = UserListQuery { limit: None, offset: Some(-1), role: None, enabled: None };
        assert!(validator::Validate::validate(&q).is_err());
    }

    #[test]
    fn list_query_offset_above_max() {
        let q = UserListQuery { limit: None, offset: Some(100_001), role: None, enabled: None };
        assert!(validator::Validate::validate(&q).is_err());
    }
}

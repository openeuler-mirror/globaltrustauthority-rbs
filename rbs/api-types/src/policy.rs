//! Policy-related request / response types.
//!
//! These types define the HTTP contract for the policy CRUD API.

use serde::{Deserialize, Serialize};

// ── Validation constants ──

/// Maximum length of a policy ID (UUID v4: 36 chars).
pub const POLICY_ID_MAX_LEN: u64 = 36;

/// Maximum length of the comma-separated `ids` query parameter.
pub const POLICY_IDS_QUERY_MAX_LEN: u64 = 4096;

/// Maximum length of a policy name.
pub const POLICY_NAME_MAX_LEN: u64 = 255;

/// Characters forbidden in policy names.
pub const POLICY_NAME_BLACKLIST: &[char] = &['<', '>', '"', '\'', '&', '|', '\\', '/', '*', '?', '`'];

/// Allowed content types for policy content.
pub const POLICY_CONTENT_TYPE_WHITELIST: &[&str] = &["base64"];

// ── Request / response types ──

/// Policy create request body.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, validator::Validate)]
#[serde(rename_all = "snake_case")]
pub struct CreatePolicyRequest {
    #[validate(length(min = 1, max = POLICY_NAME_MAX_LEN), custom(function = "validate_policy_name"))]
    pub name: String,

    #[validate(custom(function = "validate_content_type"))]
    pub content_type: String,

    #[validate(length(min = 1))]
    pub content: String,
}

/// Policy update request body.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, validator::Validate)]
#[serde(rename_all = "snake_case")]
pub struct UpdatePolicyRequest {
    #[validate(length(min = 1, max = POLICY_NAME_MAX_LEN), custom(function = "validate_policy_name"))]
    pub name: String,

    #[validate(custom(function = "validate_content_type"))]
    pub content_type: String,

    #[validate(length(min = 1))]
    pub content: String,
}

/// Policy response returned to callers.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PolicyResponse {
    pub policy_id: String,
    pub policy_name: String,
    pub policy_version: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub policy_content: String,
    pub content_type: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_resources: Option<Vec<String>>,
}

/// Policy list response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PolicyListResponse {
    pub items: Vec<PolicyResponse>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for GET /rbs/v0/resource/policy.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::IntoParams, validator::Validate)]
#[serde(rename_all = "snake_case")]
pub struct PolicyListQuery {
    #[validate(length(min = 1, max = POLICY_IDS_QUERY_MAX_LEN))]
    pub ids: Option<String>,

    #[validate(range(min = 1, max = 100))]
    pub limit: Option<i64>,

    #[validate(range(min = 0, max = 100_000))]
    pub offset: Option<i64>,
}

/// Query parameters for DELETE /rbs/v0/resource/policy.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "snake_case")]
pub struct BatchDeleteQuery {
    pub ids: String,
}

// ── Custom validators ──

fn validate_policy_name(name: &str) -> Result<(), validator::ValidationError> {
    if let Some(c) = name.chars().find(|c| POLICY_NAME_BLACKLIST.contains(c)) {
        let mut err = validator::ValidationError::new("invalid_policy_name");
        err.message = Some(format!("policy name contains forbidden character: '{}'", c).into());
        return Err(err);
    }
    Ok(())
}

fn validate_content_type(content_type: &str) -> Result<(), validator::ValidationError> {
    if !POLICY_CONTENT_TYPE_WHITELIST.contains(&content_type) {
        let mut err = validator::ValidationError::new("invalid_content_type");
        err.message = Some(format!(
            "content_type must be one of: {}",
            POLICY_CONTENT_TYPE_WHITELIST.join(", ")
        ).into());
        return Err(err);
    }
    Ok(())
}

/// Validate a policy_id path parameter.
pub fn validate_policy_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > POLICY_ID_MAX_LEN as usize {
        Err(format!(
            "policy_id length must be 1..{}, got {}",
            POLICY_ID_MAX_LEN,
            id.len()
        ))
    } else {
        Ok(())
    }
}

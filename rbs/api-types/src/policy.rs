//! Policy-related request / response types.
//!
//! These types define the HTTP contract for the policy CRUD API.

use serde::{Deserialize, Serialize};

/// Policy create request body.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CreatePolicyRequest {
    pub name: String,
    pub content_type: String,
    pub content: String,
}

/// Policy update request body.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct UpdatePolicyRequest {
    pub name: String,
    pub content_type: String,
    pub content: String,
}

/// Policy response returned to callers.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PolicyResponse {
    pub policy_id: String,
    pub policy_name: String,
    pub policy_version: i32,
    pub policy_content: String,
    pub content_type: String,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_resources: Option<Vec<String>>,
}

/// Policy list response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PolicyListResponse {
    pub items: Vec<PolicyResponse>,
    pub total: u64,
}

/// Query parameters for GET /rbs/v0/resource/policy.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "snake_case")]
pub struct PolicyListQuery {
    pub ids: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Query parameters for DELETE /rbs/v0/resource/policy.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "snake_case")]
pub struct BatchDeleteQuery {
    pub ids: String,
}

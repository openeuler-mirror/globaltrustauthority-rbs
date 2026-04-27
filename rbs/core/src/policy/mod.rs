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

//! Policy management module.

use rbs_api_types::error::RbsError;
use serde::{Deserialize, Serialize};

use crate::auth::AuthContext;

/// Result type alias using RbsError.
type Result<T> = std::result::Result<T, RbsError>;

/// Policy response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub policy_content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_resources: Option<Vec<String>>,
}

/// Policy list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyListResponse {
    pub items: Vec<PolicyResponse>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Policy create request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyCreateRequest {
    pub name: String,
    pub policy_content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Policy update request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Policy manager.
pub struct PolicyManager {
    // TODO: Add storage backend
}

impl std::fmt::Debug for PolicyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyManager").finish()
    }
}

impl PolicyManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self {}
    }

    /// Create a new policy.
    pub async fn create(&self, _req: &PolicyCreateRequest, _auth_ctx: Option<AuthContext>) -> Result<PolicyResponse> {
        Err(RbsError::NotImplemented)
    }

    /// Get policy by id.
    pub async fn get(&self, _policy_id: &str, _auth_ctx: Option<AuthContext>) -> Result<Option<PolicyResponse>> {
        Err(RbsError::NotImplemented)
    }

    /// Update policy by id.
    pub async fn update(&self, _policy_id: &str, _req: &PolicyUpdateRequest, _auth_ctx: Option<AuthContext>) -> Result<Option<PolicyResponse>> {
        Err(RbsError::NotImplemented)
    }

    /// Delete policy by id.
    pub async fn delete(&self, _policy_id: &str, _auth_ctx: Option<AuthContext>) -> Result<()> {
        Err(RbsError::NotImplemented)
    }

    /// List policies with pagination.
    pub async fn list(&self, _ids: Option<&str>, _limit: i64, _offset: i64, _auth_ctx: Option<AuthContext>) -> Result<PolicyListResponse> {
        Err(RbsError::NotImplemented)
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

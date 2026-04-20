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

//! Resource-related types.
//!
//! Covers resource content, metadata, upsert requests, and retrieve.

use serde::{Deserialize, Serialize};

use super::auth::AttestRequest;

/// Resource content returned by GET and POST .../retrieve.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResourceContentResponse {
    /// Canonical resource URI for the returned object.
    pub uri: String,
    /// Resource bytes, Base64-encoded unless documented otherwise by the provider.
    pub content: String,
    /// Optional MIME type hint for decoding `content`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Request body for PUT /rbs/v0/{...}/{resource_name}.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResourceUpsertRequest {
    /// Resource payload (plain or Base64 per deployment convention;
    /// must match provider expectations).
    pub content: String,
    /// Optional MIME type for stored object metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

}

/// Read-only metadata for an existing resource (no secret material).
///
/// Returned by GET .../info. Field presence depends on provider and deployment;
/// clients must tolerate omitted keys.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResourceInfoResponse {
    /// Canonical URI of the resource.
    pub uri: String,
    /// Path segment echo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res_provider: Option<String>,
    /// Path segment echo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_name: Option<String>,
    /// Path segment echo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// Path segment echo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    /// Creation time (RFC 3339), if tracked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last modification time (RFC 3339), if tracked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// The single bound resource policy identifier for this resource, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// Stored MIME type hint for the payload (no body returned by this operation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Declared byte length of stored content, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<i64>,
}

/// Metadata returned after create/update.
///
/// Additional fields allowed per provider.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResourceMetadataResponse {
    /// Canonical URI of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Path segment `res_provider` echoed for convenience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res_provider: Option<String>,
    /// Path segment `repository_name` echoed for convenience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_name: Option<String>,
    /// Path segment `resource_type` echoed; one of key, secret, cert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// Path segment `resource_name` echoed for convenience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,

}

/// Same JSON object as POST /rbs/v0/attest; binds evidence to POST .../retrieve path resource.
///
/// This is a type alias for AttestRequest as the request shape is identical.
pub type ResourceRetrieveRequest = AttestRequest;

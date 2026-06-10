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
//! All request/response structs for the Resource module live here and
//! are shared between the REST handler, core service, and OpenAPI doc generation.

use serde::{Deserialize, Serialize};

use super::auth::AttestRequest;

// ── Token claim key name constants ──────────────────────────────────────────

/// Key name for TEE public key in AttestToken claims (nested under
/// `attester_data.runtime_data` or at root level).
pub const ATTEST_TEE_PUBKEY_KEY: &str = "tee-pubkey";

/// Key name for encryption public key in BearerToken claims (at root level).
pub const BEARER_ENC_PUBKEY_KEY: &str = "enc-pubkey";

// ── Create ──────────────────────────────────────────────────────────────────

/// Request body for `POST /rbs/v0/{uri}` — create a resource.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, validator::Validate)]
#[serde(rename_all = "snake_case")]
pub struct CreateResourceRequest {
    pub uri: String,

    #[validate(length(min = 1, max = 36))]
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<String>,
}

// ── Update ──────────────────────────────────────────────────────────────────

/// Request body for `PUT /rbs/v0/{uri}` — update or create a resource.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, validator::Validate)]
#[serde(rename_all = "snake_case")]
pub struct UpdateResourceRequest {
    #[validate(length(min = 1, max = 36))]
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<String>,
}

// ── Response (create / update) ──────────────────────────────────────────────

/// Resource metadata returned after create or update.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResourceResponse {
    pub uri: String,
    pub provider_name: String,
    pub repository_name: String,
    pub resource_type: String,
    pub resource_name: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub export_mode: String,
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<String>,
}

// ── Content ─────────────────────────────────────────────────────────────────

/// Resource content returned by GET and POST .../retrieve.
///
/// `content` is always base64-encoded JWE ciphertext (Compact Serialization).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResourceContentResponse {
    /// Canonical resource URI for the returned object.
    pub uri: String,
    /// Base64-encoded JWE ciphertext.
    pub content: String,
    /// Original MIME type hint for decoding after JWE decryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Export mode (currently always "jwe").
    pub export_mode: String,
}

// ── Info (metadata) ─────────────────────────────────────────────────────────

/// Resource metadata returned by GET .../info (no secret material).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResourceInfoResponse {
    pub uri: String,
    pub user_id: String,
    pub policy_id: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub export_mode: String,
}

// ── Retrieve ────────────────────────────────────────────────────────────────

/// Same shape as AttestRequest; binds evidence to the POST .../retrieve path.
pub type ResourceRetrieveRequest = AttestRequest;
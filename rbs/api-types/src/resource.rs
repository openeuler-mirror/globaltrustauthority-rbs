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
    /// UUID of the caller-owned policy that governs reads of this resource.
    #[validate(length(min = 1, max = 36, message = "length must be between 1 and 36 characters"))]
    #[schema(min_length = 1, max_length = 36)]
    pub policy_id: String,
    /// Content type label; one of `jwt`, `json`, `text`, `binary`, `jwk`, `jwe` (fixed whitelist).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Export mode on read; only `jwe` is accepted (plaintext export is rejected); defaults to `jwe`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_mode: Option<String>,
    /// Free-form description of the resource; when present, 1-512 chars (empty string rejected).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<String>,
    /// Base64-encoded content, stored via the backend when it supports PUT. Optional for backends that generate the object themselves (e.g. CA) or require it to pre-exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

// ── Update ──────────────────────────────────────────────────────────────────

/// Request body for `PUT /rbs/v0/{uri}` — update or create a resource.
///
/// `policy_id` is optional on update: an explicit value rebinds the resource to
/// a new policy (validated as usual); omitting it keeps the existing resource's
/// binding. A brand-new resource created via the upsert path still requires an
/// explicit `policy_id`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, validator::Validate)]
#[serde(rename_all = "snake_case")]
pub struct UpdateResourceRequest {
    /// New policy binding (must be caller-owned); omitted keeps the current binding. Required when the upsert creates a new resource.
    #[validate(length(min = 1, max = 36, message = "length must be between 1 and 36 characters"))]
    #[schema(min_length = 1, max_length = 36)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// New content type label (`jwt`, `json`, `text`, `binary`, `jwk`, `jwe`); omitted keeps the current value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// New export mode; only `jwe` is accepted; omitted keeps the current value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_mode: Option<String>,
    /// New description (when present, 1-512 chars); omitted keeps the current value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<String>,
    /// Base64-encoded replacement content; omitted leaves the backend content unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

// ── Response (create / update) ──────────────────────────────────────────────

/// Resource metadata returned after create or update.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResourceResponse {
    /// Canonical resource URI: `/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`.
    pub uri: String,
    /// Backend provider name (first URI segment).
    pub provider_name: String,
    /// Backend repository name (second URI segment).
    pub repository_name: String,
    /// Resource type (third URI segment), e.g. `secret`, `cert`, `key`.
    pub resource_type: String,
    /// Resource name (fourth URI segment).
    pub resource_name: String,
    /// Creation time (RFC 3339).
    pub created_at: String,
    /// Last update time (RFC 3339).
    pub updated_at: String,
    /// Content type label (`jwt`, `json`, `text`, `binary`, `jwk`, `jwe`), if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Export mode of the resource; always `jwe`.
    pub export_mode: String,
    /// UUID of the policy bound to this resource.
    pub policy_id: String,
    /// Free-form description (1-512 chars), if set.
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
    /// Content type label (`jwt`, `json`, `text`, `binary`, `jwk`, `jwe`) for decoding the decrypted content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Export mode; always `jwe`.
    pub export_mode: String,
}

// ── Info (metadata) ─────────────────────────────────────────────────────────

/// Resource metadata returned by GET .../info (no secret material).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResourceInfoResponse {
    /// Canonical resource URI.
    pub uri: String,
    /// Username of the resource owner.
    pub user_id: String,
    /// UUID of the policy bound to this resource.
    pub policy_id: String,
    /// Creation time (RFC 3339).
    pub created_at: String,
    /// Last update time (RFC 3339).
    pub updated_at: String,
    /// Content type label (`jwt`, `json`, `text`, `binary`, `jwk`, `jwe`), if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Export mode of the resource; always `jwe`.
    pub export_mode: String,
}

// ── Retrieve ────────────────────────────────────────────────────────────────

/// Same shape as AttestRequest; binds evidence to the POST .../retrieve path.
pub type ResourceRetrieveRequest = AttestRequest;

// ── Backend addressing & transfer types ────────────────────────────────────

/// Addressing descriptor for a resource in a backend.
/// Derived from the URI path segments by the Service layer.
#[derive(Debug, Clone)]
pub struct ResourceDesc {
    pub repository_name: String,
    pub resource_type: String,
    pub resource_name: String,
}

/// Options passed to `get_resource_content`.
/// `csr_der` carries a PKCS#10 CSR (DER bytes, zeroized on drop) for CA backends.
/// Vault/HSM backends ignore it.
#[derive(Debug, Clone)]
pub struct GetResourceOptions {
    pub csr_der: Option<zeroize::Zeroizing<Vec<u8>>>,
}
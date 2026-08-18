/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Attestation management API types.
//!
//! Request/response/query types for ref_value management CRUD operations.
//! RBS acts as a stateless proxy and does not pre-validate GTA-supported
//! fields; all response fields are optional to tolerate GTA's by_type/all
//! summary vs by_ids full response shapes.
//!
//! Shared types (`AttestationDeleteRequest`, `AttestationDeleteType`,
//! `AttestationMutationResponse`) are reused by cert (AR-002) and policy
//! (AR-003) management operations.

use serde::{Deserialize, Serialize};
use std::fmt::Display;
use tabled::Tabled;
use validator::Validate;

fn display_option<T: Display>(value: &Option<T>) -> String {
    value.as_ref().map(ToString::to_string).unwrap_or_else(|| "-".to_string())
}

fn display_cert_type(value: &Option<Vec<String>>) -> String {
    value.as_ref().map(|types| types.join(",")).unwrap_or_else(|| "-".to_string())
}

fn display_string_list(value: &Vec<String>) -> String {
    value.join(",")
}

fn display_optional_content(value: &Option<String>) -> String {
    value.as_deref().unwrap_or("-").replace('\n', "\\n")
}

/// Reference value (baseline) entity returned by GTA.
///
/// RBS acts as a stateless proxy. `id`/`name`/`attester_type` are always
/// present in both GTA by_type/all (summary) and by_ids (full) responses,
/// so they are mandatory. `uid`/`description`/`content`/`content_type`/
/// `version`/`valid_code` appear only in the by_ids full response and are
/// optional.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Tabled)]
#[serde(rename_all = "snake_case")]
pub struct RefValue {
    /// Stable ref_value identifier.
    #[schema(example = "rv-001")]
    pub id: String,
    /// User-scoped identifier (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    #[schema(example = "test_01")]
    pub uid: Option<String>,
    /// Human-readable baseline name.
    #[schema(example = "tpm-baseline")]
    pub name: String,
    /// Attester type (e.g. tpm, tpm_ima, virt_cca).
    #[schema(example = "tpm")]
    pub attester_type: String,
    /// Optional description (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    #[schema(example = "TPM reference baseline")]
    pub description: Option<String>,
    /// Baseline content (JWT or base64-encoded payload) (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    #[schema(example = "eyJhbGciOiJSUzI1NiJ9...")]
    pub content: Option<String>,
    /// Content encoding: "jwt" (default) or "base64" (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    #[schema(example = "jwt")]
    pub content_type: Option<String>,
    /// Baseline version (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    #[schema(example = 1)]
    pub version: Option<i32>,
    /// Validity code: 0 = valid, 1 = invalid (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    #[schema(example = 0)]
    pub valid_code: Option<i32>,
}

/// Query parameters for GET ref_value list.
///
/// When `ids` is present, pagination parameters are ignored (by_ids path).
/// When `ids` is absent, `attester_type` and pagination apply (by_type/all path).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::IntoParams, Validate)]
#[serde(rename_all = "snake_case")]
pub struct RefValueListQuery {
    /// Comma-separated ref_value IDs (1-10); when present, pagination is ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<String>,
    /// Filter by attester_type (e.g. tpm, tpm_ima).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
    /// Page size (1-10, default 10). Ignored when `ids` is present.
    #[validate(range(min = 1, max = 10))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Page offset (0-100000, default 0). Ignored when `ids` is present.
    #[validate(range(min = 0, max = 100_000))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
}

/// Paginated response for GET ref_value list.
///
/// `total_count`, `limit`, and `offset` are optional: present in by_type/all
/// paths, absent in by_ids paths.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RefValueListResponse {
    /// List of ref_values matching the query.
    pub ref_values: Vec<RefValue>,
    /// Total matching count (present in by_type/all paths; absent in by_ids path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<i64>,
    /// Effective page size returned by GTA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Effective page offset returned by GTA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
}

/// Request body for POST ref_value (create).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RefValueCreateRequest {
    /// Baseline name (non-empty).
    #[validate(length(min = 1))]
    #[schema(example = "tpm-baseline")]
    pub name: String,
    /// Attester type (non-empty).
    #[validate(length(min = 1))]
    #[schema(example = "tpm")]
    pub attester_type: String,
    /// Baseline content — JWT or base64-encoded payload (non-empty).
    #[validate(length(min = 1))]
    #[schema(example = "eyJhbGciOiJSUzI1NiJ9...")]
    pub content: String,
    /// Content encoding: "jwt" (default) or "base64". When absent, GTA defaults to jwt.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "jwt")]
    pub content_type: Option<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "TPM reference baseline")]
    pub description: Option<String>,
}

/// Request body for PUT ref_value (update).
///
/// `id` is required (collection-level operation, id in body not path).
/// All other fields are optional; at least one should be provided.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RefValueUpdateRequest {
    /// ID of the ref_value to update.
    #[schema(example = "rv-001")]
    pub id: String,
    /// New name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "updated-baseline")]
    pub name: Option<String>,
    /// New description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// New attester_type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "tpm")]
    pub attester_type: Option<String>,
    /// New content.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "eyJhbGciOiJSUzI1NiJ9...")]
    pub content: Option<String>,
    /// New content encoding.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "base64")]
    pub content_type: Option<String>,
}

/// Delete mode for ref_value/cert DELETE operations.
///
/// GTA accepts `"id"`, `"all"`, `"type"` for ref_value and cert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttestationDeleteType {
    /// Delete by ID list.
    Id,
    /// Delete all.
    All,
    /// Delete by attester_type (ref_value) or cert_type (cert).
    Type,
}

/// Delete mode for policy DELETE operations.
///
/// GTA accepts `"id"`, `"all"`, `"attester_type"` for policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDeleteType {
    /// Delete by ID list.
    Id,
    /// Delete all.
    All,
    /// Delete by attester_type.
    AttesterType,
}

/// Request body for DELETE ref_value (batch delete).
///
/// GTA accepts `delete_type` = `"id"`/`"all"`/`"type"`, with
/// `attester_type` as the type filter.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RefValueDeleteRequest {
    /// Delete mode.
    pub delete_type: AttestationDeleteType,
    /// IDs to delete (required when `delete_type` is `Id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    /// Attester type filter (required when `delete_type` is `Type`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "tpm")]
    pub attester_type: Option<String>,
}

/// Request body for DELETE cert (batch delete).
///
/// GTA accepts `delete_type` = `"id"`/`"all"`/`"type"`, with
/// `cert_type` (JSON field name `type`) as the type filter.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CertDeleteRequest {
    /// Delete mode.
    pub delete_type: AttestationDeleteType,
    /// IDs to delete (required when `delete_type` is `Id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    /// Cert type filter (required when `delete_type` is `Type`; JSON field name `type`).
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    #[schema(example = "refvalue")]
    pub cert_type: Option<String>,
}

/// Request body for DELETE policy (batch delete).
///
/// GTA accepts `delete_type` = `"id"`/`"all"`/`"attester_type"`, with
/// `attester_type` as the type filter.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PolicyDeleteRequest {
    /// Delete mode.
    pub delete_type: PolicyDeleteType,
    /// IDs to delete (required when `delete_type` is `Id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    /// Attester type filter (required when `delete_type` is `AttesterType`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "tpm")]
    pub attester_type: Option<String>,
}

/// Response for POST/PUT ref_value (create/update).
///
/// Mirrors GTA's `{"ref_value": {"id":"...", "name":"...", "version": 1}}`.
/// RBS is a stateless proxy — deserialized and passed through unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RefValueMutationResponse {
    /// Mutation result.
    pub ref_value: RefValueMutation,
}

/// Inner mutation result for ref_value create/update.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RefValueMutation {
    /// ID of the mutated ref_value.
    #[schema(example = "rv-001")]
    pub id: String,
    /// Name of the mutated ref_value.
    #[schema(example = "tpm-baseline")]
    pub name: String,
    /// New version after mutation.
    #[schema(example = 2)]
    pub version: i32,
}

/// Response for POST/PUT policy (create/update).
///
/// Mirrors GTA's `{"policy": {"id":"...", "name":"...", "version": 1}}`.
/// RBS is a stateless proxy — deserialized and passed through unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PolicyMutationResponse {
    /// Mutation result.
    pub policy: PolicyMutation,
}

/// Inner mutation result for policy create/update.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PolicyMutation {
    /// ID of the mutated policy.
    #[schema(example = "P1")]
    pub id: String,
    /// Name of the mutated policy.
    #[schema(example = "policy1")]
    pub name: String,
    /// New version after mutation.
    #[schema(example = 2)]
    pub version: i32,
}

// ---------------------------------------------------------------------------
// Certificate types (AR-002)
// ---------------------------------------------------------------------------

/// Certificate record returned by GTA.
///
/// All fields are optional: GTA's `CertRespInfo` serializes every field
/// with `skip_serializing_if = "Option::is_none"`, so the present subset
/// depends on the query path and the underlying database row.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Tabled)]
#[serde(rename_all = "snake_case")]
pub struct CertRecord {
    /// Stable certificate identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    #[schema(example = "C1")]
    pub cert_id: Option<String>,
    /// Certificate name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    #[schema(example = "cert1")]
    pub cert_name: Option<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    pub description: Option<String>,
    /// Certificate content (PEM etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_optional_content")]
    pub content: Option<String>,
    /// Certificate type list.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_cert_type")]
    pub cert_type: Option<Vec<String>>,
    /// Whether this is the default certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    pub is_default: Option<bool>,
    /// Certificate version.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    #[schema(example = 1)]
    pub version: Option<i32>,
    /// Creation timestamp as Unix epoch seconds or milliseconds, depending on the GTA response.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    #[schema(example = 1700000000000_i64)]
    pub create_time: Option<i64>,
    /// Last update timestamp as Unix epoch seconds or milliseconds, depending on the GTA response.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    #[schema(example = 1700000000000_i64)]
    pub update_time: Option<i64>,
    /// Validity code.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    #[schema(example = 0)]
    pub valid_code: Option<i32>,
    /// Revocation date (Unix epoch seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    #[schema(example = 1700000000)]
    pub cert_revoked_date: Option<i64>,
    /// Revocation reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    pub cert_revoked_reason: Option<String>,
}

/// CRL (Certificate Revocation List) record returned by GTA.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Tabled)]
#[serde(rename_all = "snake_case")]
pub struct CrlRecord {
    /// Stable CRL identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    #[schema(example = "L1")]
    pub crl_id: Option<String>,
    /// CRL name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_option")]
    #[schema(example = "crl1")]
    pub crl_name: Option<String>,
    /// CRL content.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(display_with = "display_optional_content")]
    pub crl_content: Option<String>,
}

/// Query parameters for GET cert list.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::IntoParams, Validate)]
#[serde(rename_all = "snake_case")]
pub struct CertListQuery {
    /// Comma-separated certificate IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<String>,
    /// Filter by certificate type (query param `cert_type`, JSON field `type`).
    #[serde(skip_serializing_if = "Option::is_none", rename = "cert_type")]
    pub cert_type: Option<String>,
    /// Page size (1-10, default 10).
    #[validate(range(min = 1, max = 10))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Page offset (0-100000, default 0).
    #[validate(range(min = 0, max = 100_000))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
}

/// Paginated response for GET cert list.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CertListResponse {
    /// List of certificates matching the query.
    #[serde(default)]
    pub certs: Vec<CertRecord>,
    /// List of CRL records matching the query.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crls: Vec<CrlRecord>,
    /// Total matching count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<i64>,
    /// Effective page size returned by GTA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Effective page offset returned by GTA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
}

/// Request body for POST cert (create).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CertCreateRequest {
    /// Certificate name (non-empty).
    #[validate(length(min = 1))]
    #[schema(example = "cert1")]
    pub name: String,
    /// Certificate type list (JSON field name `type`).
    #[serde(rename = "type")]
    #[schema(example = "[\"tpm\"]")]
    pub cert_type: Vec<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Certificate content; required when `cert_type` does not contain `crl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// CRL content; required when `cert_type` contains `crl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_content: Option<String>,
    /// Whether to set as default certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

/// Request body for PUT cert (update).
///
/// `id` is required (collection-level operation, id in body not path).
/// GTA rejects `content` on update — the field is passed through so GTA
/// can return the appropriate error.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CertUpdateRequest {
    /// ID of the certificate to update.
    #[schema(example = "C1")]
    pub id: String,
    /// New name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// New description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// New certificate type list (JSON field name `type`). Must not contain `crl`.
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub cert_type: Option<Vec<String>>,
    /// Certificate content — GTA rejects this on update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Whether to set as default certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

/// Inner mutation result for cert create/update.
///
/// GTA returns `{"cert": {"cert_id":"...", "cert_name":"...", "version": 1}}`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CertMutationResult {
    /// Certificate ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "C1")]
    pub cert_id: Option<String>,
    /// Certificate name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "cert1")]
    pub cert_name: Option<String>,
    /// New version after mutation.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 2)]
    pub version: Option<i32>,
}

/// Inner mutation result for CRL create.
///
/// GTA returns `{"crl": {"crl_id":"...", "crl_name":"..."}}`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CrlMutationResult {
    /// CRL ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "L1")]
    pub crl_id: Option<String>,
    /// CRL name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "crl1")]
    pub crl_name: Option<String>,
}

/// Response for POST/PUT cert (create/update mutation).
///
/// GTA wraps the result in a `cert` or `crl` key; only one is present.
/// RBS is a stateless proxy and passes the wrapper through unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CertMutationResponse {
    /// Present when a cert was created/updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertMutationResult>,
    /// Present when a CRL was created/updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl: Option<CrlMutationResult>,
}

// ---------------------------------------------------------------------------
// Attestation policy types (AR-003)
// ---------------------------------------------------------------------------

/// Attestation policy entity returned by GTA.
///
/// Named `AttestationPolicy` to distinguish from RBS local resource policy
/// (`Policy`/`PolicyResponse` in `t_res_policy`). `id`/`name`/`attester_type`
/// are always present in both GTA by_type/all (summary) and by_ids (full)
/// responses, so they are mandatory. Other fields appear only in by_ids.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, Tabled)]
#[serde(rename_all = "snake_case")]
pub struct AttestationPolicy {
    /// Stable policy identifier.
    #[schema(example = "P1")]
    pub id: String,
    /// Policy name.
    #[schema(example = "policy1")]
    pub name: String,
    /// Optional description (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    pub description: Option<String>,
    /// Policy content (JWT or text) (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    pub content: Option<String>,
    /// Attester type list (array, unlike ref_value's scalar attester_type).
    #[schema(example = "[\"tpm\",\"sgx\"]")]
    #[tabled(display_with = "display_string_list")]
    pub attester_type: Vec<String>,
    /// Whether this is the default policy (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    pub is_default: Option<bool>,
    /// Policy version (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    #[schema(example = 1)]
    pub version: Option<i32>,
    /// Last update timestamp as Unix epoch seconds or milliseconds, depending on the GTA response.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    #[schema(example = 1700000000000_i64)]
    pub update_time: Option<i64>,
    /// Validity code: 0 = valid, 1 = invalid (by_ids path only).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tabled(skip)]
    #[schema(example = 0)]
    pub valid_code: Option<i32>,
}

/// Query parameters for GET attestation policy list.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::IntoParams, Validate)]
#[serde(rename_all = "snake_case")]
pub struct PolicyListQuery {
    /// Comma-separated policy IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<String>,
    /// Filter by attester_type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
    /// Page size (1-10, default 10).
    #[validate(range(min = 1, max = 10))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Page offset (0-100000, default 0).
    #[validate(range(min = 0, max = 100_000))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
}

/// Paginated response for GET attestation policy list.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AttestationPolicyListResponse {
    /// List of policies matching the query.
    pub policies: Vec<AttestationPolicy>,
    /// Total matching count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<i64>,
    /// Effective page size returned by GTA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Effective page offset returned by GTA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
}

/// Request body for POST attestation policy (create).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PolicyCreateRequest {
    /// Policy name (non-empty).
    #[validate(length(min = 1))]
    #[schema(example = "policy1")]
    pub name: String,
    /// Attester type list (non-empty array).
    #[validate(length(min = 1))]
    #[schema(example = "[\"tpm\"]")]
    pub attester_type: Vec<String>,
    /// Content encoding (required): "jwt" or "text".
    #[validate(length(min = 1))]
    #[schema(example = "jwt")]
    pub content_type: String,
    /// Policy content (non-empty).
    #[validate(length(min = 1))]
    #[schema(example = "eyJhbGciOiJSUzI1NiJ9...")]
    pub content: String,
    /// Whether to set as default policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Request body for PUT attestation policy (update).
///
/// `id` is required (collection-level operation, id in body not path).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct PolicyUpdateRequest {
    /// ID of the policy to update.
    #[schema(example = "P1")]
    pub id: String,
    /// New name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// New description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// New attester type list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<Vec<String>>,
    /// New content encoding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// New policy content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Whether to set as default policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

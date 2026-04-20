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

//! Attestation-related types.
//!
//! Covers challenge/response, evidence submission, and token issuance.

use serde::{Deserialize, Serialize};
use serde_json::Map;

/// Optional attester-supplied metadata.
///
/// Same structure for top-level `attester_data` on AttestRequest
/// and for `measurements[].attester_data`. If a measurement defines `attester_data`,
/// it wins for that measurement; otherwise the top-level `attester_data` applies.
///
/// `runtime_data` must not duplicate the challenge nonce (nonce lives only under
/// `rbc_evidences.measurements[].nonce`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AttesterData {
    /// Key/value runtime fields (e.g. attester_pubkey as JWK for encrypted resource return);
    /// excludes nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_data: Option<Map<String, serde_json::Value>>,

}

/// Single attestation artifact within a measurement (backend-specific detail).
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RbcEvidenceItem {
    /// Plugin or attester kind (e.g. tpm_boot).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
    /// Evidence payload (string or object per attestation backend).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
    /// Policy identifiers evaluated for this evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,

}

/// One node or attestation unit inside the evidence bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RbcMeasurement {
    /// Must equal the `nonce` field from GET /rbs/v0/auth (same string, no transformation).
    pub nonce: String,
    /// Optional node or workload identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Optional hint for nonce interpretation (backend-specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_type: Option<String>,
    /// Optional desired token format hint (backend-specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_fmt: Option<String>,
    /// Attester-supplied metadata for this measurement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<AttesterData>,
    /// Collected attestation artifacts for this measurement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidences: Option<Vec<RbcEvidenceItem>>,

}

/// Evidence JSON produced by RBC (`collect_evidence`) or equivalent.
///
/// Typical GTA-oriented shape includes a non-empty `measurements` array;
/// deployments may add other keys or per-backend wrappers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RbcEvidencesPayload {
    /// Optional agent or collector version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// At least one entry required for standard attest flows; each entry carries nonce and evidences.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub measurements: Vec<RbcMeasurement>,

}

/// Request body for POST /rbs/v0/attest.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AttestRequest {
    /// Optional attestation backend id (e.g. gta); default is deployment-specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_provider: Option<String>,
    /// Evidence bundle from RBC.
    #[serde(default)]
    pub rbc_evidences: RbcEvidencesPayload,
    /// Top-level attester metadata; used if measurement-level attester_data is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<AttesterData>,
}

/// Response for POST /rbs/v0/attest.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AttestResponse {
    /// AttestToken or session JWT for subsequent Bearer resource access.
    pub token: String,
}

/// Response for GET /rbs/v0/challenge (attestation challenge).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AuthChallengeResponse {
    /// Challenge value for binding attestation (opaque; often Base64).
    /// Use the field value as-is in `rbc_evidences.measurements[].nonce`
    /// for POST /rbs/v0/attest and POST .../retrieve.
    pub nonce: String,
}

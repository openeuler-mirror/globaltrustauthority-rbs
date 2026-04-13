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

//! HTTP JSON types for attestation and resource retrieval (aligned with `docs/api/rbs_api.yaml`).

use serde::{Deserialize, Serialize};

/// `GET /rbs/v0/challenge` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallengeResponse {
    pub nonce: String,
}

/// Optional attester metadata (`AttesterData` in OpenAPI).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttesterData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_data: Option<serde_json::Map<String, serde_json::Value>>,
}

/// One evidence artifact inside a measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbcEvidenceItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
    /// Evidence payload (string or object per backend).
    pub evidence: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,
}

/// One measurement node in `rbc_evidences`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbcMeasurement {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_fmt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<AttesterData>,
    #[serde(default)]
    pub evidences: Vec<RbcEvidenceItem>,
}

/// Evidence bundle (`RbcEvidencesPayload` in OpenAPI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbcEvidencesPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurements: Option<Vec<RbcMeasurement>>,
}

/// `POST /rbs/v0/attest` and evidence body for `POST .../retrieve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_provider: Option<String>,
    pub rbc_evidences: RbcEvidencesPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_data: Option<AttesterData>,
}

/// `POST /rbs/v0/attest` success body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestResponse {
    pub token: String,
}

/// `POST .../retrieve` and `GET ...` resource success body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceContentResponse {
    pub uri: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Same JSON object as [`AttestRequest`] (OpenAPI `ResourceRetrieveRequest`).
pub type ResourceRetrieveRequest = AttestRequest;

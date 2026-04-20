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

//! Native evidence provider: collects evidence locally via the attestation_client crate.

use async_trait::async_trait;
use attestation_client::{AttestationClient, GetEvidenceRequest};
use rbs_api_types::{AttesterData, AuthChallengeResponse};
use serde::Deserialize;
use serde_json::Value;

use crate::error::RbcError;
use crate::evidence::EvidenceProvider;

const DEFAULT_AGENT_CONFIG: &str = "/etc/attestation_agent/agent_config.yaml";

/// Configuration for the native evidence provider.
/// Deserialized from the `evidence_provider` block in `rbc.yaml` (excluding the `type` field).
#[derive(Debug, Deserialize)]
pub struct NativeEvidenceProviderConfig {
    pub config_path: Option<String>,
}

/// Collects attestation evidence locally by invoking attester plugins via `attestation_client`.
pub struct NativeEvidenceProvider {
    client: AttestationClient,
}

impl NativeEvidenceProvider {
    /// Create a new provider from raw provider config (all fields except `type`).
    pub fn new(cfg: serde_json::Value) -> Result<Self, RbcError> {
        let config: NativeEvidenceProviderConfig = serde_json::from_value(cfg)
            .map_err(|e| RbcError::ConfigError(format!("NativeEvidenceProvider config: {e}")))?;
        let path = config.config_path.as_deref().unwrap_or(DEFAULT_AGENT_CONFIG);
        let client = AttestationClient::new(path)
            .map_err(|e| RbcError::ProviderError(format!("attestation_client init failed: {e}")))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl EvidenceProvider for NativeEvidenceProvider {
    /// Collect local evidence bound to the RBS-issued nonce.
    async fn collect_evidence(
        &self,
        challenge: &AuthChallengeResponse,
        attester_data: Option<&AttesterData>,
    ) -> Result<Value, RbcError> {
        let attester_data_val = attester_data
            .map(|d| serde_json::to_value(d))
            .transpose()
            .map_err(|e| RbcError::EvidenceError(format!("serialize attester_data failed: {e}")))?;

        let req = GetEvidenceRequest {
            attesters: vec![],
            nonce_type: Some("verifier".to_string()),
            nonce: Some(challenge.nonce.clone()),
            token_fmt: None,
            attester_data: attester_data_val,
        };

        let response = self
            .client
            .collect_evidence(req)
            .map_err(|e| RbcError::EvidenceError(e.to_string()))?;

        serde_json::to_value(&response)
            .map_err(|e| RbcError::EvidenceError(format!("serialize evidence response failed: {e}")))
    }
}

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

        let response = self.client.collect_evidence(req).map_err(|e| RbcError::EvidenceError(e.to_string()))?;

        serde_json::to_value(&response)
            .map_err(|e| RbcError::EvidenceError(format!("serialize evidence response failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_rejects_malformed_provider_config() {
        let err = NativeEvidenceProvider::new(json!({"config_path": 42})).err().expect("config_path must be a string");
        assert!(matches!(err, RbcError::ConfigError(_)), "expected ConfigError, got {err:?}");
        assert!(err.to_string().contains("NativeEvidenceProvider config"), "unexpected message: {err}");
    }

    #[test]
    fn new_maps_agent_config_init_failure_to_provider_error() {
        // The attestation agent config does not exist, so `AttestationClient::new` fails and the
        // error must surface as a provider error rather than a panic.
        let err = NativeEvidenceProvider::new(json!({"config_path": "/nonexistent/rbc-agent-config.yaml"}))
            .err().expect("missing agent config must fail");
        assert!(matches!(err, RbcError::ProviderError(_)), "expected ProviderError, got {err:?}");
        assert!(err.to_string().contains("attestation_client init failed"), "unexpected message: {err}");
    }

    #[test]
    fn collect_evidence_rejects_invalid_nonce() {
        // `AttestationClient` is a fieldless handle, so the provider can be built without a
        // usable agent configuration to exercise the nonce validation error mapping.
        let provider = NativeEvidenceProvider { client: AttestationClient };
        let challenge = AuthChallengeResponse { nonce: "not base64 !!".to_string() };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");

        let err = rt.block_on(provider.collect_evidence(&challenge, None)).err().expect("invalid nonce must fail");
        assert!(matches!(err, RbcError::EvidenceError(_)), "expected EvidenceError, got {err:?}");
    }

    #[test]
    fn collect_evidence_serializes_attester_data() {
        let provider = NativeEvidenceProvider { client: AttestationClient };
        let challenge = AuthChallengeResponse { nonce: "not base64 !!".to_string() };
        let attester_data = AttesterData { runtime_data: Some(serde_json::Map::new()) };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");

        // Supplying attester data drives the serialization branch before the nonce check fails.
        let err = rt
            .block_on(provider.collect_evidence(&challenge, Some(&attester_data)))
            .err()
            .expect("invalid nonce must fail");
        assert!(matches!(err, RbcError::EvidenceError(_)), "expected EvidenceError, got {err:?}");
    }

    #[test]
    fn collect_evidence_with_valid_nonce_reports_missing_plugins() {
        let provider = NativeEvidenceProvider { client: AttestationClient };
        let challenge = AuthChallengeResponse { nonce: "YWJjZA==".to_string() };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");

        // No attester plugins are installed, so evidence collection fails and is mapped to
        // `EvidenceError` instead of propagating the underlying client error.
        let err = rt.block_on(provider.collect_evidence(&challenge, None)).err().expect("plugin manager unset");
        assert!(matches!(err, RbcError::EvidenceError(_)), "expected EvidenceError, got {err:?}");
    }
}

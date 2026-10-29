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

//! Native token provider: performs a full attestation flow locally via the attestation_client crate (UC-02).

use async_trait::async_trait;
use attestation_client::{AttestationClient, TokenRequest};
use rbs_api_types::AttesterData;
use serde::Deserialize;
use serde_json::Value;

use crate::error::RbcError;
use crate::token::TokenProvider;

const DEFAULT_AGENT_CONFIG: &str = "/etc/attestation_agent/agent_config.yaml";

/// Configuration for the native token provider.
/// Deserialized from the `token_provider` block in `rbc.yaml` (excluding the `type` field).
#[derive(Debug, Deserialize)]
pub struct NativeTokenProviderConfig {
    pub config_path: Option<String>,
}

/// Obtains a token by running the full GTA attestation flow locally (challenge → evidence → token).
pub struct NativeTokenProvider {
    client: AttestationClient,
}

impl NativeTokenProvider {
    /// Create a new provider from raw provider config (all fields except `type`).
    pub fn new(cfg: serde_json::Value) -> Result<Self, RbcError> {
        let config: NativeTokenProviderConfig = serde_json::from_value(cfg)
            .map_err(|e| RbcError::ConfigError(format!("NativeTokenProvider config: {e}")))?;
        let path = config.config_path.as_deref().unwrap_or(DEFAULT_AGENT_CONFIG);
        let client = AttestationClient::new(path)
            .map_err(|e| RbcError::ProviderError(format!("attestation_client init failed: {e}")))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl TokenProvider for NativeTokenProvider {
    /// Run the full GTA attestation flow and return the token JSON string.
    ///
    /// `evidence` is unused — `attestation_client` collects evidence internally.
    async fn get_token(
        &self,
        _evidence: Option<&Value>,
        attester_data: Option<&AttesterData>,
    ) -> Result<String, RbcError> {
        let attester_data_val = attester_data
            .map(|d| serde_json::to_value(d))
            .transpose()
            .map_err(|e| RbcError::ProviderError(format!("serialize attester_data failed: {e}")))?;

        let req = TokenRequest {
            attester_info: None,
            challenge: Some(true),
            attester_data: attester_data_val,
            token_fmt: None,
        };

        self.client.get_token(req).await.map_err(|e| RbcError::ProviderError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_rejects_malformed_provider_config() {
        let err = NativeTokenProvider::new(json!({"config_path": 42})).err().expect("config_path must be a string");
        assert!(matches!(err, RbcError::ConfigError(_)), "expected ConfigError, got {err:?}");
        assert!(err.to_string().contains("NativeTokenProvider config"), "unexpected message: {err}");
    }

    #[test]
    fn new_maps_agent_config_init_failure_to_provider_error() {
        let err = NativeTokenProvider::new(json!({"config_path": "/nonexistent/rbc-agent-config.yaml"}))
            .err().expect("missing agent config must fail");
        assert!(matches!(err, RbcError::ProviderError(_)), "expected ProviderError, got {err:?}");
        assert!(err.to_string().contains("attestation_client init failed"), "unexpected message: {err}");
    }

    #[test]
    fn new_reports_unparsable_agent_config_as_provider_error() {
        // `rbc/tests/data/agent_config.yaml` is a partial agent config: it is found on disk but
        // cannot be parsed, which must be reported as a provider initialization error.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/agent_config.yaml");
        let err = NativeTokenProvider::new(json!({"config_path": path})).err().expect("partial config must fail");
        assert!(matches!(err, RbcError::ProviderError(_)), "expected ProviderError, got {err:?}");
    }

    #[test]
    fn get_token_serializes_attester_data() {
        let provider = NativeTokenProvider { client: AttestationClient };
        let attester_data = AttesterData { runtime_data: Some(serde_json::Map::new()) };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");

        let err = rt.block_on(provider.get_token(None, Some(&attester_data))).err().expect("attestation flow must fail");
        assert!(matches!(err, RbcError::ProviderError(_)), "expected ProviderError, got {err:?}");
    }

    #[test]
    fn get_token_maps_client_failure_to_provider_error() {
        // `AttestationClient` is a fieldless handle; the attestation flow then fails on the
        // unconfigured agent client and must be reported as a provider error.
        let provider = NativeTokenProvider { client: AttestationClient };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");

        let err = rt.block_on(provider.get_token(None, None)).err().expect("attestation flow must fail");
        assert!(matches!(err, RbcError::ProviderError(_)), "expected ProviderError, got {err:?}");
    }
}

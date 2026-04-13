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

use attestation_client::{AttestationClient, TokenRequest};
use rbs_api_types::api::AttesterData;
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

impl TokenProvider for NativeTokenProvider {
    /// Run the full GTA attestation flow and return the token JSON string.
    ///
    /// `evidence` is unused — `attestation_client` collects evidence internally.
    fn get_token(
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

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| RbcError::ProviderError("no tokio runtime available".into()))?;

        std::thread::scope(|_| {
            tokio::task::block_in_place(|| {
                rt.block_on(self.client.get_token(req))
                    .map_err(|e| RbcError::ProviderError(e.to_string()))
            })
        })
    }
}

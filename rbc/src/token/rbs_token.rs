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

//! Token provider that submits evidence to the RBS `/attest` endpoint (UC-01).

use std::collections::HashMap;
use async_trait::async_trait;
use rbs_api_types::{AttestRequest, AttesterData, RbcEvidencesPayload};
use serde::Deserialize;
use serde_json::Value;

use crate::client::RbsRestClient;
use crate::error::RbcError;
use crate::token::TokenProvider;

const DEFAULT_AGENT_CONFIG: &str = "/etc/attestation_agent/agent_config.yaml";
const HEADER_USER_ID: &str = "User-Id";
const HEADER_API_KEY: &str = "API-Key";

/// Configuration for the RBS attest token provider.
/// Deserialized from the `token_provider` block in `rbc.yaml` (excluding the `type` field).
#[derive(Debug, Deserialize)]
pub struct RbsTokenProviderConfig {
    pub config_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentCredentials {
    user_id: String,
    apikey: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentConfig {
    agent: AgentCredentials,
}

impl AgentConfig {
    fn from_file(path: &str) -> Result<Self, RbcError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RbcError::ConfigError(format!("read agent config {path}: {e}")))?;
        serde_yaml::from_str(&content)
            .map_err(|e| RbcError::ConfigError(format!("parse agent config {path}: {e}")))
    }
}

/// Obtains a token by posting evidence to the RBS `/attest` endpoint.
pub struct RbsAttestTokenProvider {
    rest_client: RbsRestClient,
    user_id: String,
    apikey: Option<String>,
}

impl RbsAttestTokenProvider {
    /// Create a new provider.
    ///
    /// `rest_client` is shared from the top-level `Client` (constructed from endpoint/TLS config).
    /// `cfg` holds all fields from the `token_provider` block except `type`.
    pub fn new(rest_client: RbsRestClient, cfg: serde_json::Value) -> Result<Self, RbcError> {
        let config: RbsTokenProviderConfig = serde_json::from_value(cfg)
            .map_err(|e| RbcError::ConfigError(format!("RbsTokenProvider config: {e}")))?;
        let path = config.config_path.as_deref().unwrap_or(DEFAULT_AGENT_CONFIG);
        let agent = AgentConfig::from_file(path)?.agent;
        Ok(Self { rest_client, user_id: agent.user_id, apikey: agent.apikey })
    }
}

#[async_trait]
impl TokenProvider for RbsAttestTokenProvider {
    async fn get_token(
        &self,
        evidence: Option<&Value>,
        _attester_data: Option<&AttesterData>,
    ) -> Result<String, RbcError> {
        let evidence_val = evidence.ok_or_else(|| {
            RbcError::InvalidInput("RbsAttestTokenProvider requires evidence".into())
        })?;

        let rbc_evidences: RbcEvidencesPayload = serde_json::from_value(evidence_val.clone())
            .map_err(|e| RbcError::AttestError(format!("invalid evidence format: {e}")))?;

        let req = AttestRequest {
            as_provider: None,
            rbc_evidences,
            attester_data: None,
        };

        let mut headers = HashMap::new();
        headers.insert(HEADER_USER_ID, self.user_id.as_str());
        if let Some(apikey) = &self.apikey {
            headers.insert(HEADER_API_KEY, apikey);
        }
        let resp = self.rest_client.post_attest(&req, &headers).await?;

        Ok(resp.token)
    }
}

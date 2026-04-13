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

use rbs_api_types::api::{AttestRequest, AttesterData, RbcEvidencesPayload};
use serde::Deserialize;
use serde_json::Value;

use crate::client::RbsRestClient;
use crate::error::RbcError;
use crate::token::TokenProvider;

/// Configuration for the RBS attest token provider.
/// Deserialized from the `token_provider` block in `rbc.yaml` (excluding the `type` field).
/// Currently no extra fields — reserved for future extension (e.g. custom timeouts).
#[derive(Debug, Deserialize)]
pub struct RbsTokenProviderConfig;

/// Obtains a token by posting evidence to the RBS `/attest` endpoint.
pub struct RbsAttestTokenProvider {
    rest_client: RbsRestClient,
}

impl RbsAttestTokenProvider {
    /// Create a new provider.
    ///
    /// `rest_client` is shared from the top-level `Client` (constructed from endpoint/TLS config).
    /// `cfg` holds all fields from the `token_provider` block except `type`; currently unused
    /// but parsed for forward compatibility.
    pub fn new(rest_client: RbsRestClient, cfg: serde_json::Value) -> Result<Self, RbcError> {
        let _config: RbsTokenProviderConfig = serde_json::from_value(cfg)
            .map_err(|e| RbcError::ConfigError(format!("RbsTokenProvider config: {e}")))?;
        Ok(Self { rest_client })
    }
}

impl TokenProvider for RbsAttestTokenProvider {
    fn get_token(
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

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| RbcError::AttestError("no tokio runtime available".into()))?;

        let client = self.rest_client.clone();
        let resp = std::thread::scope(|_| {
            tokio::task::block_in_place(|| rt.block_on(client.post_attest(&req)))
        })?;

        Ok(resp.token)
    }
}

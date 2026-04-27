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

//! REST-based GTA attestation provider implementation.
//!
//! This provider communicates with GTA REST API to perform attestation operations.
//!
//! Architecture:
//! - `GtaRestClient`: HTTP communication layer (TLS, timeouts, retries)
//! - `AttestationRestClient`: Attestation-specific logic (request/response transformation)
//! - GTA types: Request/response structures matching GTA REST API format
//!
//! Future extension points:
//! - Policy/RefValue/Cert REST clients can be added alongside AttestationRestClient
//! - Builtin mode uses GtaBuiltinProvider directly (no HTTP)

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use rbs_api_types::{
    AttestRequest, AttestResponse, AuthChallengeResponse,
    config::AttestationRestConfig,
    error::RbsError,
};

use crate::attestation::provider::AttestationProvider;

// GTA REST API Types (matching GTA service format)

/// GTA Challenge response from `GET /challenge`.
#[derive(Debug, Clone, Deserialize)]
struct GtaChallengeResponse {
    service_version: String,
    nonce: String,
}

/// GTA Attest request body (RBS → GTA).
#[derive(Debug, Clone, Serialize)]
struct GtaAttestRequest {
    measurements: Vec<GtaMeasurement>,
}

#[derive(Debug, Clone, Serialize)]
struct GtaMeasurement {
    node_id: String,
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_fmt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attester_data: Option<serde_json::Value>,
    evidences: Vec<GtaEvidence>,
}

#[derive(Debug, Clone, Serialize)]
struct GtaEvidence {
    attester_type: String,
    evidence: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_ids: Option<Vec<String>>,
}

/// GTA Attest response from `POST /attest`.
#[derive(Debug, Clone, Deserialize)]
struct GtaAttestResponse {
    service_version: String,
    tokens: Vec<GtaToken>,
}

#[derive(Debug, Clone, Deserialize)]
struct GtaToken {
    node_id: String,
    token: String,
}

/// GTA REST API error response.
#[derive(Debug, Clone, Deserialize)]
struct GtaErrorResponse {
    message: String,
}

// GtaRestClient: HTTP Communication Layer

/// GTA REST API HTTP client.
///
/// Handles low-level HTTP communication: TLS configuration, timeouts,
/// retries, and error mapping. Does not know about attestation semantics.
#[derive(Debug, Clone)]
struct GtaRestClient {
    config: AttestationRestConfig,
    client: Client,
    base_url: String,
}

impl GtaRestClient {
    /// Create a new GTA REST client.
    fn new(config: AttestationRestConfig) -> Self {
        let client = Self::build_client(&config);
        let base_url = config.base_url.trim_end_matches('/').to_string();
        Self {
            config,
            client,
            base_url,
        }
    }

    /// Build HTTP client with TLS configuration.
    fn build_client(config: &AttestationRestConfig) -> Client {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs as u64));

        if !config.tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if !config.ca_file.is_empty() {
            let cert = std::fs::read(&config.ca_file)
                .expect("Failed to read CA certificate file");
            let cert = reqwest::Certificate::from_pem(&cert)
                .expect("Failed to parse CA certificate");
            builder = builder.add_root_certificate(cert);
        }

        builder.build().expect("Failed to build HTTP client")
    }

    /// Build full URL for a path.
    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    /// Extract error message from response body, falling back to HTTP status if absent or empty.
    async fn extract_error_message(resp: reqwest::Response, status: reqwest::StatusCode) -> String {
        match resp.json::<GtaErrorResponse>().await {
            Ok(err_resp) if !err_resp.message.is_empty() => err_resp.message,
            _ => format!("HTTP {}", status),
        }
    }

    /// GET request with retry logic.
    async fn get<T: for<'de> serde::Deserialize<'de>>(&self, path: &str) -> Result<T, GtaError> {
        let url = self.url(path);
        let mut attempt = 0;

        loop {
            attempt += 1;
            match self.client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp.json().await.map_err(|e| GtaError::ParseError(e.to_string()));
                    } else if status.is_server_error() && attempt <= self.config.retries {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    } else {
                        let message = Self::extract_error_message(resp, status).await;
                        return Err(GtaError::ServerError(message));
                    }
                }
                Err(e) if attempt <= self.config.retries => {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if e.is_timeout() {
                        continue;
                    }
                    return Err(GtaError::NetworkError(e.to_string()));
                }
                Err(e) => {
                    if e.is_timeout() {
                        return Err(GtaError::TimeoutError(e.to_string()));
                    }
                    return Err(GtaError::NetworkError(e.to_string()));
                }
            }
        }
    }

    /// POST request with JSON body and custom headers.
    async fn post<T, B>(&self, path: &str, body: &B) -> Result<T, GtaError>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        let url = self.url(path);
        let user_id = &self.config.credentials.user_id;
        let api_key = self.config.credentials.sub_api_key.get();
        let mut attempt = 0;

        loop {
            attempt += 1;
            // Build request with headers each iteration (RequestBuilder doesn't implement Clone)
            let mut req = self.client.post(&url);
            req = req.header("User-Id", user_id);
            if !api_key.is_empty() {
                req = req.header("API-Key", api_key);
            }
            match req.json(body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp.json().await.map_err(|e| GtaError::ParseError(e.to_string()));
                    } else if status.is_server_error() && attempt <= self.config.retries {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    } else {
                        let message = Self::extract_error_message(resp, status).await;
                        return Err(GtaError::ServerError(message));
                    }
                }
                Err(e) if attempt <= self.config.retries => {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if e.is_timeout() {
                        continue;
                    }
                    return Err(GtaError::NetworkError(e.to_string()));
                }
                Err(e) => {
                    if e.is_timeout() {
                        return Err(GtaError::TimeoutError(e.to_string()));
                    }
                    return Err(GtaError::NetworkError(e.to_string()));
                }
            }
        }
    }
}

/// GTA REST API errors.
#[derive(Debug)]
enum GtaError {
    /// Network connectivity issues (non-timeout).
    NetworkError(String),
    /// Request timeout.
    TimeoutError(String),
    /// HTTP 5xx from GTA server.
    ServerError(String),
    /// Response parse error.
    ParseError(String),
    /// Request validation error.
    ValidationError(String),
}

impl From<GtaError> for RbsError {
    fn from(err: GtaError) -> RbsError {
        match err {
            GtaError::NetworkError(_) => RbsError::AttestationProviderUnavailable,
            GtaError::TimeoutError(_) => RbsError::ProviderTimeout,
            GtaError::ServerError(_) => RbsError::AttestationProviderUnavailable,
            GtaError::ParseError(context) => RbsError::InternalUnexpected { context },
            GtaError::ValidationError(msg) => RbsError::InvalidParameter(msg),
        }
    }
}

impl std::fmt::Display for GtaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GtaError::NetworkError(msg) => write!(f, "network error: {}", msg),
            GtaError::TimeoutError(msg) => write!(f, "timeout error: {}", msg),
            GtaError::ServerError(msg) => write!(f, "server error: {}", msg),
            GtaError::ParseError(msg) => write!(f, "parse error: {}", msg),
            GtaError::ValidationError(msg) => write!(f, "validation error: {}", msg),
        }
    }
}

// AttestationRestClient: Attestation-Specific Logic

/// REST client for GTA attestation operations.
///
/// Implements `AttestationProvider` by combining `GtaRestClient` with
/// request/response transformation logic.
#[derive(Debug, Clone)]
pub struct AttestationRestClient {
    rest_client: GtaRestClient,
}

impl AttestationRestClient {
    /// Create a new attestation REST client.
    #[must_use]
    pub fn new(config: AttestationRestConfig) -> Self {
        Self {
            rest_client: GtaRestClient::new(config),
        }
    }

    /// Transform RBS AttestRequest to GTA AttestRequest format.
    pub(self) fn transform_to_gta_format(req: &AttestRequest) -> Result<GtaAttestRequest, RbsError> {
        let measurements = req.rbc_evidences.measurements
            .iter()
            .enumerate()
            .map(|(idx, m)| Self::transform_measurement(m, idx))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(GtaAttestRequest { measurements })
    }

    /// Validates a single evidence item and transforms it to GTA format.
    /// Returns an error if required fields (attester_type, evidence) are missing.
    fn transform_evidence_item(
        measurement_idx: usize,
        evidence_idx: usize,
        e: &rbs_api_types::RbcEvidenceItem,
    ) -> Result<GtaEvidence, RbsError> {
        let attester_type = e.attester_type.clone()
            .ok_or_else(|| RbsError::InvalidParameter(format!(
                "rbc_evidences.measurements[{}].evidences[{}].attester_type is required but None",
                measurement_idx, evidence_idx
            )))?;

        let evidence = e.evidence.clone()
            .ok_or_else(|| RbsError::InvalidParameter(format!(
                "rbc_evidences.measurements[{}].evidences[{}].evidence is required but None",
                measurement_idx, evidence_idx
            )))?;

        Ok(GtaEvidence {
            attester_type,
            evidence,
            policy_ids: e.policy_ids.clone(),
        })
    }

    fn transform_measurement(
        m: &rbs_api_types::RbcMeasurement,
        measurement_idx: usize,
    ) -> Result<GtaMeasurement, RbsError> {
        // Convert attester_data (AttesterData) to serde_json::Value
        let attester_data = m.attester_data.as_ref()
            .map(|ad| {
                serde_json::to_value(ad).map_err(|e| RbsError::InvalidParameter(format!(
                    "failed to serialize attester_data: {}", e
                )))
            })
            .transpose()?;

        let evidences = match m.evidences.as_ref() {
            Some(evidences_list) => {
                let mut transformed = Vec::with_capacity(evidences_list.len());
                for (evidence_idx, e) in evidences_list.iter().enumerate() {
                    transformed.push(Self::transform_evidence_item(measurement_idx, evidence_idx, e)?);
                }
                transformed
            }
            None => Vec::new(),
        };

        // node_id is optional, use empty string if not provided
        let node_id = m.node_id.clone().unwrap_or_default();

        Ok(GtaMeasurement {
            node_id,
            nonce: Some(m.nonce.clone()),
            nonce_type: m.nonce_type.clone(),
            token_fmt: m.token_fmt.clone(),
            attester_data,
            evidences,
        })
    }
}

#[async_trait]
impl AttestationProvider for AttestationRestClient {
    async fn get_auth_challenge(&self, _as_provider: Option<&str>) -> Result<AuthChallengeResponse, RbsError> {
        let gta_resp: GtaChallengeResponse = self.rest_client
            .get("/challenge")
            .await
            .map_err(RbsError::from)?;

        Ok(AuthChallengeResponse {
            nonce: gta_resp.nonce,
        })
    }

    async fn attest(&self, req: AttestRequest) -> Result<AttestResponse, RbsError> {
        let gta_req = AttestationRestClient::transform_to_gta_format(&req)?;

        let gta_resp: GtaAttestResponse = self.rest_client
            .post("/attest", &gta_req)
            .await
            .map_err(RbsError::from)?;

        let token = gta_resp.tokens
            .first()
            .map(|t| t.token.clone())
            .unwrap_or_default();

        Ok(AttestResponse { token })
    }
}

// GtaRestProvider (Public Type Alias)

/// REST-based GTA attestation provider.
///
/// This is the public type that implements `AttestationProvider`.
/// Internally it delegates to `AttestationRestClient` which combines
/// `GtaRestClient` (HTTP communication) with format transformation.
///
/// # Type Alias Note
///
/// For future extensions (policy, ref_value, cert REST clients),
/// this may become a struct containing multiple REST clients instead of
/// a type alias to `AttestationRestClient`.
pub type GtaRestProvider = AttestationRestClient;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_to_gta_format_empty_measurements() {
        let req = AttestRequest {
            as_provider: None,
            rbc_evidences: rbs_api_types::RbcEvidencesPayload {
                agent_version: Some("1.0.0".to_string()),
                measurements: vec![],
            },
            attester_data: None,
        };

        let gta_req = AttestationRestClient::transform_to_gta_format(&req).unwrap();
        assert!(gta_req.measurements.is_empty());
    }

    #[test]
    fn test_transform_to_gta_format_single_measurement() {
        let req = AttestRequest {
            as_provider: None,
            rbc_evidences: rbs_api_types::RbcEvidencesPayload {
                agent_version: Some("1.0.0".to_string()),
                measurements: vec![
                    rbs_api_types::RbcMeasurement {
                        nonce: "test_nonce".to_string(),
                        node_id: Some("node-1".to_string()),
                        nonce_type: Some("verifier".to_string()),
                        token_fmt: Some("eat".to_string()),
                        attester_data: None,
                        evidences: Some(vec![
                            rbs_api_types::RbcEvidenceItem {
                                attester_type: Some("tpm_boot".to_string()),
                                evidence: Some(serde_json::json!({"quote": "abc123"})),
                                policy_ids: Some(vec!["policy-1".to_string()]),
                            }
                        ]),
                    }
                ],
            },
            attester_data: None,
        };

        let gta_req = AttestationRestClient::transform_to_gta_format(&req).unwrap();
        assert_eq!(gta_req.measurements.len(), 1);

        let m = &gta_req.measurements[0];
        assert_eq!(m.node_id, "node-1");
        assert_eq!(m.nonce, Some("test_nonce".to_string()));
        assert_eq!(m.evidences.len(), 1);
        assert_eq!(m.evidences[0].attester_type, "tpm_boot");
        assert_eq!(m.evidences[0].evidence, serde_json::json!({"quote": "abc123"}));
    }

    #[test]
    fn test_transform_evidence_item_missing_attester_type() {
        let evidence = rbs_api_types::RbcEvidenceItem {
            attester_type: None,
            evidence: Some(serde_json::json!({"quote": "abc123"})),
            policy_ids: None,
        };
        let result = AttestationRestClient::transform_evidence_item(0, 2, &evidence);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("attester_type"));
        assert!(err.to_string().contains("measurements[0].evidences[2]"));
    }

    #[test]
    fn test_transform_evidence_item_missing_evidence() {
        let evidence = rbs_api_types::RbcEvidenceItem {
            attester_type: Some("tpm_boot".to_string()),
            evidence: None,
            policy_ids: None,
        };
        let result = AttestationRestClient::transform_evidence_item(1, 0, &evidence);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("evidence"));
        assert!(err.to_string().contains("measurements[1].evidences[0]"));
    }

    #[test]
    fn test_transform_measurement_with_invalid_evidence_in_list() {
        // Valid measurement with one valid and one invalid evidence
        let req = AttestRequest {
            as_provider: None,
            rbc_evidences: rbs_api_types::RbcEvidencesPayload {
                agent_version: None,
                measurements: vec![
                    rbs_api_types::RbcMeasurement {
                        nonce: "nonce1".to_string(),
                        node_id: None,
                        nonce_type: None,
                        token_fmt: None,
                        attester_data: None,
                        evidences: Some(vec![
                            rbs_api_types::RbcEvidenceItem {
                                attester_type: Some("tpm_boot".to_string()),
                                evidence: Some(serde_json::json!({"quote": "valid"})),
                                policy_ids: None,
                            },
                            rbs_api_types::RbcEvidenceItem {
                                attester_type: None,
                                evidence: Some(serde_json::json!({"quote": "invalid"})),
                                policy_ids: None,
                            },
                        ]),
                    }
                ],
            },
            attester_data: None,
        };
        let result = AttestationRestClient::transform_to_gta_format(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("attester_type"));
    }
}


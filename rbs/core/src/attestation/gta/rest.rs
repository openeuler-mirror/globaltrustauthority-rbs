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

//! REST-based GTA attestation provider — business logic layer.
//!
//! `AttestationRestClient` combines `GtaRestClient` (HTTP, see `client.rs`)
//! with request/response transformation. Implements `AttestationProvider`
//! (challenge/attest + `as_*()` subtype accessors) and the three management
//! subtypes (`RefValueProvider`/`CertProvider`/`PolicyProvider`).

use async_trait::async_trait;

use rbs_api_types::attestation_mgmt::{PolicyListQuery, AttestationPolicyListResponse};
use rbs_api_types::{
    AttestRequest, AttestResponse, AuthChallengeResponse, AttestationDeleteType,
    CertCreateRequest, CertDeleteRequest, CertListQuery, CertListResponse,
    CertMutationResponse, CertUpdateRequest, PolicyCreateRequest, PolicyDeleteRequest,
    PolicyDeleteType, PolicyMutationResponse, PolicyUpdateRequest, RefValueCreateRequest,
    RefValueDeleteRequest, RefValueListQuery, RefValueListResponse, RefValueMutationResponse,
    RefValueUpdateRequest, config::AttestationRestConfig, error::RbsError,
};
use crate::attestation::provider::{
    AttestationProvider, CertProvider, PolicyProvider, RefValueProvider,
};
use super::client::{GtaAttestRequest, GtaAttestResponse, GtaChallengeResponse, GtaEvidence, GtaMeasurement, GtaRestClient};

// GTA REST API paths
const GTA_CHALLENGE_PATH: &str = "/global-trust-authority/service/v1/challenge";
const GTA_ATTEST_PATH: &str = "/global-trust-authority/service/v1/attest";
const GTA_REF_VALUE_PATH: &str = "/global-trust-authority/service/v1/ref_value";
const GTA_CERT_PATH: &str = "/global-trust-authority/service/v1/cert";
const GTA_POLICY_PATH: &str = "/global-trust-authority/service/v1/policy";

/// REST client for GTA attestation operations.
///
/// Implements `AttestationProvider` by combining `GtaRestClient` with
/// request/response transformation logic. Also implements the three
/// management subtypes via `as_ref_value`/`as_cert`/`as_policy`.
#[derive(Debug, Clone)]
pub struct AttestationRestClient {
    rest_client: GtaRestClient,
}

impl AttestationRestClient {
    #[must_use]
    pub fn new(config: AttestationRestConfig) -> Self {
        Self { rest_client: GtaRestClient::new(config) }
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

    fn transform_evidence_item(
        measurement_idx: usize, evidence_idx: usize, e: &rbs_api_types::RbcEvidenceItem,
    ) -> Result<GtaEvidence, RbsError> {
        let attester_type = e.attester_type.clone().ok_or_else(|| RbsError::InvalidParameter(format!(
            "rbc_evidences.measurements[{}].evidences[{}].attester_type is required but None",
            measurement_idx, evidence_idx
        )))?;
        let evidence = e.evidence.clone().ok_or_else(|| RbsError::InvalidParameter(format!(
            "rbc_evidences.measurements[{}].evidences[{}].evidence is required but None",
            measurement_idx, evidence_idx
        )))?;
        Ok(GtaEvidence {
            attester_type, evidence,
            policy_ids: e.policy_ids.clone(),
            ref_value_id: e.ref_value_id.clone(),
        })
    }

    fn transform_measurement(
        m: &rbs_api_types::RbcMeasurement, measurement_idx: usize,
    ) -> Result<GtaMeasurement, RbsError> {
        let attester_data = m.attester_data.as_ref()
            .map(|ad| serde_json::to_value(ad).map_err(|e| RbsError::InvalidParameter(
                format!("failed to serialize attester_data: {}", e)
            )))
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
        Ok(GtaMeasurement {
            node_id: m.node_id.clone().unwrap_or_default(),
            nonce: Some(m.nonce.clone()),
            nonce_type: m.nonce_type.clone(),
            token_fmt: m.token_fmt.clone(),
            attester_data, evidences,
        })
    }
}

// ── AttestationProvider impl (runtime + as_* subtype accessors) ────────────

#[async_trait]
impl AttestationProvider for AttestationRestClient {
    async fn get_auth_challenge(&self, _as_provider: Option<&str>) -> Result<AuthChallengeResponse, RbsError> {
        log::debug!("GTA get_auth_challenge: requesting challenge from GTA");
        let gta_resp: GtaChallengeResponse = self.rest_client
            .get(GTA_CHALLENGE_PATH).await.map_err(RbsError::from)?;
        log::info!("GTA get_auth_challenge: challenge received successfully");
        Ok(AuthChallengeResponse { nonce: gta_resp.nonce })
    }

    async fn attest(&self, req: AttestRequest) -> Result<AttestResponse, RbsError> {
        log::info!("GTA attest: sending attestation request ({} measurements)", req.rbc_evidences.measurements.len());
        let gta_req = AttestationRestClient::transform_to_gta_format(&req)?;
        let gta_resp: GtaAttestResponse = self.rest_client
            .post(GTA_ATTEST_PATH, &gta_req).await.map_err(RbsError::from)?;
        let token = gta_resp.tokens.first().map(|t| t.token.clone()).unwrap_or_default();
        log::info!("GTA attest: attestation completed, received {} token(s)", gta_resp.tokens.len());
        Ok(AttestResponse { token })
    }

    fn as_ref_value(&self) -> Option<&dyn RefValueProvider> { Some(self) }
    fn as_cert(&self) -> Option<&dyn CertProvider> { Some(self) }
    fn as_policy(&self) -> Option<&dyn PolicyProvider> { Some(self) }
}

// ── RefValueProvider impl ────────────────────────────────────────────────────

#[async_trait]
impl RefValueProvider for AttestationRestClient {
    async fn list_ref_values(&self, as_provider: &str, query: RefValueListQuery) -> Result<RefValueListResponse, RbsError> {
        log::debug!("GTA list_ref_values: provider='{}'", as_provider);
        self.rest_client.get_mgmt_with_query(GTA_REF_VALUE_PATH, &query).await.map_err(RbsError::from)
    }

    async fn get_ref_value(&self, as_provider: &str, id: String) -> Result<RefValueListResponse, RbsError> {
        log::debug!("GTA get_ref_value: provider='{}', id='{}'", as_provider, id);
        let query = RefValueListQuery { ids: Some(id), attester_type: None, limit: None, offset: None };
        self.rest_client.get_mgmt_with_query(GTA_REF_VALUE_PATH, &query).await.map_err(RbsError::from)
    }

    async fn create_ref_value(&self, as_provider: &str, req: RefValueCreateRequest) -> Result<RefValueMutationResponse, RbsError> {
        log::debug!("GTA create_ref_value: provider='{}', name='{}'", as_provider, req.name);
        self.rest_client.post_mgmt(GTA_REF_VALUE_PATH, &req).await.map_err(RbsError::from)
    }

    async fn update_ref_value(&self, as_provider: &str, req: RefValueUpdateRequest) -> Result<RefValueMutationResponse, RbsError> {
        log::debug!("GTA update_ref_value: provider='{}', id='{}'", as_provider, req.id);
        self.rest_client.put_mgmt(GTA_REF_VALUE_PATH, &req).await.map_err(RbsError::from)
    }

    async fn delete_ref_values(&self, as_provider: &str, req: RefValueDeleteRequest) -> Result<(), RbsError> {
        log::debug!("GTA delete_ref_values: provider='{}'", as_provider);
        self.rest_client.delete_mgmt(GTA_REF_VALUE_PATH, &req).await.map_err(RbsError::from)
    }

    async fn delete_ref_value(&self, as_provider: &str, id: String) -> Result<(), RbsError> {
        log::debug!("GTA delete_ref_value: provider='{}', id='{}'", as_provider, id);
        let req = RefValueDeleteRequest { delete_type: AttestationDeleteType::Id, ids: Some(vec![id]), attester_type: None };
        self.rest_client.delete_mgmt(GTA_REF_VALUE_PATH, &req).await.map_err(RbsError::from)
    }
}

// ── CertProvider impl ────────────────────────────────────────────────────────

#[async_trait]
impl CertProvider for AttestationRestClient {
    async fn list_certs(&self, as_provider: &str, query: CertListQuery) -> Result<CertListResponse, RbsError> {
        log::debug!("GTA list_certs: provider='{}'", as_provider);
        self.rest_client.get_mgmt_with_query(GTA_CERT_PATH, &query).await.map_err(RbsError::from)
    }

    async fn get_cert(&self, as_provider: &str, id: String) -> Result<CertListResponse, RbsError> {
        log::debug!("GTA get_cert: provider='{}', id='{}'", as_provider, id);
        let query = CertListQuery { ids: Some(id), cert_type: None, limit: None, offset: None };
        self.rest_client.get_mgmt_with_query(GTA_CERT_PATH, &query).await.map_err(RbsError::from)
    }

    async fn create_cert(&self, as_provider: &str, req: CertCreateRequest) -> Result<CertMutationResponse, RbsError> {
        log::debug!("GTA create_cert: provider='{}', name='{}'", as_provider, req.name);
        self.rest_client.post_mgmt(GTA_CERT_PATH, &req).await.map_err(RbsError::from)
    }

    async fn update_cert(&self, as_provider: &str, req: CertUpdateRequest) -> Result<CertMutationResponse, RbsError> {
        log::debug!("GTA update_cert: provider='{}', id='{}'", as_provider, req.id);
        self.rest_client.put_mgmt(GTA_CERT_PATH, &req).await.map_err(RbsError::from)
    }

    async fn delete_certs(&self, as_provider: &str, req: CertDeleteRequest) -> Result<(), RbsError> {
        log::debug!("GTA delete_certs: provider='{}'", as_provider);
        self.rest_client.delete_mgmt(GTA_CERT_PATH, &req).await.map_err(RbsError::from)
    }

    async fn delete_cert(&self, as_provider: &str, id: String) -> Result<(), RbsError> {
        log::debug!("GTA delete_cert: provider='{}', id='{}'", as_provider, id);
        let req = CertDeleteRequest { delete_type: AttestationDeleteType::Id, ids: Some(vec![id]), cert_type: None };
        self.rest_client.delete_mgmt(GTA_CERT_PATH, &req).await.map_err(RbsError::from)
    }
}

// ── PolicyProvider impl ──────────────────────────────────────────────────────

#[async_trait]
impl PolicyProvider for AttestationRestClient {
    async fn list_policies(&self, as_provider: &str, query: PolicyListQuery) -> Result<AttestationPolicyListResponse, RbsError> {
        log::debug!("GTA list_policies: provider='{}'", as_provider);
        self.rest_client.get_mgmt_with_query(GTA_POLICY_PATH, &query).await.map_err(RbsError::from)
    }

    async fn get_policy(&self, as_provider: &str, id: String) -> Result<AttestationPolicyListResponse, RbsError> {
        log::debug!("GTA get_policy: provider='{}', id='{}'", as_provider, id);
        let query = PolicyListQuery { ids: Some(id), attester_type: None, limit: None, offset: None };
        self.rest_client.get_mgmt_with_query(GTA_POLICY_PATH, &query).await.map_err(RbsError::from)
    }

    async fn create_policy(&self, as_provider: &str, req: PolicyCreateRequest) -> Result<PolicyMutationResponse, RbsError> {
        log::debug!("GTA create_policy: provider='{}', name='{}'", as_provider, req.name);
        self.rest_client.post_mgmt(GTA_POLICY_PATH, &req).await.map_err(RbsError::from)
    }

    async fn update_policy(&self, as_provider: &str, req: PolicyUpdateRequest) -> Result<PolicyMutationResponse, RbsError> {
        log::debug!("GTA update_policy: provider='{}', id='{}'", as_provider, req.id);
        self.rest_client.put_mgmt(GTA_POLICY_PATH, &req).await.map_err(RbsError::from)
    }

    async fn delete_policies(&self, as_provider: &str, req: PolicyDeleteRequest) -> Result<(), RbsError> {
        log::debug!("GTA delete_policies: provider='{}'", as_provider);
        self.rest_client.delete_mgmt(GTA_POLICY_PATH, &req).await.map_err(RbsError::from)
    }

    async fn delete_policy(&self, as_provider: &str, id: String) -> Result<(), RbsError> {
        log::debug!("GTA delete_policy: provider='{}', id='{}'", as_provider, id);
        let req = PolicyDeleteRequest { delete_type: PolicyDeleteType::Id, ids: Some(vec![id]), attester_type: None };
        self.rest_client.delete_mgmt(GTA_POLICY_PATH, &req).await.map_err(RbsError::from)
    }
}

/// REST-based GTA attestation provider (public type alias).
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
                                ref_value_id: Some("R1".to_string()),
                            }
                        ]),
                    }
                ],
            },
        };
        let gta_req = AttestationRestClient::transform_to_gta_format(&req).unwrap();
        assert_eq!(gta_req.measurements.len(), 1);
        let m = &gta_req.measurements[0];
        assert_eq!(m.node_id, "node-1");
        assert_eq!(m.nonce, Some("test_nonce".to_string()));
        assert_eq!(m.evidences.len(), 1);
        assert_eq!(m.evidences[0].attester_type, "tpm_boot");
        assert_eq!(m.evidences[0].evidence, serde_json::json!({"quote": "abc123"}));
        assert_eq!(m.evidences[0].ref_value_id, Some("R1".to_string()));
    }

    #[test]
    fn test_transform_evidence_item_missing_attester_type() {
        let evidence = rbs_api_types::RbcEvidenceItem {
            attester_type: None, evidence: Some(serde_json::json!({"quote": "abc123"})),
            policy_ids: None, ref_value_id: None,
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
            attester_type: Some("tpm_boot".to_string()), evidence: None,
            policy_ids: None, ref_value_id: None,
        };
        let result = AttestationRestClient::transform_evidence_item(1, 0, &evidence);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("evidence"));
        assert!(err.to_string().contains("measurements[1].evidences[0]"));
    }

    #[test]
    fn test_transform_measurement_with_invalid_evidence_in_list() {
        let req = AttestRequest {
            as_provider: None,
            rbc_evidences: rbs_api_types::RbcEvidencesPayload {
                agent_version: None,
                measurements: vec![
                    rbs_api_types::RbcMeasurement {
                        nonce: "nonce1".to_string(), node_id: None, nonce_type: None,
                        token_fmt: None, attester_data: None,
                        evidences: Some(vec![
                            rbs_api_types::RbcEvidenceItem {
                                attester_type: Some("tpm_boot".to_string()),
                                evidence: Some(serde_json::json!({"quote": "valid"})),
                                policy_ids: None, ref_value_id: None,
                            },
                            rbs_api_types::RbcEvidenceItem {
                                attester_type: None,
                                evidence: Some(serde_json::json!({"quote": "invalid"})),
                                policy_ids: None, ref_value_id: None,
                            },
                        ]),
                    }
                ],
            },
        };
        let result = AttestationRestClient::transform_to_gta_format(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("attester_type"));
    }

    #[test]
    fn test_transform_evidence_item_with_ref_value_id() {
        let evidence = rbs_api_types::RbcEvidenceItem {
            attester_type: Some("tpm_boot".to_string()),
            evidence: Some(serde_json::json!({"quote": "abc123"})),
            policy_ids: Some(vec!["policy-1".to_string()]),
            ref_value_id: Some("R1".to_string()),
        };
        let result = AttestationRestClient::transform_evidence_item(0, 0, &evidence).unwrap();
        assert_eq!(result.attester_type, "tpm_boot");
        assert_eq!(result.evidence, serde_json::json!({"quote": "abc123"}));
        assert_eq!(result.policy_ids, Some(vec!["policy-1".to_string()]));
        assert_eq!(result.ref_value_id, Some("R1".to_string()));
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("ref_value_id"));
        assert!(json.contains("R1"));
    }

    #[test]
    fn test_transform_evidence_item_ref_value_id_none_not_serialized() {
        let evidence = rbs_api_types::RbcEvidenceItem {
            attester_type: Some("tpm_boot".to_string()),
            evidence: Some(serde_json::json!({"quote": "abc123"})),
            policy_ids: None, ref_value_id: None,
        };
        let result = AttestationRestClient::transform_evidence_item(0, 0, &evidence).unwrap();
        assert_eq!(result.ref_value_id, None);
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("ref_value_id"));
    }
}

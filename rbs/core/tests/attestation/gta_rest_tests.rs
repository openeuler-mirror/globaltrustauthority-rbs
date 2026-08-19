/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Tests for `GtaRestProvider` / `AttestationRestClient` attestation logic.

use rbs_api_types::config::{AttestationCredentials, AttestationRestConfig};
use rbs_api_types::error::RbsError;
use rbs_api_types::{AttestRequest, AttesterData, RbcEvidenceItem, RbcMeasurement};
use rbs_core::{AttestationProvider, AttestationManager, GtaRestProvider};
use std::collections::BTreeMap;

use super::common::{make_attest_request, make_mock_provider_with_token};

fn make_dummy_gta_provider() -> GtaRestProvider {
    let config = AttestationRestConfig {
        base_url: "https://gta.example.com".to_string(),
        timeout_secs: 30,
        retries: 3,
        tls_verify: true,
        ca_file: String::new(),
        client_cert_path: String::new(),
        client_key_path: String::new(),
        credentials: AttestationCredentials::default(),
    };
    GtaRestProvider::new(config)
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Attest_010
// attest指定provider提交evidence
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Attest_010
/// 验证attest显式指定as_provider=gta时能正确路由并返回token。
#[tokio::test]
async fn test_attest_010_specified_provider_returns_token() {
    let mut manager = AttestationManager::new();
    manager.register(
        "gta",
        make_mock_provider_with_token("nonce-010", "token-010"),
    );
    manager.set_default("gta");

    let req = make_attest_request(Some("gta"));
    let result = manager.attest(req).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().token, "token-010");
}

/// RUST_GTA_RBS_TP_ATTEST_Attest_010
/// 验证显式指定as_provider=gta与不指定(使用默认)路由到同一provider结果一致。
#[tokio::test]
async fn test_attest_010_explicit_vs_default_same_provider() {
    let mut manager = AttestationManager::new();
    manager.register(
        "gta",
        make_mock_provider_with_token("nonce", "token-same"),
    );
    manager.set_default("gta");

    let req_explicit = make_attest_request(Some("gta"));
    let req_default = make_attest_request(None);

    let token_explicit = manager.attest(req_explicit).await.unwrap().token;
    let token_default = manager.attest(req_default).await.unwrap().token;
    assert_eq!(token_explicit, token_default);
}

/// RUST_GTA_RBS_TP_ATTEST_Attest_010
/// 验证指定未注册的as_provider时attest返回ManagementProviderNotFound。
#[tokio::test]
async fn test_attest_010_unregistered_provider_fails() {
    let manager = AttestationManager::new();
    let req = make_attest_request(Some("unknown"));
    let result = manager.attest(req).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), RbsError::ManagementProviderNotFound(_)));
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Attest_018
// attester_data序列化失败返回400 (InvalidParameter)
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Attest_018
/// 验证attest请求中evidence缺少attester_type时transform返回InvalidParameter(400)。
/// transform_to_gta_format在HTTP调用前对请求进行校验，校验失败返回InvalidParameter。
#[tokio::test]
async fn test_attest_018_missing_attester_type_returns_invalid_parameter() {
    let provider = make_dummy_gta_provider();

    let req = AttestRequest {
        as_provider: Some("gta".to_string()),
        rbc_evidences: rbs_api_types::RbcEvidencesPayload {
            measurements: vec![RbcMeasurement {
                nonce: "test-nonce".to_string(),
                evidences: Some(vec![RbcEvidenceItem {
                    attester_type: None,
                    evidence: Some(serde_json::json!({"quote": "abc"})),
                    policy_ids: None,
                    ref_value_id: None,
                }]),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };

    let result = provider.attest(req).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, RbsError::InvalidParameter(_)));
    assert!(format!("{}", err).contains("attester_type"));
}

/// RUST_GTA_RBS_TP_ATTEST_Attest_018
/// 验证attest请求中evidence缺少evidence字段时transform返回InvalidParameter(400)。
#[tokio::test]
async fn test_attest_018_missing_evidence_returns_invalid_parameter() {
    let provider = make_dummy_gta_provider();

    let req = AttestRequest {
        as_provider: Some("gta".to_string()),
        rbc_evidences: rbs_api_types::RbcEvidencesPayload {
            measurements: vec![RbcMeasurement {
                nonce: "test-nonce".to_string(),
                evidences: Some(vec![RbcEvidenceItem {
                    attester_type: Some("tpm_boot".to_string()),
                    evidence: None,
                    policy_ids: None,
                    ref_value_id: None,
                }]),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };

    let result = provider.attest(req).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, RbsError::InvalidParameter(_)));
    assert!(format!("{}", err).contains("evidence"));
}

/// RUST_GTA_RBS_TP_ATTEST_Attest_018
/// 验证attest请求中measurement包含有效attester_data时transform成功序列化(不返回错误)。
#[tokio::test]
async fn test_attest_018_valid_attester_data_serializes() {
    let provider = make_dummy_gta_provider();

    let mut runtime_data = BTreeMap::new();
    runtime_data.insert("attester_pubkey".to_string(), serde_json::json!({"kty": "RSA"}));

    let req = AttestRequest {
        as_provider: Some("gta".to_string()),
        rbc_evidences: rbs_api_types::RbcEvidencesPayload {
            measurements: vec![RbcMeasurement {
                nonce: "test-nonce".to_string(),
                attester_data: Some(AttesterData {
                    runtime_data: Some(runtime_data.into_iter().collect()),
                }),
                evidences: Some(vec![RbcEvidenceItem {
                    attester_type: Some("tpm_boot".to_string()),
                    evidence: Some(serde_json::json!({"quote": "abc"})),
                    policy_ids: None,
                    ref_value_id: None,
                }]),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };

    let result = provider.attest(req).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        !matches!(err, RbsError::InvalidParameter(_)),
        "attester_data should serialize successfully; error should be from HTTP, not transform"
    );
}

/// RUST_GTA_RBS_TP_ATTEST_Attest_018
/// 验证多个measurement中第二个缺少attester_type时返回InvalidParameter，且错误信息包含正确索引。
#[tokio::test]
async fn test_attest_018_multiple_measurements_invalid_in_second() {
    let provider = make_dummy_gta_provider();

    let valid_evidence = RbcEvidenceItem {
        attester_type: Some("tpm_boot".to_string()),
        evidence: Some(serde_json::json!({"quote": "valid"})),
        policy_ids: None,
        ref_value_id: None,
    };
    let invalid_evidence = RbcEvidenceItem {
        attester_type: None,
        evidence: Some(serde_json::json!({"quote": "invalid"})),
        policy_ids: None,
        ref_value_id: None,
    };

    let req = AttestRequest {
        as_provider: Some("gta".to_string()),
        rbc_evidences: rbs_api_types::RbcEvidencesPayload {
            measurements: vec![
                RbcMeasurement {
                    nonce: "nonce1".to_string(),
                    evidences: Some(vec![valid_evidence]),
                    ..Default::default()
                },
                RbcMeasurement {
                    nonce: "nonce2".to_string(),
                    evidences: Some(vec![invalid_evidence]),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        ..Default::default()
    };

    let result = provider.attest(req).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, RbsError::InvalidParameter(_)));
    assert!(format!("{}", err).contains("measurements[1]"));
}

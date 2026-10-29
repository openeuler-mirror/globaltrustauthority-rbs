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
use rbs_core::{
    AttestationManager, AttestationProvider, CertProvider, GtaRestProvider, PolicyProvider, RefValueProvider,
};
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

// ===========================================================================
// Provider impl against a mock GTA service (wiremock)
//
// These tests drive every `AttestationProvider` / `RefValueProvider` /
// `CertProvider` / `PolicyProvider` method of `AttestationRestClient` through
// real HTTP so the request builders, query encoding, response decoding and
// error mapping are all exercised.
// ===========================================================================

mod provider_http {
    use super::*;
    use rbs_api_types::attestation_mgmt::{AttestationDeleteType, PolicyDeleteType, PolicyListQuery};
    use rbs_api_types::{
        CertCreateRequest, CertDeleteRequest, CertListQuery, CertUpdateRequest, PolicyCreateRequest,
        PolicyDeleteRequest, PolicyUpdateRequest, RefValueCreateRequest, RefValueDeleteRequest,
        RefValueListQuery, RefValueUpdateRequest,
    };
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CHALLENGE_PATH: &str = "/global-trust-authority/service/v1/challenge";
    const ATTEST_PATH: &str = "/global-trust-authority/service/v1/attest";
    const REF_VALUE_PATH: &str = "/global-trust-authority/service/v1/ref_value";
    const CERT_PATH: &str = "/global-trust-authority/service/v1/cert";
    const POLICY_PATH: &str = "/global-trust-authority/service/v1/policy";

    fn provider_for(server: &MockServer) -> GtaRestProvider {
        GtaRestProvider::new(AttestationRestConfig {
            base_url: server.uri(),
            timeout_secs: 5,
            retries: 0,
            tls_verify: false,
            ca_file: String::new(),
            client_cert_path: String::new(),
            client_key_path: String::new(),
            credentials: AttestationCredentials {
                user_id: "user-1".to_string(),
                api_key_auth: false,
                ..AttestationCredentials::default()
            },
        })
    }

    // ── challenge / attest ──────────────────────────────────────────────────

    /// `get_auth_challenge` returns the nonce carried by GTA's challenge response.
    #[tokio::test]
    async fn get_auth_challenge_returns_gta_nonce() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(CHALLENGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "service_version": "1.0.0",
                "nonce": "mock-nonce-1",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let resp = provider.get_auth_challenge(None).await.expect("challenge");
        assert_eq!(resp.nonce, "mock-nonce-1");
    }

    /// A non-2xx challenge answer is forwarded verbatim as a provider error.
    #[tokio::test]
    async fn get_auth_challenge_forwards_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(CHALLENGE_PATH))
            .respond_with(ResponseTemplate::new(400).set_body_string("{\"message\":\"bad request\"}"))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider.get_auth_challenge(Some("gta")).await.expect_err("upstream 400 must fail");
        assert!(matches!(err, RbsError::AttestationProviderError { status: 400, .. }), "unexpected: {err:?}");
    }

    /// `attest` transforms the evidence bundle, posts it and extracts the token;
    /// a measurement without `evidences` is sent with an empty evidence list.
    #[tokio::test]
    async fn attest_returns_token_from_gta() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ATTEST_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "service_version": "1.0.0",
                "tokens": [{"node_id": "node-1", "token": "mock-token-1"}],
            })))
            .expect(1)
            .mount(&server)
            .await;

        let req = AttestRequest {
            as_provider: Some("gta".to_string()),
            rbc_evidences: rbs_api_types::RbcEvidencesPayload {
                agent_version: Some("1.0.0".to_string()),
                measurements: vec![
                    RbcMeasurement {
                        nonce: "nonce-with-evidence".to_string(),
                        node_id: Some("node-1".to_string()),
                        attester_data: Some(AttesterData {
                            runtime_data: Some(
                                BTreeMap::from([("tee-pubkey".to_string(), serde_json::json!({"kty": "RSA"}))])
                                    .into_iter()
                                    .collect(),
                            ),
                        }),
                        evidences: Some(vec![RbcEvidenceItem {
                            attester_type: Some("tpm_boot".to_string()),
                            evidence: Some(serde_json::json!({"quote": "abc"})),
                            policy_ids: None,
                            ref_value_id: None,
                        }]),
                        ..Default::default()
                    },
                    RbcMeasurement { nonce: "nonce-without-evidence".to_string(), ..Default::default() },
                ],
            },
        };

        let provider = provider_for(&server);
        let resp = provider.attest(req).await.expect("attest");
        assert_eq!(resp.token, "mock-token-1");
    }

    /// A 200 answer with an empty token list surfaces as a 502 provider error,
    /// not as an empty token.
    #[tokio::test]
    async fn attest_rejects_empty_token_list_over_http() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ATTEST_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "service_version": "1.0.0",
                "tokens": [],
            })))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider.attest(make_attest_request(None)).await.expect_err("empty token list must fail");
        match err {
            RbsError::AttestationProviderError { status, body } => {
                assert_eq!(status, 502);
                assert!(body.contains("token list was empty"), "body: {body}");
            },
            other => panic!("expected AttestationProviderError, got {other:?}"),
        }
    }

    // ── ref_value ───────────────────────────────────────────────────────────

    /// All six ref_value operations hit the documented GTA path/method and
    /// decode the corresponding response.
    #[tokio::test]
    async fn ref_value_operations_round_trip() {
        let server = MockServer::start().await;
        let list_body = serde_json::json!({
            "ref_values": [{"id": "R1", "name": "baseline", "attester_type": "tpm"}],
            "total_count": 1,
        });
        Mock::given(method("GET"))
            .and(path(REF_VALUE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(list_body.clone()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(REF_VALUE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ref_value": {"id": "R1", "name": "baseline", "version": 1},
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(REF_VALUE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ref_value": {"id": "R1", "name": "baseline", "version": 2},
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(REF_VALUE_PATH))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let provider = provider_for(&server);

        let query =
            RefValueListQuery { ids: None, attester_type: Some("tpm".to_string()), limit: Some(10), offset: None };
        let listed = provider.list_ref_values("gta", query).await.expect("list ref values");
        assert_eq!(listed.ref_values.len(), 1);
        assert_eq!(listed.ref_values[0].id, "R1");

        let single = provider.get_ref_value("gta", "R1".to_string()).await.expect("get ref value");
        assert_eq!(single.total_count, Some(1));

        let created = provider
            .create_ref_value(
                "gta",
                RefValueCreateRequest {
                    name: "baseline".to_string(),
                    attester_type: "tpm".to_string(),
                    content: "content".to_string(),
                    content_type: None,
                    description: None,
                },
            )
            .await
            .expect("create ref value");
        assert_eq!(created.ref_value.version, 1);

        let updated = provider
            .update_ref_value(
                "gta",
                RefValueUpdateRequest {
                    id: "R1".to_string(),
                    name: None,
                    description: None,
                    attester_type: None,
                    content: None,
                    content_type: None,
                },
            )
            .await
            .expect("update ref value");
        assert_eq!(updated.ref_value.version, 2);

        provider
            .delete_ref_values(
                "gta",
                RefValueDeleteRequest { delete_type: AttestationDeleteType::All, ids: None, attester_type: None },
            )
            .await
            .expect("delete ref values");
        provider.delete_ref_value("gta", "R1".to_string()).await.expect("delete ref value");
    }

    /// The by-id GET carries the id as the `ids` query parameter.
    #[tokio::test]
    async fn get_ref_value_sends_ids_query_parameter() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REF_VALUE_PATH))
            .and(query_param("ids", "R1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ref_values": []})))
            .expect(1)
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        provider.get_ref_value("gta", "R1".to_string()).await.expect("get ref value");
    }

    // ── cert ────────────────────────────────────────────────────────────────

    /// All six cert operations hit the documented GTA path/method.
    #[tokio::test]
    async fn cert_operations_round_trip() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(CERT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "certs": [{"cert_id": "C1", "cert_name": "cert1"}],
                "total_count": 1,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CERT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cert": {"cert_id": "C1", "cert_name": "cert1", "version": 1},
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(CERT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cert": {"cert_id": "C1", "cert_name": "cert1", "version": 2},
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(CERT_PATH))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let provider = provider_for(&server);

        let query = CertListQuery { ids: None, cert_type: Some("tpm".to_string()), limit: None, offset: Some(0) };
        let listed = provider.list_certs("gta", query).await.expect("list certs");
        assert_eq!(listed.certs.len(), 1);
        assert_eq!(listed.total_count, Some(1));

        let single = provider.get_cert("gta", "C1".to_string()).await.expect("get cert");
        assert_eq!(single.certs[0].cert_id.as_deref(), Some("C1"));

        let created = provider
            .create_cert(
                "gta",
                CertCreateRequest {
                    name: "cert1".to_string(),
                    cert_type: vec!["tpm".to_string()],
                    description: None,
                    content: Some("pem".to_string()),
                    crl_content: None,
                    is_default: None,
                },
            )
            .await
            .expect("create cert");
        assert_eq!(created.cert.expect("cert result").version, Some(1));

        let updated = provider
            .update_cert(
                "gta",
                CertUpdateRequest {
                    id: "C1".to_string(),
                    name: None,
                    description: None,
                    cert_type: None,
                    content: None,
                    is_default: None,
                },
            )
            .await
            .expect("update cert");
        assert_eq!(updated.cert.expect("cert result").version, Some(2));

        provider
            .delete_certs(
                "gta",
                CertDeleteRequest {
                    delete_type: AttestationDeleteType::Type,
                    ids: None,
                    cert_type: Some("tpm".to_string()),
                },
            )
            .await
            .expect("delete certs");
        provider.delete_cert("gta", "C1".to_string()).await.expect("delete cert");
    }

    // ── attestation policy ──────────────────────────────────────────────────

    /// All six policy operations hit the documented GTA path/method.
    #[tokio::test]
    async fn policy_operations_round_trip() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "policies": [{"id": "P1", "name": "policy1", "attester_type": ["tpm"]}],
                "total_count": 1,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "policy": {"id": "P1", "name": "policy1", "version": 1},
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "policy": {"id": "P1", "name": "policy1", "version": 2},
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let provider = provider_for(&server);

        let query =
            PolicyListQuery { ids: None, attester_type: Some("tpm".to_string()), limit: Some(10), offset: None };
        let listed = provider.list_policies("gta", query).await.expect("list policies");
        assert_eq!(listed.policies.len(), 1);
        assert_eq!(listed.policies[0].id, "P1");

        let single = provider.get_policy("gta", "P1".to_string()).await.expect("get policy");
        assert_eq!(single.total_count, Some(1));

        let created = provider
            .create_policy(
                "gta",
                PolicyCreateRequest {
                    name: "policy1".to_string(),
                    attester_type: vec!["tpm".to_string()],
                    content_type: "jwt".to_string(),
                    content: "content".to_string(),
                    is_default: None,
                    description: None,
                },
            )
            .await
            .expect("create policy");
        assert_eq!(created.policy.version, 1);

        let updated = provider
            .update_policy(
                "gta",
                PolicyUpdateRequest {
                    id: "P1".to_string(),
                    name: None,
                    description: None,
                    attester_type: None,
                    content_type: None,
                    content: None,
                    is_default: None,
                },
            )
            .await
            .expect("update policy");
        assert_eq!(updated.policy.version, 2);

        provider
            .delete_policies(
                "gta",
                PolicyDeleteRequest {
                    delete_type: PolicyDeleteType::AttesterType,
                    ids: None,
                    attester_type: Some("tpm".to_string()),
                },
            )
            .await
            .expect("delete policies");
        provider.delete_policy("gta", "P1".to_string()).await.expect("delete policy");
    }

    /// Management GET failures keep GTA's status code and raw body.
    #[tokio::test]
    async fn management_get_forwards_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(REF_VALUE_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider
            .list_ref_values("gta", RefValueListQuery { ids: None, attester_type: None, limit: None, offset: None })
            .await
            .expect_err("403 must fail");
        match err {
            RbsError::AttestationProviderError { status, body } => {
                assert_eq!(status, 403);
                assert_eq!(body, "forbidden");
            },
            other => panic!("expected AttestationProviderError, got {other:?}"),
        }
    }

    /// Management write failures keep GTA's status code and raw body.
    #[tokio::test]
    async fn management_write_forwards_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CERT_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider
            .create_cert(
                "gta",
                CertCreateRequest {
                    name: "cert1".to_string(),
                    cert_type: vec!["tpm".to_string()],
                    description: None,
                    content: Some("pem".to_string()),
                    crl_content: None,
                    is_default: None,
                },
            )
            .await
            .expect_err("500 must fail");
        match err {
            RbsError::AttestationProviderError { status, body } => {
                assert_eq!(status, 500);
                assert_eq!(body, "boom");
            },
            other => panic!("expected AttestationProviderError, got {other:?}"),
        }
    }

    // ── subtype accessors ───────────────────────────────────────────────────

    /// The REST client advertises all three management subtypes.
    #[test]
    fn rest_client_exposes_all_management_subtypes() {
        let provider = make_dummy_gta_provider();
        assert!(provider.as_ref_value().is_some(), "ref_value subtype must be available");
        assert!(provider.as_cert().is_some(), "cert subtype must be available");
        assert!(provider.as_policy().is_some(), "policy subtype must be available");
    }
}

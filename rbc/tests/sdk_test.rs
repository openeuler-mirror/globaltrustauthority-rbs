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
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path, header};
use rbc::{Client, GetResourceRequest};
use rbc::sdk::{Config, ProviderRawConfig, ProviderType};

const TEST_AGENT_CONFIG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/agent_config.yaml");

#[test]
fn test_config_builder() {
    let config = Config::builder()
        .base_url("https://rbs.example.com")
        .timeout_secs(60)
        .evidence_provider(vec![ProviderRawConfig {
            enabled: true,
            provider_type: ProviderType::Native,
            rest: Default::default(),
        }])
        .token_provider(vec![ProviderRawConfig {
            enabled: true,
            provider_type: ProviderType::Rbs,
            rest: Default::default(),
        }])
        .build()
        .unwrap();

    assert_eq!(config.rbs.base_url, "https://rbs.example.com");
    assert_eq!(config.rbs.timeout_secs, Some(60));
    assert!(config.evidence_provider.as_ref().unwrap()
        .iter().any(|p| p.provider_type == ProviderType::Native));
    assert!(config.token_provider.as_ref().unwrap()
        .iter().any(|p| p.provider_type == ProviderType::Rbs));
}

#[test]
fn test_config_builder_requires_base_url() {
    let result = Config::builder()
        .evidence_provider(vec![ProviderRawConfig {
            enabled: false,
            provider_type: ProviderType::Native,
            rest: Default::default(),
        }])
        .token_provider(vec![ProviderRawConfig {
            enabled: false,
            provider_type: ProviderType::Rbs,
            rest: Default::default(),
        }])
        .build();

    assert!(result.is_err());
}

fn native_ep() -> Vec<ProviderRawConfig> {
    vec![ProviderRawConfig { enabled: false, provider_type: ProviderType::Native, rest: Default::default() }]
}

fn rbs_tp(config_path: &str) -> Vec<ProviderRawConfig> {
    let mut rest = serde_json::Map::new();
    rest.insert("config_path".into(), config_path.into());
    vec![ProviderRawConfig { enabled: true, provider_type: ProviderType::Rbs, rest }]
}

#[test]
fn test_passport_mode_with_rbs_attest() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mock_server = rt.block_on(async {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rbs/v0/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"nonce": "mock-nonce"})
            ))
            .mount(&server).await;

        Mock::given(method("POST"))
            .and(path("/rbs/v0/attest"))
            .and(header("User-Id", "test-user"))
            .and(header("API-Key", "test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"token": "mock-jwt-token"})
            ))
            .mount(&server).await;

        let resource_content = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"secret-value",
        );
        Mock::given(method("GET"))
            .and(path("/rbs/v0/test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "uri": "test-key",
                    "content": resource_content,
                    "content_type": "application/octet-stream"
                })
            ))
            .mount(&server).await;

        server
    });

    let config = Config::builder()
        .base_url(&mock_server.uri())
        .evidence_provider(native_ep())
        .token_provider(rbs_tp(TEST_AGENT_CONFIG))
        .build()
        .unwrap();

    let client = Client::new(config).unwrap();

    let challenge = client.get_auth_challenge().unwrap();
    assert_eq!(challenge.nonce, "mock-nonce");

    let session = client.new_session(None).unwrap();

    // NativeEvidenceProvider is not connected; test the attest path directly with mock evidence
    let mock_evidence = serde_json::json!({
        "agent_version": "test",
        "measurements": []
    });
    let resp = session.attest(Some(&mock_evidence)).unwrap();
    assert_eq!(resp.token, "mock-jwt-token");

    let resource = session.get_resource(
        "test-key",
        GetResourceRequest::ByAttestToken(&resp.token),
    ).unwrap();
    assert_eq!(resource.uri, "test-key");
    assert_eq!(resource.content.as_slice(), b"secret-value");
}

#[test]
fn test_rbs_error_mapping() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mock_server = rt.block_on(async {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rbs/v0/challenge"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server).await;

        server
    });

    let config = Config::builder()
        .base_url(&mock_server.uri())
        .evidence_provider(native_ep())
        .token_provider(rbs_tp(TEST_AGENT_CONFIG))
        .build()
        .unwrap();

    let client = Client::new(config).unwrap();
    let result = client.get_auth_challenge();
    assert!(result.is_err());
}

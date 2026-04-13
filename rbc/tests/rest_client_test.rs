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

use rbc::client::RbsRestClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use rbc::error::RbcError;
use rbs_api_types::api::{AttestRequest, RbcEvidencesPayload};

#[tokio::test]
async fn test_get_auth_returns_nonce() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/challenge"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"nonce": "test-nonce-123"})),
        )
        .mount(&mock_server)
        .await;

    let client = RbsRestClient::new(&mock_server.uri(), None).unwrap();
    let challenge = client.get_nonce(None).await.unwrap();
    assert_eq!(challenge.nonce, "test-nonce-123");
}

#[tokio::test]
async fn test_post_attest_returns_token() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rbs/v0/attest"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"token": "jwt-token-abc"})),
        )
        .mount(&mock_server)
        .await;

    let client = RbsRestClient::new(&mock_server.uri(), None).unwrap();
    let req = AttestRequest {
        as_provider: None,
        rbc_evidences: RbcEvidencesPayload {
            agent_version: None,
            measurements: None,
        },
        attester_data: None,
    };
    let resp = client.post_attest(&req).await.unwrap();
    assert_eq!(resp.token, "jwt-token-abc");
}

#[tokio::test]
async fn test_get_resource_with_bearer_token() {
    let mock_server = MockServer::start().await;
    let uri = "vault/default/secret/my-key";
    Mock::given(method("GET"))
        .and(path(format!("/rbs/v0/{uri}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": uri,
            "content": "c2VjcmV0LWRhdGE=",
            "content_type": "jwe"
        })))
        .mount(&mock_server)
        .await;

    let client = RbsRestClient::new(&mock_server.uri(), None).unwrap();
    let resp = client
        .get_resource(uri, "bearer-token")
        .await
        .unwrap();
    assert_eq!(resp.uri, uri);
    assert_eq!(resp.content, "c2VjcmV0LWRhdGE=");
}

#[tokio::test]
async fn test_http_404_returns_resource_not_found() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&mock_server)
        .await;

    let client = RbsRestClient::new(&mock_server.uri(), None).unwrap();
    let err = client
        .get_resource("missing", "token")
        .await
        .unwrap_err();
    assert!(
        matches!(err, RbcError::ResourceNotFound(_)),
        "expected ResourceNotFound, got: {err:?}"
    );
}

#[tokio::test]
async fn test_get_resource_by_evidence_returns_content() {
    let mock_server = MockServer::start().await;
    let uri = "vault/default/secret/my-key";
    Mock::given(method("POST"))
        .and(path(format!("/rbs/v0/{uri}/retrieve")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": uri,
            "content": "ZW5jcnlwdGVkLWNvbnRlbnQ=",
            "content_type": "jwe"
        })))
        .mount(&mock_server)
        .await;

    let client = RbsRestClient::new(&mock_server.uri(), None).unwrap();
    let req = AttestRequest {
        as_provider: None,
        rbc_evidences: RbcEvidencesPayload {
            agent_version: None,
            measurements: None,
        },
        attester_data: None,
    };
    let resp = client.get_resource_by_evidence(uri, &req).await.unwrap();
    assert_eq!(resp.uri, uri);
    assert_eq!(resp.content, "ZW5jcnlwdGVkLWNvbnRlbnQ=");
    assert_eq!(resp.content_type.as_deref(), Some("jwe"));
}

#[tokio::test]
async fn test_get_resource_by_evidence_404_returns_resource_not_found() {
    let mock_server = MockServer::start().await;
    let uri = "vault/default/secret/missing-key";
    Mock::given(method("POST"))
        .and(path(format!("/rbs/v0/{uri}/retrieve")))
        .respond_with(ResponseTemplate::new(404).set_body_string("resource not found"))
        .mount(&mock_server)
        .await;

    let client = RbsRestClient::new(&mock_server.uri(), None).unwrap();
    let req = AttestRequest {
        as_provider: None,
        rbc_evidences: RbcEvidencesPayload {
            agent_version: None,
            measurements: None,
        },
        attester_data: None,
    };
    let err = client
        .get_resource_by_evidence(uri, &req)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RbcError::ResourceNotFound(_)),
        "expected ResourceNotFound, got: {err:?}"
    );
}

#[tokio::test]
async fn test_http_500_returns_server_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/challenge"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .mount(&mock_server)
        .await;

    let client = RbsRestClient::new(&mock_server.uri(), None).unwrap();
    let err = client.get_nonce(None).await.unwrap_err();
    assert!(
        matches!(err, RbcError::ServerError(_)),
        "expected ServerError, got: {err:?}"
    );
}

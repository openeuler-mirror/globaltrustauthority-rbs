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

use rbs_admin_client::attestation::cert::{
    CertClient, CertCreateRequest, CertDeleteRequest, CertListParams, CertService, CertUpdateRequest,
};
use rbs_admin_client::AdminClient;
use rbs_api_types::AttestationDeleteType;
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn unusable_admin_client() -> AdminClient {
    AdminClient::new("data:text/plain,not-a-base-url", "test-token", &None)
        .expect("admin client should accept syntactically valid URLs")
}

fn cert_client(server: &MockServer) -> CertClient {
    CertClient::new(AdminClient::new(&server.uri(), "test-token", &None).expect("admin client should be created"), None)
}

#[tokio::test]
async fn cert_operations_report_url_build_failure() {
    let client = CertClient::new(unusable_admin_client(), None);
    let create = CertCreateRequest {
        name: "cert-1".to_string(),
        description: Some("demo cert".to_string()),
        cert_type: vec!["tpm".to_string()],
        content: Some("pem".to_string()),
        crl_content: None,
        is_default: Some(false),
    };
    let update = CertUpdateRequest {
        id: "cert-1".to_string(),
        name: Some("cert-2".to_string()),
        description: None,
        cert_type: Some(vec!["tpm".to_string()]),
        is_default: Some(true),
        content: None,
    };
    let delete = CertDeleteRequest {
        delete_type: AttestationDeleteType::Id,
        ids: Some(vec!["cert-1".to_string()]),
        cert_type: None,
    };

    let err = client.list_certs(&CertListParams::default()).await.expect_err("list should fail");
    assert_eq!(err.to_string(), "base URL cannot be used to build cert path");
    assert_eq!(
        client.create_cert(&create).await.expect_err("create should fail").to_string(),
        "base URL cannot be used to build cert path"
    );
    assert_eq!(
        client.update_cert(&update).await.expect_err("update should fail").to_string(),
        "base URL cannot be used to build cert path"
    );
    assert_eq!(
        client.delete_certs(&delete).await.expect_err("delete should fail").to_string(),
        "base URL cannot be used to build cert path"
    );
    assert_eq!(
        client.get_cert("cert-1").await.expect_err("get should fail").to_string(),
        "base URL cannot be used to build cert item path"
    );
}

#[tokio::test]
async fn cert_client_uses_pagination_for_list_and_item_endpoint_for_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/cert"))
        .and(header("authorization", "Bearer test-token"))
        .and(query_param("ids", "cert-1,cert-2"))
        .and(query_param("cert_type", "tpm"))
        .and(query_param("limit", "10"))
        .and(query_param("offset", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "certs": [],
            "total_count": 21,
            "limit": 10,
            "offset": 20
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/cert/cert-1"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"certs": [{"cert_id": "cert-1"}]})))
        .mount(&server)
        .await;

    let client = cert_client(&server);
    let listed = client
        .list_certs(&CertListParams {
            ids: Some(vec!["cert-1".to_string(), "cert-2".to_string()]),
            cert_type: Some("tpm".to_string()),
            limit: Some(10),
            offset: Some(20),
        })
        .await
        .expect("list should succeed");
    assert_eq!(listed.total_count, Some(21));
    assert_eq!(listed.limit, Some(10));
    assert_eq!(listed.offset, Some(20));

    let cert = client.get_cert("cert-1").await.expect("get should succeed");
    assert_eq!(cert.certs[0].cert_id.as_deref(), Some("cert-1"));
}

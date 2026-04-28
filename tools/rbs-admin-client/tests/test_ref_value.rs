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

use rbs_admin_client::attestation::ref_value::{
    RefValueClient, RefValueCreateRequest, RefValueDeleteRequest, RefValueListParams, RefValueService,
    RefValueUpdateRequest,
};
use rbs_admin_client::AdminClient;
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn admin_client(base_url: &str) -> AdminClient {
    AdminClient::new(base_url, "test-token", &None).expect("admin client should be created")
}

fn unusable_admin_client() -> AdminClient {
    AdminClient::new("data:text/plain,not-a-base-url", "test-token", &None)
        .expect("admin client should accept syntactically valid URLs")
}

fn ref_value_client(server: &MockServer) -> RefValueClient {
    RefValueClient::new(admin_client(&server.uri()), None)
}

#[tokio::test]
async fn ref_value_client_uses_collection_endpoint_for_list_create_update_and_delete() {
    let server = MockServer::start().await;
    let create = RefValueCreateRequest {
        name: "rv_name_1".to_string(),
        description: Some("demo ref value".to_string()),
        attester_type: "tpm".to_string(),
        content: "jwt-content".to_string(),
    };
    let update = RefValueUpdateRequest {
        id: "rv_id_1".to_string(),
        name: Some("rv_name_1_new".to_string()),
        description: Some("updated desc".to_string()),
        attester_type: Some("tpm".to_string()),
        content: Some("jwt-content-new".to_string()),
    };
    let delete = RefValueDeleteRequest {
        delete_type: "id".to_string(),
        ids: Some(vec!["rv_id_1".to_string(), "rv_id_2".to_string()]),
        attester_type: None,
    };

    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/ref_value"))
        .and(header("authorization", "Bearer test-token"))
        .and(query_param("ids", "rv_id_1,rv_id_2"))
        .and(query_param("attester_type", "tpm"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref_values": [{
                "id": "rv_id_1",
                "uid": "user_01",
                "name": "rv_name_1",
                "description": "demo ref value",
                "attester_type": "tpm",
                "content": "jwt-content",
                "version": 1,
                "valid_code": 0
            }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/rbs/v0/attestation/gta/ref_value"))
        .and(body_json(&create))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref_value": {
                "id": "rv_id_1",
                "name": "rv_name_1",
                "version": 1
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/rbs/v0/attestation/gta/ref_value"))
        .and(body_json(&update))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref_value": {
                "id": "rv_id_1",
                "name": "rv_name_1_new",
                "version": 2
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/attestation/gta/ref_value"))
        .and(body_json(&delete))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = ref_value_client(&server);
    let list = client
        .list_ref_values(&RefValueListParams {
            ids: Some(vec!["rv_id_1".to_string(), "rv_id_2".to_string()]),
            attester_type: Some("tpm".to_string()),
        })
        .await
        .expect("list ref values should succeed");
    assert_eq!(list.ref_values.len(), 1);
    assert_eq!(list.ref_values[0].id.as_deref(), Some("rv_id_1"));

    let created = client.create_ref_value(&create).await.expect("create ref value should succeed");
    assert_eq!(created.ref_value.id.as_deref(), Some("rv_id_1"));

    let updated = client.update_ref_value(&update).await.expect("update ref value should succeed");
    assert_eq!(updated.ref_value.version, Some(2));

    client.delete_ref_values(&delete).await.expect("delete ref values should succeed");
}

#[tokio::test]
async fn ref_value_operations_report_url_build_failure() {
    let client = RefValueClient::new(unusable_admin_client(), None);
    let request = RefValueCreateRequest {
        name: "rv_name_1".to_string(),
        description: None,
        attester_type: "tpm".to_string(),
        content: "jwt-content".to_string(),
    };

    let err = client.create_ref_value(&request).await.expect_err("unusable ref value URL should fail");
    assert_eq!(err.to_string(), "base URL cannot be used to build ref value path");
}

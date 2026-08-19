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

use rbs_admin_client::attestation::policy::{
    AttestationPolicyCreateRequest, AttestationPolicyDeleteRequest, AttestationPolicyListParams,
    AttestationPolicyUpdateRequest, PolicyClient, PolicyService,
};
use rbs_admin_client::AdminClient;
use rbs_api_types::PolicyDeleteType;
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

fn policy_client(server: &MockServer) -> PolicyClient {
    PolicyClient::new(admin_client(&server.uri()), None)
}

#[tokio::test]
async fn policy_client_uses_item_endpoint_for_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/policy/policy_id_1"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "policies": [{"id": "policy_id_1", "name": "policy_name_1", "attester_type": ["tpm"]}]
        })))
        .mount(&server)
        .await;

    let response = policy_client(&server).get_policy("policy_id_1").await.expect("get policy should succeed");
    assert_eq!(response.policies[0].id, "policy_id_1");
}

#[tokio::test]
async fn policy_client_uses_collection_endpoint_for_list_create_update_and_delete() {
    let server = MockServer::start().await;
    let create = AttestationPolicyCreateRequest {
        name: "policy_name_1".to_string(),
        description: Some("demo policy".to_string()),
        attester_type: vec!["tpm".to_string()],
        content_type: "text".to_string(),
        content: "cGFja2FnZSBwb2xpY3kKYWxsb3cgPSB0cnVl".to_string(),
        is_default: Some(false),
    };
    let update = AttestationPolicyUpdateRequest {
        id: "policy_id_1".to_string(),
        name: Some("policy_name_1_new".to_string()),
        description: Some("updated desc".to_string()),
        attester_type: Some(vec!["tpm".to_string()]),
        content_type: Some("text".to_string()),
        content: Some("cGFja2FnZSBwb2xpY3kKYWxsb3cgPSBmYWxzZQ==".to_string()),
        is_default: Some(true),
    };
    let delete = AttestationPolicyDeleteRequest {
        delete_type: PolicyDeleteType::Id,
        ids: Some(vec!["policy_id_1".to_string(), "policy_id_2".to_string()]),
        attester_type: None,
    };

    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .and(header("authorization", "Bearer test-token"))
        .and(query_param("ids", "policy_id_1,policy_id_2"))
        .and(query_param("attester_type", "tpm"))
        .and(query_param("limit", "10"))
        .and(query_param("offset", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "policies": [{
                "id": "policy_id_1",
                "name": "policy_name_1",
                "description": "demo policy",
                "content": "package policy\nallow = true",
                "attester_type": ["tpm"],
                "is_default": false,
                "version": 1,
                "update_time": 1710000000,
                "valid_code": 0
            }],
            "total_count": 21,
            "limit": 10,
            "offset": 20
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .and(body_json(&create))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "policy": {
                "id": "policy_id_1",
                "name": "policy_name_1",
                "version": 1
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .and(body_json(&update))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "policy": {
                "id": "policy_id_1",
                "name": "policy_name_1_new",
                "version": 2
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .and(body_json(&delete))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = policy_client(&server);
    let list = client
        .list_policies(&AttestationPolicyListParams {
            ids: Some(vec!["policy_id_1".to_string(), "policy_id_2".to_string()]),
            attester_type: Some("tpm".to_string()),
            limit: Some(10),
            offset: Some(20),
        })
        .await
        .expect("list policies should succeed");
    assert_eq!(list.policies.len(), 1);
    assert_eq!(list.policies[0].id, "policy_id_1");
    assert_eq!(list.total_count, Some(21));
    assert_eq!(list.limit, Some(10));
    assert_eq!(list.offset, Some(20));

    let created = client.create_policy(&create).await.expect("create policy should succeed");
    assert_eq!(created.policy.id, "policy_id_1");

    let updated = client.update_policy(&update).await.expect("update policy should succeed");
    assert_eq!(updated.policy.version, 2);

    client.delete_policies(&delete).await.expect("delete policies should succeed");
}

#[tokio::test]
async fn policy_operations_report_url_build_failure() {
    let client = PolicyClient::new(unusable_admin_client(), None);
    let request = AttestationPolicyCreateRequest {
        name: "policy_name_1".to_string(),
        description: None,
        attester_type: vec!["tpm".to_string()],
        content_type: "text".to_string(),
        content: "cGFja2FnZQ==".to_string(),
        is_default: None,
    };

    let err = client.create_policy(&request).await.expect_err("unusable policy URL should fail");
    assert_eq!(err.to_string(), "base URL cannot be used to build policy path");
}

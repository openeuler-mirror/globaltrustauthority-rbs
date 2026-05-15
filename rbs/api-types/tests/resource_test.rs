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

//! Integration tests for resource types.

use rbs_api_types::{
    CreateResourceRequest, ResourceContentResponse, ResourceInfoResponse,
    ResourceResponse, ResourceRetrieveRequest, UpdateResourceRequest,
};

#[test]
fn test_resource_content_response() {
    let json = serde_json::json!({
        "uri": "/rbs/v0/vault/repo1/secret/mykey",
        "content": "SGVsbG9Xb3JsZA==",
        "content_type": "application/json",
        "export_mode": "jwe"
    });
    let resp: ResourceContentResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.uri, "/rbs/v0/vault/repo1/secret/mykey");
    assert_eq!(resp.content, "SGVsbG9Xb3JsZA==");
    assert_eq!(resp.content_type.as_deref(), Some("application/json"));
    assert_eq!(resp.export_mode, "jwe");
}

#[test]
fn test_resource_info_response() {
    let json = serde_json::json!({
        "uri": "/rbs/v0/provider1/repo1/key/mykey",
        "user_id": "user1",
        "policy_id": "pol-001",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
        "content_type": "application/json",
        "export_mode": "jwe"
    });
    let resp: ResourceInfoResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.uri, "/rbs/v0/provider1/repo1/key/mykey");
    assert_eq!(resp.user_id, "user1");
    assert_eq!(resp.export_mode, "jwe");
}

#[test]
fn test_resource_retrieve_request_is_attest_request() {
    let json = serde_json::json!({
        "rbc_evidences": {
            "measurements": [{"nonce": "test-nonce"}]
        }
    });
    let req: ResourceRetrieveRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.rbc_evidences.measurements[0].nonce, "test-nonce");
}

#[test]
fn test_create_resource_request() {
    let json = serde_json::json!({
        "uri": "/rbs/v0/vault/repo1/secret/mykey",
        "policy_id": "pol-001",
        "content_type": "json",
        "export_mode": "jwe"
    });
    let req: CreateResourceRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.uri, "/rbs/v0/vault/repo1/secret/mykey");
    assert_eq!(req.policy_id, "pol-001");
    assert_eq!(req.export_mode.as_deref(), Some("jwe"));
}

#[test]
fn test_create_resource_request_defaults() {
    let json = serde_json::json!({
        "uri": "/rbs/v0/vault/repo1/secret/mykey",
        "policy_id": "pol-001"
    });
    let req: CreateResourceRequest = serde_json::from_value(json).unwrap();
    assert!(req.export_mode.is_none());
    assert!(req.content_type.is_none());
}

#[test]
fn test_update_resource_request() {
    let json = serde_json::json!({
        "policy_id": "pol-002",
        "export_mode": "jwe"
    });
    let req: UpdateResourceRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.policy_id, "pol-002");
    assert_eq!(req.export_mode.as_deref(), Some("jwe"));
}

#[test]
fn test_resource_response() {
    let json = serde_json::json!({
        "uri": "/rbs/v0/vault/repo1/secret/mykey",
        "provider_name": "vault",
        "repository_name": "repo1",
        "resource_type": "secret",
        "resource_name": "mykey",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
        "content_type": "json",
        "export_mode": "jwe",
        "policy_id": "pol-001"
    });
    let resp: ResourceResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.uri, "/rbs/v0/vault/repo1/secret/mykey");
    assert_eq!(resp.repository_name, "repo1");
    assert_eq!(resp.export_mode, "jwe");
    assert_eq!(resp.policy_id, "pol-001");
}

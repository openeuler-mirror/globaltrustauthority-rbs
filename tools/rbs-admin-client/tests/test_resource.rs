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

use rbs_admin_client::resource::{
    ResourceClient, ResourceCreateRequest, ResourcePath, ResourceService, ResourceUpdateRequest,
};
use rbs_admin_client::AdminClient;

fn admin_client(base_url: &str) -> AdminClient {
    AdminClient::new(base_url, "test-token", &None).expect("admin client should be created")
}

fn unusable_admin_client() -> AdminClient {
    AdminClient::new("data:text/plain,not-a-base-url", "test-token", &None)
        .expect("admin client should accept syntactically valid URLs")
}

fn resource_path() -> ResourcePath {
    ResourcePath {
        provider_name: "vault".to_string(),
        repository_name: "default".to_string(),
        resource_type: "secret".to_string(),
        resource_name: "demo".to_string(),
    }
}

#[tokio::test]
async fn resource_operations_report_url_build_failure() {
    let client = ResourceClient::new(unusable_admin_client());
    let path = resource_path();
    let create = ResourceCreateRequest {
        uri: "".to_string(),
        policy_id: "policy-1".to_string(),
        additional_info: None,
        content_type: Some("text".to_string()),
        export_mode: Some("plain".to_string()),
    };
    let update = ResourceUpdateRequest {
        uri: "".to_string(),
        policy_id: "policy-2".to_string(),
        additional_info: Some("Zm9v".to_string()),
        content_type: Some("json".to_string()),
        export_mode: Some("jwe".to_string()),
    };
    assert_eq!(
        client
            .get_resource_info(&path)
            .await
            .expect_err("get info should fail")
            .to_string(),
        "base URL cannot be used to build resource info path"
    );
    assert_eq!(
        client
            .create_resource(&path, &create)
            .await
            .expect_err("create should fail")
            .to_string(),
        "base URL cannot be used to build resource path"
    );
    assert_eq!(
        client
            .update_resource(&path, &update)
            .await
            .expect_err("update should fail")
            .to_string(),
        "base URL cannot be used to build resource path"
    );
    assert_eq!(
        client
            .delete_resource(&path)
            .await
            .expect_err("delete should fail")
            .to_string(),
        "base URL cannot be used to build resource path"
    );
}

#[test]
fn resource_client_is_constructible_with_valid_base_url() {
    let _ = ResourceClient::new(admin_client("https://example.com"));
}

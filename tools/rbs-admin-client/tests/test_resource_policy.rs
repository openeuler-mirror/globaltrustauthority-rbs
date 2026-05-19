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

use rbs_admin_client::resource_policy::{
    ResourcePolicyClient, ResourcePolicyContentType, ResourcePolicyCreateRequest, ResourcePolicyListParams, ResourcePolicyService,
    ResourcePolicyUpdateRequest,
};
use rbs_admin_client::AdminClient;

fn unusable_admin_client() -> AdminClient {
    AdminClient::new("data:text/plain,not-a-base-url", "test-token", &None)
        .expect("admin client should accept syntactically valid URLs")
}

#[tokio::test]
async fn resource_policy_operations_report_url_or_argument_failures() {
    let client = ResourcePolicyClient::new(unusable_admin_client());
    let create = ResourcePolicyCreateRequest {
        name: "allow-secret".to_string(),
        content_type: ResourcePolicyContentType::Base64,
        content: "Zm9v".to_string(),
    };
    let update = ResourcePolicyUpdateRequest {
        name: "allow-secret-v2".to_string(),
        content_type: ResourcePolicyContentType::Base64,
        content: "YmFy".to_string(),
    };

    assert_eq!(
        client
            .list_policies(&ResourcePolicyListParams {
                ids: Some(vec!["policy-1".to_string()]),
                limit: Some(10),
                offset: Some(0),
            })
            .await
            .expect_err("list should fail")
            .to_string(),
        "failed to build resource policy collection URL"
    );
    assert_eq!(
        client.get_policy(" ").await.expect_err("blank id should fail").to_string(),
        "policy_id must not be empty"
    );
    assert_eq!(
        client.create_policy(&create).await.expect_err("create should fail").to_string(),
        "failed to build resource policy collection URL"
    );
    assert_eq!(
        client
            .update_policy("policy-1", &update)
            .await
            .expect_err("update should fail")
            .to_string(),
        "base URL cannot be used to build resource policy item path"
    );
    assert_eq!(
        client.delete_policy("\t").await.expect_err("blank id should fail").to_string(),
        "policy_id must not be empty"
    );
    assert_eq!(
        client.delete_policies(&[]).await.expect_err("empty ids should fail").to_string(),
        "ids must not be empty"
    );
}

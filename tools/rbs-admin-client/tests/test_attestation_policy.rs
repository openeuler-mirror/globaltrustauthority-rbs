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

fn unusable_admin_client() -> AdminClient {
    AdminClient::new("data:text/plain,not-a-base-url", "test-token", &None)
        .expect("admin client should accept syntactically valid URLs")
}

#[tokio::test]
async fn policy_operations_report_url_build_failure() {
    let client = PolicyClient::new(unusable_admin_client(), None);
    let create = AttestationPolicyCreateRequest {
        name: "policy-1".to_string(),
        description: Some("demo".to_string()),
        attester_type: vec!["tpm".to_string()],
        content_type: "text".to_string(),
        content: "Zm9v".to_string(),
        is_default: Some(false),
    };
    let update = AttestationPolicyUpdateRequest {
        id: "policy-1".to_string(),
        name: Some("policy-2".to_string()),
        description: None,
        attester_type: None,
        content_type: None,
        content: None,
        is_default: None,
    };
    let delete = AttestationPolicyDeleteRequest {
        delete_type: PolicyDeleteType::Id,
        ids: Some(vec!["policy-1".to_string()]),
        attester_type: None,
    };

    assert_eq!(
        client
            .list_policies(&AttestationPolicyListParams {
                ids: Some(vec!["policy-1".to_string()]),
                attester_type: Some("tpm".to_string()),
                limit: None,
                offset: None,
            })
            .await
            .expect_err("list should fail")
            .to_string(),
        "base URL cannot be used to build policy path"
    );
    assert_eq!(
        client.create_policy(&create).await.expect_err("create should fail").to_string(),
        "base URL cannot be used to build policy path"
    );
    assert_eq!(
        client.update_policy(&update).await.expect_err("update should fail").to_string(),
        "base URL cannot be used to build policy path"
    );
    assert_eq!(
        client.delete_policies(&delete).await.expect_err("delete should fail").to_string(),
        "base URL cannot be used to build policy path"
    );
    assert_eq!(
        client.get_policy("policy-1").await.expect_err("get should fail").to_string(),
        "base URL cannot be used to build policy item path"
    );
}

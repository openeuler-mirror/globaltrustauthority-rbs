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

fn unusable_admin_client() -> AdminClient {
    AdminClient::new("data:text/plain,not-a-base-url", "test-token", &None)
        .expect("admin client should accept syntactically valid URLs")
}

#[tokio::test]
async fn ref_value_operations_report_url_build_failure() {
    let client = RefValueClient::new(unusable_admin_client(), None);
    let create = RefValueCreateRequest {
        name: "rv-1".to_string(),
        description: Some("demo".to_string()),
        attester_type: "tpm".to_string(),
        content: "jwt".to_string(),
    };
    let update = RefValueUpdateRequest {
        id: "rv-1".to_string(),
        name: Some("rv-2".to_string()),
        description: None,
        attester_type: None,
        content: None,
    };
    let delete = RefValueDeleteRequest { delete_type: "id".to_string(), ids: Some(vec!["rv-1".to_string()]), attester_type: None };

    assert_eq!(
        client
            .list_ref_values(&RefValueListParams { ids: Some(vec!["rv-1".to_string()]), attester_type: Some("tpm".to_string()) })
            .await
            .expect_err("list should fail")
            .to_string(),
        "base URL cannot be used to build ref value path"
    );
    assert_eq!(
        client
            .create_ref_value(&create)
            .await
            .expect_err("create should fail")
            .to_string(),
        "base URL cannot be used to build ref value path"
    );
    assert_eq!(
        client
            .update_ref_value(&update)
            .await
            .expect_err("update should fail")
            .to_string(),
        "base URL cannot be used to build ref value path"
    );
    assert_eq!(
        client
            .delete_ref_values(&delete)
            .await
            .expect_err("delete should fail")
            .to_string(),
        "base URL cannot be used to build ref value path"
    );
}

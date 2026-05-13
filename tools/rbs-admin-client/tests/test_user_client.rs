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

use rbs_admin_client::{AdminClient, CreateUserRequest, ListUsersParams, UpdateUserRequest, UserClient, UserService};

fn unusable_admin_client() -> AdminClient {
    AdminClient::new("data:text/plain,not-a-base-url", "test-token", &None)
        .expect("admin client should accept syntactically valid URLs")
}

#[tokio::test]
async fn user_client_reports_argument_and_url_failures() {
    let client = UserClient::new(unusable_admin_client());
    let create = CreateUserRequest {
        username: "ops".to_string(),
        role: Some("user".to_string()),
        enabled: Some(true),
        auth_type: "jwt".to_string(),
        public_key: None,
        jwk: None,
    };
    let update = UpdateUserRequest {
        role: Some("user".to_string()),
        enabled: Some(false),
        auth_type: Some("jwt".to_string()),
        public_key: None,
        jwk: None,
    };

    assert_eq!(
        client.create(&create).await.expect_err("create should fail").to_string(),
        "failed to build users collection URL"
    );
    assert_eq!(
        client
            .list(&ListUsersParams { limit: 10, offset: 0 })
            .await
            .expect_err("list should fail")
            .to_string(),
        "failed to build users collection URL"
    );
    assert_eq!(client.get(" ").await.expect_err("blank get should fail").to_string(), "username must not be empty");
    assert_eq!(client.delete("").await.expect_err("blank delete should fail").to_string(), "username must not be empty");
    assert_eq!(
        client
            .update("ops", &update)
            .await
            .expect_err("update should fail")
            .to_string(),
        "base URL cannot be used to build user item path"
    );
}

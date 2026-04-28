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

use rbs_admin_client::{
    AdminClient, CreateUserRequest, JwtVerification, ListUsersParams, UpdateUserRequest, UserClient, UserService,
};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_user_client(server: &MockServer) -> UserClient {
    let admin = AdminClient::new(&server.uri(), "test-token", &None).expect("admin client should be created");
    UserClient::new(admin)
}

fn build_unusable_base_user_client() -> UserClient {
    let admin = AdminClient::new("data:text/plain,not-a-base-url", "test-token", &None)
        .expect("admin client should accept syntactically valid URLs");
    UserClient::new(admin)
}

#[tokio::test]
async fn create_user_sends_expected_request_and_decodes_response() {
    let server = MockServer::start().await;
    let request = CreateUserRequest {
        username: "ops-user".to_string(),
        auth_type: "jwt".to_string(),
        role: Some("user".to_string()),
        jwt_verification: Some(JwtVerification {
            public_key: Some("-----BEGIN PUBLIC KEY-----\nmock\n-----END PUBLIC KEY-----".to_string()),
            jwks_uri: None,
        }),
    };

    Mock::given(method("POST"))
        .and(path("/rbs/v0/users"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_json(&request))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "user-1",
            "username": "ops-user",
            "auth_type": "jwt",
            "role": "user",
            "enabled": true,
            "jwt_verification": {
                "public_key": "-----BEGIN PUBLIC KEY-----\nmock\n-----END PUBLIC KEY-----",
                "jwks_uri": null
            },
            "created_at": "2026-04-14T10:00:00Z",
            "updated_at": "2026-04-14T10:00:00Z"
        })))
        .mount(&server)
        .await;

    let client = build_user_client(&server);
    let user = client.create(&request).await.expect("create should succeed");

    assert_eq!(user.id.as_deref(), Some("user-1"));
    assert_eq!(user.username, "ops-user");
    assert_eq!(user.auth_type.as_deref(), Some("jwt"));
    assert_eq!(user.role.as_deref(), Some("user"));
    assert_eq!(user.enabled, Some(true));
}

#[tokio::test]
async fn list_users_appends_filters_and_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rbs/v0/users"))
        .and(header("authorization", "Bearer test-token"))
        .and(query_param("role", "user"))
        .and(query_param("enabled", "true"))
        .and(query_param("limit", "20"))
        .and(query_param("offset", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "users": [
                {
                    "id": "user-1",
                    "username": "ops-user",
                    "auth_type": "jwt",
                    "role": "user",
                    "enabled": true,
                    "jwt_verification": null,
                    "created_at": "2026-04-14T10:00:00Z",
                    "updated_at": "2026-04-14T10:00:00Z"
                }
            ],
            "total_count": 1,
            "limit": 20,
            "offset": 5
        })))
        .mount(&server)
        .await;

    let client = build_user_client(&server);
    let resp = client
        .list(&ListUsersParams { role: Some("user".to_string()), enabled: Some(true), limit: 20, offset: 5 })
        .await
        .expect("list should succeed");

    assert_eq!(resp.total_count, 1);
    assert_eq!(resp.limit, 20);
    assert_eq!(resp.offset, 5);
    assert_eq!(resp.users.len(), 1);
    assert_eq!(resp.users[0].username, "ops-user");
}

#[tokio::test]
async fn list_users_allows_missing_optional_filters() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rbs/v0/users"))
        .and(header("authorization", "Bearer test-token"))
        .and(query_param("limit", "10"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "users": [],
            "total_count": 0,
            "limit": 10,
            "offset": 0
        })))
        .mount(&server)
        .await;

    let client = build_user_client(&server);
    let resp = client
        .list(&ListUsersParams { role: None, enabled: None, limit: 10, offset: 0 })
        .await
        .expect("list without optional filters should succeed");

    assert!(resp.users.is_empty());
    assert_eq!(resp.total_count, 0);
    assert_eq!(resp.limit, 10);
    assert_eq!(resp.offset, 0);
}

#[tokio::test]
async fn get_update_and_delete_user_use_item_endpoint() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rbs/v0/users/ops-user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "user-1",
            "username": "ops-user",
            "auth_type": "jwt",
            "role": "user",
            "enabled": true,
            "jwt_verification": null,
            "created_at": "2026-04-14T10:00:00Z",
            "updated_at": "2026-04-14T10:00:00Z"
        })))
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path("/rbs/v0/users/ops-user"))
        .and(body_json(&UpdateUserRequest {
            role: Some("user".to_string()),
            enabled: Some(false),
            jwt_verification: Some(JwtVerification {
                public_key: None,
                jwks_uri: Some("https://example.test/jwks".to_string()),
            }),
        }))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "user-1",
            "username": "ops-user",
            "auth_type": "jwt",
            "role": "user",
            "enabled": false,
            "jwt_verification": {
                "public_key": null,
                "jwks_uri": "https://example.test/jwks"
            },
            "created_at": "2026-04-14T10:00:00Z",
            "updated_at": "2026-04-14T11:00:00Z"
        })))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/users/ops-user"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = build_user_client(&server);

    let got = client.get("ops-user").await.expect("get should succeed");
    assert_eq!(got.username, "ops-user");

    let updated = client
        .update(
            "ops-user",
            &UpdateUserRequest {
                role: Some("user".to_string()),
                enabled: Some(false),
                jwt_verification: Some(JwtVerification {
                    public_key: None,
                    jwks_uri: Some("https://example.test/jwks".to_string()),
                }),
            },
        )
        .await
        .expect("update should succeed");
    assert_eq!(updated.enabled, Some(false));
    assert_eq!(
        updated.jwt_verification.as_ref().and_then(|value| value.jwks_uri.as_deref()),
        Some("https://example.test/jwks")
    );

    client.delete("ops-user").await.expect("delete should succeed");
}

#[tokio::test]
async fn item_operations_reject_blank_username_without_sending_request() {
    let server = MockServer::start().await;
    let client = build_user_client(&server);
    let request = UpdateUserRequest { role: None, enabled: Some(true), jwt_verification: None };

    let get_err = client.get("   ").await.expect_err("blank username should fail");
    assert!(get_err.to_string().contains("username must not be empty"));

    let update_err = client.update("", &request).await.expect_err("blank username should fail");
    assert!(update_err.to_string().contains("username must not be empty"));

    let delete_err = client.delete("\t").await.expect_err("blank username should fail");
    assert!(delete_err.to_string().contains("username must not be empty"));
}

#[tokio::test]
async fn get_returns_sanitized_not_found_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rbs/v0/users/missing-user"))
        .respond_with(ResponseTemplate::new(404).set_body_string("user not found"))
        .mount(&server)
        .await;

    let client = build_user_client(&server);
    let err = client.get("missing-user").await.expect_err("404 response should fail");

    assert_eq!(err.to_string(), "The requested item was not found.");
}

#[tokio::test]
async fn delete_returns_sanitized_server_error() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/users/ops-user"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = build_user_client(&server);
    let err = client.delete("ops-user").await.expect_err("500 delete should fail");

    assert_eq!(err.to_string(), "The service is temporarily unavailable. Please try again later.");
}

#[tokio::test]
async fn create_reports_invalid_json_response_body() {
    let server = MockServer::start().await;
    let request = CreateUserRequest {
        username: "ops-user".to_string(),
        auth_type: "jwt".to_string(),
        role: None,
        jwt_verification: None,
    };

    Mock::given(method("POST"))
        .and(path("/rbs/v0/users"))
        .and(body_json(&request))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let client = build_user_client(&server);
    let err = client.create(&request).await.expect_err("invalid JSON response should fail");

    assert_eq!(err.to_string(), "The service returned an unexpected response. Please try again later.");
}

#[tokio::test]
async fn collection_operations_report_url_build_failure() {
    let client = build_unusable_base_user_client();
    let request = CreateUserRequest {
        username: "ops-user".to_string(),
        auth_type: "jwt".to_string(),
        role: None,
        jwt_verification: None,
    };

    let err = client.create(&request).await.expect_err("unusable base URL should fail before request");

    assert_eq!(err.to_string(), "failed to build users collection URL");

    let err = client
        .list(&ListUsersParams { role: None, enabled: None, limit: 10, offset: 0 })
        .await
        .expect_err("unusable base URL should fail before request");

    assert_eq!(err.to_string(), "failed to build users collection URL");
}

#[tokio::test]
async fn item_operations_report_item_url_build_failure() {
    let client = build_unusable_base_user_client();
    let request = UpdateUserRequest { role: None, enabled: Some(false), jwt_verification: None };

    let get_err = client.get("ops-user").await.expect_err("get should fail before request");
    assert_eq!(get_err.to_string(), "base URL cannot be used to build user item path");

    let update_err = client.update("ops-user", &request).await.expect_err("update should fail before request");
    assert_eq!(update_err.to_string(), "base URL cannot be used to build user item path");

    let delete_err = client.delete("ops-user").await.expect_err("delete should fail before request");
    assert_eq!(delete_err.to_string(), "base URL cannot be used to build user item path");
}

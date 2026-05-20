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

//! Integration tests for user types.

use rbs_api_types::{
    AuthType, Role, UserCreateRequest, UserListResponse, UserResponse, UserUpdateRequest,
};

#[test]
fn test_user_create_request() {
    // Base64 of "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
    let json = serde_json::json!({
        "username": "alice",
        "auth_type": "jwt",
        "public_key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0KdGVzdAo9LS0tLS1FTkQgUFVCTElDIEtFWV9ERUNLQUdJTi0tLS0K"
    });
    let req: UserCreateRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.username, "alice");
    assert_eq!(req.auth_type, AuthType::Jwt);
    assert!(req.public_key.is_some());
    assert!(req.role.is_none());
    assert!(req.enabled.is_none());
}

#[test]
fn test_user_create_request_with_role() {
    // Base64 of "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
    let json = serde_json::json!({
        "username": "alice",
        "auth_type": "jwt",
        "public_key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0KdGVzdAo9LS0tLS1FTkQgUFVCTElDIEtFWV9ERUNLQUdJTi0tLS0K",
        "role": "user",
        "enabled": true
    });
    let req: UserCreateRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.role, Some(Role::User));
    assert_eq!(req.enabled, Some(true));
}

#[test]
fn test_user_update_request() {
    let json = serde_json::json!({
        "enabled": false
    });
    let req: UserUpdateRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.enabled, Some(false));
    assert!(req.role.is_none());
    assert!(req.auth_type.is_none());
    assert!(req.public_key.is_none());
    assert!(req.jwk.is_none());
}

#[test]
fn test_user_update_request_role() {
    // Base64 of "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
    let json = serde_json::json!({
        "role": "user",
        "auth_type": "jwt",
        "public_key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0KdGVzdAo9LS0tLS1FTkQgUFVCTElDIEtFWV9ERUNLQUdJTi0tLS0K"
    });
    let req: UserUpdateRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.role, Some(Role::User));
    assert!(req.public_key.is_some());
}

#[test]
fn test_user_response() {
    let json = serde_json::json!({
        "id": "user-123",
        "username": "bob",
        "role": "user",
        "enabled": true,
        "created_at": "2026-05-05T10:00:00Z",
        "updated_at": "2026-05-05T10:00:00Z"
    });
    let resp: UserResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.id, "user-123");
    assert_eq!(resp.username, "bob");
    assert_eq!(resp.role, Role::User);
    assert!(resp.enabled);
}

#[test]
fn test_user_list_response() {
    let json = serde_json::json!({
        "users": [
            {
                "id": "1", "username": "alice",
                "role": "user", "enabled": true,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            },
            {
                "id": "2", "username": "bob",
                "role": "user", "enabled": true,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            }
        ],
        "total_count": 10,
        "limit": 2,
        "offset": 0
    });
    let resp: UserListResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.users.len(), 2);
    assert_eq!(resp.total_count, 10);
    assert_eq!(resp.limit, 2);
    assert_eq!(resp.offset, 0);
}

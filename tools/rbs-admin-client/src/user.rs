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
use crate::client::AdminClient;
use crate::error::RbsAdminClientError;
use crate::{send_empty, send_json, validate_path_segment};
use async_trait::async_trait;
use rbs_api_types::{UserCreateRequest, UserListQuery, UserListResponse, UserResponse, UserUpdateRequest};
use reqwest::Method;

const USERS_PATH: &str = "/rbs/v0/users";
#[derive(Clone)]
pub struct UserClient {
    client: AdminClient,
}

#[async_trait]
pub trait UserService {
    async fn create(&self, request: &UserCreateRequest) -> Result<UserResponse, RbsAdminClientError>;

    async fn delete(&self, username: &str) -> Result<(), RbsAdminClientError>;

    async fn update(&self, username: &str, request: &UserUpdateRequest) -> Result<UserResponse, RbsAdminClientError>;

    async fn list(&self, params: &UserListQuery) -> Result<UserListResponse, RbsAdminClientError>;

    async fn get(&self, username: &str) -> Result<UserResponse, RbsAdminClientError>;
}

#[async_trait]
impl UserService for UserClient {
    async fn create(&self, request: &UserCreateRequest) -> Result<UserResponse, RbsAdminClientError> {
        let url = self
            .client
            .base_url
            .join(USERS_PATH)
            .map_err(|_| RbsAdminClientError::ClientError("failed to build users collection URL".to_string()))?;
        send_json(&self.client, Method::POST, url, Some(request)).await
    }

    async fn delete(&self, username: &str) -> Result<(), RbsAdminClientError> {
        if username.trim().is_empty() {
            return Err(RbsAdminClientError::ClientError("username must not be empty".to_string()));
        }
        let url = self.item_url(username)?;
        send_empty::<()>(&self.client, Method::DELETE, url, None).await
    }

    async fn update(&self, username: &str, request: &UserUpdateRequest) -> Result<UserResponse, RbsAdminClientError> {
        if username.trim().is_empty() {
            return Err(RbsAdminClientError::ClientError("username must not be empty".to_string()));
        }
        let url = self.item_url(username)?;
        send_json(&self.client, Method::PUT, url, Some(request)).await
    }

    async fn list(&self, params: &UserListQuery) -> Result<UserListResponse, RbsAdminClientError> {
        let mut url = self
            .client
            .base_url
            .join(USERS_PATH)
            .map_err(|_| RbsAdminClientError::ClientError("failed to build users collection URL".to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &params.limit.unwrap_or(10).to_string());
            query.append_pair("offset", &params.offset.unwrap_or(0).to_string());
            if let Some(role) = params.role {
                query.append_pair("role", &role.to_string());
            }
            if let Some(enabled) = params.enabled {
                query.append_pair("enabled", &enabled.to_string());
            }
        }
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn get(&self, username: &str) -> Result<UserResponse, RbsAdminClientError> {
        if username.trim().is_empty() {
            return Err(RbsAdminClientError::ClientError("username must not be empty".to_string()));
        }
        let url = self.item_url(username)?;
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }
}

impl UserClient {
    pub fn new(client: AdminClient) -> Self {
        Self { client }
    }

    fn item_url(&self, username: &str) -> Result<reqwest::Url, RbsAdminClientError> {
        validate_path_segment(username, "username")?;
        self.client.base_url.join(format!("{}/{}", USERS_PATH, username).as_str()).map_err(|_| {
            RbsAdminClientError::ClientError("base URL cannot be used to build user item path".to_string())
        })
    }
}

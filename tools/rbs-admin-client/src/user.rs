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
use async_trait::async_trait;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::AdminClient;
use crate::error::RbsAdminClientError;
use crate::{send_empty, send_json};

const USERS_PATH: &str = "/rbs/v0/users";

#[derive(Clone)]
pub struct UserClient {
    client: AdminClient,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateUserRequest {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    pub auth_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateUserRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ListUsersParams {
    pub limit: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserListResponse {
    pub items: Vec<User>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

#[async_trait]
pub trait UserService {
    async fn create(&self, request: &CreateUserRequest) -> Result<User, RbsAdminClientError>;

    async fn delete(&self, username: &str) -> Result<(), RbsAdminClientError>;

    async fn update(&self, username: &str, request: &UpdateUserRequest) -> Result<User, RbsAdminClientError>;

    async fn list(&self, params: &ListUsersParams) -> Result<UserListResponse, RbsAdminClientError>;

    async fn get(&self, username: &str) -> Result<User, RbsAdminClientError>;
}

#[async_trait]
impl UserService for UserClient {
    async fn create(&self, request: &CreateUserRequest) -> Result<User, RbsAdminClientError> {
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
        let url = self.client.base_url.join(format!("{}/{}", USERS_PATH, username).as_str()).map_err(|_| {
            RbsAdminClientError::ClientError("base URL cannot be used to build user item path".to_string())
        })?;
        send_empty(&self.client, Method::DELETE, url).await
    }

    async fn update(&self, username: &str, request: &UpdateUserRequest) -> Result<User, RbsAdminClientError> {
        if username.trim().is_empty() {
            return Err(RbsAdminClientError::ClientError("username must not be empty".to_string()));
        }
        let url = self.client.base_url.join(format!("{}/{}", USERS_PATH, username).as_str()).map_err(|_| {
            RbsAdminClientError::ClientError("base URL cannot be used to build user item path".to_string())
        })?;
        send_json(&self.client, Method::PUT, url, Some(request)).await
    }

    async fn list(&self, params: &ListUsersParams) -> Result<UserListResponse, RbsAdminClientError> {
        let mut url = self
            .client
            .base_url
            .join(USERS_PATH)
            .map_err(|_| RbsAdminClientError::ClientError("failed to build users collection URL".to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &params.limit.to_string());
            query.append_pair("offset", &params.offset.to_string());
        }
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn get(&self, username: &str) -> Result<User, RbsAdminClientError> {
        if username.trim().is_empty() {
            return Err(RbsAdminClientError::ClientError("username must not be empty".to_string()));
        }
        let url = self.client.base_url.join(format!("{}/{}", USERS_PATH, username).as_str()).map_err(|_| {
            RbsAdminClientError::ClientError("base URL cannot be used to build user item path".to_string())
        })?;
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }
}

impl UserClient {
    pub fn new(client: AdminClient) -> Self {
        Self { client }
    }
}

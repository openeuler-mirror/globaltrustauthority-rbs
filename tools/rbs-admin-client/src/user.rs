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

use crate::client::AdminClient;
use crate::error::RbsAdminClientError;
use crate::{send_empty, send_json};

const USERS_PATH: &str = "/rbs/v0/users";

#[derive(Clone)]
pub struct UserClient {
    client: AdminClient,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVerification {
    pub public_key: Option<String>,
    pub jwks_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub auth_type: String,
    pub role: Option<String>,
    pub jwt_verification: Option<JwtVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub role: Option<String>,
    pub enabled: Option<bool>,
    pub jwt_verification: Option<JwtVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUsersParams {
    pub role: Option<String>,
    pub enabled: Option<bool>,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<String>,
    pub username: String,
    pub auth_type: Option<String>,
    pub role: Option<String>,
    pub enabled: Option<bool>,
    pub jwt_verification: Option<JwtVerification>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListResponse {
    pub users: Vec<User>,
    pub total_count: u64,
    pub limit: u64,
    pub offset: u64,
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
        send_json(&self.client, Method::PATCH, url, Some(request)).await
    }

    async fn list(&self, params: &ListUsersParams) -> Result<UserListResponse, RbsAdminClientError> {
        let mut url = self
            .client
            .base_url
            .join(USERS_PATH)
            .map_err(|_| RbsAdminClientError::ClientError("failed to build users collection URL".to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(role) = &params.role {
                query.append_pair("role", role.as_str());
            }
            if let Some(enabled) = params.enabled {
                query.append_pair("enabled", if enabled { "true" } else { "false" });
            }
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

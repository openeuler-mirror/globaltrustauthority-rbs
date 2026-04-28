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
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};

use crate::client::AdminClient;
use crate::error::RbsAdminClientError;
use crate::{send_empty, send_json};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePath {
    pub res_provider: String,
    pub repository_name: String,
    pub resource_type: String,
    pub resource_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourceResponse {
    pub uri: String,
    pub content: String,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourceInfoResponse {
    pub uri: String,
    #[serde(default)]
    pub res_provider: Option<String>,
    #[serde(default)]
    pub repository_name: Option<String>,
    #[serde(default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub resource_name: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceCreateRequest {
    pub content: String,
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_mode: Option<String>,
}

pub type ResourceUpdateRequest = ResourceCreateRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourceMutationResponse {
    pub uri: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct ResourceClient {
    client: AdminClient,
}

impl ResourceClient {
    pub fn new(client: AdminClient) -> Self {
        Self { client }
    }

    fn resource_url(&self, path: &ResourcePath) -> Result<Url, RbsAdminClientError> {
        self.client
            .base_url
            .join(
                format!(
                    "/rbs/v0/{}/{}/{}/{}",
                    path.res_provider, path.repository_name, path.resource_type, path.resource_name
                )
                .as_str(),
            )
            .map_err(|_| RbsAdminClientError::ClientError("base URL cannot be used to build resource path".to_string()))
    }

    fn resource_info_url(&self, path: &ResourcePath) -> Result<Url, RbsAdminClientError> {
        self.client
            .base_url
            .join(
                format!(
                    "/rbs/v0/{}/{}/{}/{}/info",
                    path.res_provider, path.repository_name, path.resource_type, path.resource_name
                )
                .as_str(),
            )
            .map_err(|_| {
                RbsAdminClientError::ClientError("base URL cannot be used to build resource info path".to_string())
            })
    }
}

#[async_trait]
pub trait ResourceService {
    async fn get_resource(&self, path: &ResourcePath) -> Result<ResourceResponse, RbsAdminClientError>;

    async fn get_resource_info(&self, path: &ResourcePath) -> Result<ResourceInfoResponse, RbsAdminClientError>;

    async fn create_resource(
        &self,
        path: &ResourcePath,
        request: &ResourceCreateRequest,
    ) -> Result<ResourceMutationResponse, RbsAdminClientError>;

    async fn update_resource(
        &self,
        path: &ResourcePath,
        request: &ResourceUpdateRequest,
    ) -> Result<ResourceMutationResponse, RbsAdminClientError>;

    async fn delete_resource(&self, path: &ResourcePath) -> Result<(), RbsAdminClientError>;
}

#[async_trait]
impl ResourceService for ResourceClient {
    async fn get_resource(&self, path: &ResourcePath) -> Result<ResourceResponse, RbsAdminClientError> {
        let url = self.resource_url(path)?;
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn get_resource_info(&self, path: &ResourcePath) -> Result<ResourceInfoResponse, RbsAdminClientError> {
        let url = self.resource_info_url(path)?;
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn create_resource(
        &self,
        path: &ResourcePath,
        request: &ResourceCreateRequest,
    ) -> Result<ResourceMutationResponse, RbsAdminClientError> {
        let url = self.resource_url(path)?;
        send_json(&self.client, Method::POST, url, Some(request)).await
    }

    async fn update_resource(
        &self,
        path: &ResourcePath,
        request: &ResourceUpdateRequest,
    ) -> Result<ResourceMutationResponse, RbsAdminClientError> {
        let url = self.resource_url(path)?;
        send_json(&self.client, Method::PUT, url, Some(request)).await
    }

    async fn delete_resource(&self, path: &ResourcePath) -> Result<(), RbsAdminClientError> {
        let url = self.resource_url(path)?;
        send_empty(&self.client, Method::DELETE, url).await
    }
}

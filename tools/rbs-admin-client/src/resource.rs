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
use rbs_api_types::{CreateResourceRequest, ResourceContentResponse, ResourceResponse, UpdateResourceRequest};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePath {
    pub provider_name: String,
    pub repository_name: String,
    pub resource_type: String,
    pub resource_name: String,
}

#[derive(Clone, Debug)]
pub struct ResourceClient {
    client: AdminClient,
}

impl ResourceClient {
    pub fn new(client: AdminClient) -> Self {
        Self { client }
    }

    fn resource_url(&self, path: &str) -> Result<Url, RbsAdminClientError> {
        validate_resource_uri(path)?;
        self.client
            .base_url
            .join(format!("/rbs/v0/{}", path).as_str())
            .map_err(|_| RbsAdminClientError::ClientError("base URL cannot be used to build resource path".to_string()))
    }

    fn resource_path_url(&self, path: &ResourcePath) -> Result<Url, RbsAdminClientError> {
        self.resource_url(
            format!("{}/{}/{}/{}", path.provider_name, path.repository_name, path.resource_type, path.resource_name)
                .as_str(),
        )
    }

    fn resource_info_url(&self, path: &ResourcePath) -> Result<Url, RbsAdminClientError> {
        validate_resource_path(path)?;
        self.client
            .base_url
            .join(
                format!(
                    "/rbs/v0/{}/{}/{}/{}/info",
                    path.provider_name, path.repository_name, path.resource_type, path.resource_name
                )
                .as_str(),
            )
            .map_err(|_| {
                RbsAdminClientError::ClientError("base URL cannot be used to build resource info path".to_string())
            })
    }
}

fn validate_resource_uri(uri: &str) -> Result<(), RbsAdminClientError> {
    let segments: Vec<_> = uri.split('/').collect();
    if segments.len() != 4 {
        return Err(RbsAdminClientError::ClientError(
            "resource URI must use provider/repository/type/name format".to_string(),
        ));
    }
    for segment in segments {
        validate_path_segment(segment, "resource URI segment")?;
    }
    Ok(())
}

fn validate_resource_path(path: &ResourcePath) -> Result<(), RbsAdminClientError> {
    for segment in [&path.provider_name, &path.repository_name, &path.resource_type, &path.resource_name] {
        validate_path_segment(segment, "resource path segment")?;
    }
    Ok(())
}

#[async_trait]
pub trait ResourceService {
    async fn get_resource(&self, uri: &str) -> Result<ResourceContentResponse, RbsAdminClientError>;

    async fn get_resource_info(&self, path: &ResourcePath) -> Result<ResourceResponse, RbsAdminClientError>;

    async fn create_resource(
        &self,
        path: &ResourcePath,
        request: &CreateResourceRequest,
    ) -> Result<ResourceResponse, RbsAdminClientError>;

    async fn update_resource(
        &self,
        path: &ResourcePath,
        request: &UpdateResourceRequest,
    ) -> Result<ResourceResponse, RbsAdminClientError>;

    async fn delete_resource(&self, path: &ResourcePath) -> Result<(), RbsAdminClientError>;
}

#[async_trait]
impl ResourceService for ResourceClient {
    async fn get_resource(&self, uri: &str) -> Result<ResourceContentResponse, RbsAdminClientError> {
        let url = self.resource_url(uri)?;
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn get_resource_info(&self, path: &ResourcePath) -> Result<ResourceResponse, RbsAdminClientError> {
        let url = self.resource_info_url(path)?;
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn create_resource(
        &self,
        path: &ResourcePath,
        request: &CreateResourceRequest,
    ) -> Result<ResourceResponse, RbsAdminClientError> {
        let url = self.resource_path_url(path)?;
        send_json(&self.client, Method::POST, url, Some(request)).await
    }

    async fn update_resource(
        &self,
        path: &ResourcePath,
        request: &UpdateResourceRequest,
    ) -> Result<ResourceResponse, RbsAdminClientError> {
        let url = self.resource_path_url(path)?;
        send_json(&self.client, Method::PUT, url, Some(request)).await
    }

    async fn delete_resource(&self, path: &ResourcePath) -> Result<(), RbsAdminClientError> {
        let url = self.resource_path_url(path)?;
        send_empty::<()>(&self.client, Method::DELETE, url, None).await
    }
}

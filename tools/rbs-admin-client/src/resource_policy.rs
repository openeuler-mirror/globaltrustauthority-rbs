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

const RESOURCE_POLICY_PATH: &str = "/rbs/v0/resource/policy";

#[derive(Clone, Debug)]
pub struct ResourcePolicyClient {
    client: AdminClient,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourcePolicy {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub policy_content: String,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub applied_resources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourcePolicyListParams {
    pub ids: Option<Vec<String>>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePolicyCreateRequest {
    pub name: String,
    pub policy_content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePolicyUpdateRequest {
    pub name: String,
    pub policy_content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourcePolicyListResponse {
    pub policies: Vec<ResourcePolicy>,
    pub total_count: u64,
    pub limit: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourcePolicyMutationResponse {
    pub policy: ResourcePolicy,
}

#[async_trait]
pub trait ResourcePolicyService {
    async fn list_policies(
        &self,
        params: &ResourcePolicyListParams,
    ) -> Result<ResourcePolicyListResponse, RbsAdminClientError>;

    async fn get_policy(&self, policy_id: &str) -> Result<ResourcePolicyMutationResponse, RbsAdminClientError>;

    async fn create_policy(
        &self,
        request: &ResourcePolicyCreateRequest,
    ) -> Result<ResourcePolicyMutationResponse, RbsAdminClientError>;

    async fn update_policy(
        &self,
        policy_id: &str,
        request: &ResourcePolicyUpdateRequest,
    ) -> Result<ResourcePolicyMutationResponse, RbsAdminClientError>;

    async fn delete_policy(&self, policy_id: &str) -> Result<(), RbsAdminClientError>;

    async fn delete_policies(&self, ids: &[String]) -> Result<(), RbsAdminClientError>;
}

#[async_trait]
impl ResourcePolicyService for ResourcePolicyClient {
    async fn list_policies(
        &self,
        params: &ResourcePolicyListParams,
    ) -> Result<ResourcePolicyListResponse, RbsAdminClientError> {
        let mut url = self.collection_url()?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(ids) = &params.ids {
                if !ids.is_empty() {
                    query.append_pair("ids", &ids.join(","));
                }
            }
            if let Some(limit) = params.limit {
                query.append_pair("limit", &limit.to_string());
            }
            if let Some(offset) = params.offset {
                query.append_pair("offset", &offset.to_string());
            }
        }
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn get_policy(&self, policy_id: &str) -> Result<ResourcePolicyMutationResponse, RbsAdminClientError> {
        if policy_id.trim().is_empty() {
            return Err(RbsAdminClientError::ClientError("policy_id must not be empty".to_string()));
        }
        let url = self.item_url(policy_id)?;
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn create_policy(
        &self,
        request: &ResourcePolicyCreateRequest,
    ) -> Result<ResourcePolicyMutationResponse, RbsAdminClientError> {
        let url = self.collection_url()?;
        send_json(&self.client, Method::POST, url, Some(request)).await
    }

    async fn update_policy(
        &self,
        policy_id: &str,
        request: &ResourcePolicyUpdateRequest,
    ) -> Result<ResourcePolicyMutationResponse, RbsAdminClientError> {
        if policy_id.trim().is_empty() {
            return Err(RbsAdminClientError::ClientError("policy_id must not be empty".to_string()));
        }
        let url = self.item_url(policy_id)?;
        send_json(&self.client, Method::PUT, url, Some(request)).await
    }

    async fn delete_policy(&self, policy_id: &str) -> Result<(), RbsAdminClientError> {
        if policy_id.trim().is_empty() {
            return Err(RbsAdminClientError::ClientError("policy_id must not be empty".to_string()));
        }
        let url = self.item_url(policy_id)?;
        send_empty(&self.client, Method::DELETE, url).await
    }

    async fn delete_policies(&self, ids: &[String]) -> Result<(), RbsAdminClientError> {
        if ids.is_empty() {
            return Err(RbsAdminClientError::ClientError("ids must not be empty".to_string()));
        }
        let mut url = self.collection_url()?;
        url.query_pairs_mut().append_pair("ids", &ids.join(","));
        send_empty(&self.client, Method::DELETE, url).await
    }
}

impl ResourcePolicyClient {
    pub fn new(client: AdminClient) -> Self {
        Self { client }
    }

    fn collection_url(&self) -> Result<reqwest::Url, RbsAdminClientError> {
        self.client
            .base_url
            .join(RESOURCE_POLICY_PATH)
            .map_err(|_| RbsAdminClientError::ClientError("failed to build resource policy collection URL".to_string()))
    }

    fn item_url(&self, policy_id: &str) -> Result<reqwest::Url, RbsAdminClientError> {
        self.client.base_url.join(format!("{}/{}", RESOURCE_POLICY_PATH, policy_id).as_str()).map_err(|_| {
            RbsAdminClientError::ClientError("base URL cannot be used to build resource policy item path".to_string())
        })
    }
}

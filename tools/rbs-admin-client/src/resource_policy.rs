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
use crate::path_url::build_path_url;
use crate::{send_empty, send_json};
use async_trait::async_trait;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use tabled::Tabled;

const RESOURCE_POLICY_PATH: &str = "/rbs/v0/resource/policy";
const RESOURCE_POLICY_ITEM_URL_ERROR: &str = "base URL cannot be used to build resource policy item path";

#[derive(Clone, Debug)]
pub struct ResourcePolicyClient {
    client: AdminClient,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ResourcePolicyContentType {
    #[default]
    Base64,
}

impl Display for ResourcePolicyContentType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64 => write!(f, "base64"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, Tabled)]
pub struct ResourcePolicy {
    pub policy_id: String,
    pub policy_name: String,
    pub policy_version: i64,
    #[tabled(skip)]
    #[serde(default)]
    pub policy_content: String,
    pub content_type: ResourcePolicyContentType,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    #[tabled(skip)]
    pub applied_resources: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourcePolicyListParams {
    pub ids: Option<Vec<String>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePolicyCreateRequest {
    pub name: String,
    pub content_type: ResourcePolicyContentType,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePolicyUpdateRequest {
    pub name: String,
    pub content_type: ResourcePolicyContentType,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourcePolicyListResponse {
    pub items: Vec<ResourcePolicy>,
    pub total_count: i64,
}

#[async_trait]
pub trait ResourcePolicyService {
    async fn list_policies(
        &self,
        params: &ResourcePolicyListParams,
    ) -> Result<ResourcePolicyListResponse, RbsAdminClientError>;

    async fn get_policy(&self, policy_id: &str) -> Result<ResourcePolicy, RbsAdminClientError>;

    async fn create_policy(&self, request: &ResourcePolicyCreateRequest)
        -> Result<ResourcePolicy, RbsAdminClientError>;

    async fn update_policy(
        &self,
        policy_id: &str,
        request: &ResourcePolicyUpdateRequest,
    ) -> Result<ResourcePolicy, RbsAdminClientError>;

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

    async fn get_policy(&self, policy_id: &str) -> Result<ResourcePolicy, RbsAdminClientError> {
        if policy_id.trim().is_empty() {
            return Err(RbsAdminClientError::ClientError("policy_id must not be empty".to_string()));
        }
        let url = self.item_url(policy_id)?;
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn create_policy(
        &self,
        request: &ResourcePolicyCreateRequest,
    ) -> Result<ResourcePolicy, RbsAdminClientError> {
        let url = self.collection_url()?;
        send_json(&self.client, Method::POST, url, Some(request)).await
    }

    async fn update_policy(
        &self,
        policy_id: &str,
        request: &ResourcePolicyUpdateRequest,
    ) -> Result<ResourcePolicy, RbsAdminClientError> {
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
        build_path_url(
            &self.client.base_url,
            &["rbs", "v0", "resource", "policy", policy_id],
            RESOURCE_POLICY_ITEM_URL_ERROR,
        )
    }
}

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

use crate::attestation::{DEFAULT_AS_PROVIDER, POLICY_SEGMENT};
use crate::client::AdminClient;
use crate::error::RbsAdminClientError;
use crate::{send_empty_json, send_json};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Policy {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub attester_type: Vec<String>,
    #[serde(default)]
    pub is_default: Option<bool>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub update_time: Option<u64>,
    #[serde(default)]
    pub valid_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyCreateRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub attester_type: Vec<String>,
    pub content_type: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyUpdateRequest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyListParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDeleteRequest {
    pub delete_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyListResponse {
    #[serde(default)]
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyMutation {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyMutationResponse {
    pub policy: PolicyMutation,
}

#[derive(Clone, Debug)]
pub struct PolicyClient {
    client: AdminClient,
    as_provider: String,
}

impl PolicyClient {
    pub fn new(client: AdminClient, as_provider: Option<String>) -> Self {
        let as_provider = as_provider.unwrap_or_else(|| DEFAULT_AS_PROVIDER.to_string());
        Self { client, as_provider }
    }

    fn box_url(&self) -> Result<Url, RbsAdminClientError> {
        self.client
            .base_url
            .join(format!("/rbs/v0/attestation/{}/{}", self.as_provider, POLICY_SEGMENT).as_str())
            .map_err(|_| RbsAdminClientError::ClientError("base URL cannot be used to build policy path".to_string()))
    }
}

#[async_trait]
pub trait PolicyService {
    async fn list_policies(&self, params: &PolicyListParams) -> Result<PolicyListResponse, RbsAdminClientError>;

    async fn create_policy(&self, request: &PolicyCreateRequest)
        -> Result<PolicyMutationResponse, RbsAdminClientError>;

    async fn update_policy(&self, request: &PolicyUpdateRequest)
        -> Result<PolicyMutationResponse, RbsAdminClientError>;

    async fn delete_policies(&self, request: &PolicyDeleteRequest) -> Result<(), RbsAdminClientError>;
}

#[async_trait]
impl PolicyService for PolicyClient {
    async fn list_policies(&self, params: &PolicyListParams) -> Result<PolicyListResponse, RbsAdminClientError> {
        let mut url = self.box_url()?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(ids) = &params.ids {
                if !ids.is_empty() {
                    query.append_pair("ids", &ids.join(","));
                }
            }
            if let Some(attester_type) = &params.attester_type {
                if !attester_type.trim().is_empty() {
                    query.append_pair("attester_type", attester_type);
                }
            }
        }
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn create_policy(
        &self,
        request: &PolicyCreateRequest,
    ) -> Result<PolicyMutationResponse, RbsAdminClientError> {
        let url = self.box_url()?;
        send_json(&self.client, Method::POST, url, Some(request)).await
    }

    async fn update_policy(
        &self,
        request: &PolicyUpdateRequest,
    ) -> Result<PolicyMutationResponse, RbsAdminClientError> {
        let url = self.box_url()?;
        send_json(&self.client, Method::PUT, url, Some(request)).await
    }

    async fn delete_policies(&self, request: &PolicyDeleteRequest) -> Result<(), RbsAdminClientError> {
        let url = self.box_url()?;
        send_empty_json(&self.client, Method::DELETE, url, request).await
    }
}

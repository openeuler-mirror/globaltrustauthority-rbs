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

use crate::attestation::{DEFAULT_AS_PROVIDER, REF_VALUE_SEGMENT};
use crate::error::RbsAdminClientError;
use crate::{send_empty_json, send_json, AdminClient};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RefValue {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub uid: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub attester_type: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub valid_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefValueCreateRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub attester_type: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefValueUpdateRequest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RefValueListParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefValueDeleteRequest {
    pub delete_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RefValueListResponse {
    #[serde(default)]
    pub ref_values: Vec<RefValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RefValueMutation {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RefValueMutationResponse {
    pub ref_value: RefValueMutation,
}

#[derive(Debug, Clone)]
pub struct RefValueClient {
    client: AdminClient,
    as_provider: String,
}

impl RefValueClient {
    pub fn new(client: AdminClient, as_provider: Option<String>) -> Self {
        let as_provider = as_provider.unwrap_or_else(|| DEFAULT_AS_PROVIDER.to_string());
        Self { client, as_provider }
    }

    fn box_url(&self) -> Result<Url, RbsAdminClientError> {
        self.client
            .base_url
            .join(format!("/rbs/v0/attestation/{}/{}", self.as_provider, REF_VALUE_SEGMENT).as_str())
            .map_err(|_| {
                RbsAdminClientError::ClientError("base URL cannot be used to build ref value path".to_string())
            })
    }
}

#[async_trait]
pub trait RefValueService {
    async fn list_ref_values(&self, params: &RefValueListParams) -> Result<RefValueListResponse, RbsAdminClientError>;

    async fn create_ref_value(
        &self,
        request: &RefValueCreateRequest,
    ) -> Result<RefValueMutationResponse, RbsAdminClientError>;

    async fn update_ref_value(
        &self,
        request: &RefValueUpdateRequest,
    ) -> Result<RefValueMutationResponse, RbsAdminClientError>;

    async fn delete_ref_values(&self, request: &RefValueDeleteRequest) -> Result<(), RbsAdminClientError>;
}

#[async_trait]
impl RefValueService for RefValueClient {
    async fn list_ref_values(&self, params: &RefValueListParams) -> Result<RefValueListResponse, RbsAdminClientError> {
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

    async fn create_ref_value(
        &self,
        request: &RefValueCreateRequest,
    ) -> Result<RefValueMutationResponse, RbsAdminClientError> {
        let url = self.box_url()?;
        send_json(&self.client, Method::POST, url, Some(request)).await
    }

    async fn update_ref_value(
        &self,
        request: &RefValueUpdateRequest,
    ) -> Result<RefValueMutationResponse, RbsAdminClientError> {
        let url = self.box_url()?;
        send_json(&self.client, Method::PUT, url, Some(request)).await
    }

    async fn delete_ref_values(&self, request: &RefValueDeleteRequest) -> Result<(), RbsAdminClientError> {
        let url = self.box_url()?;
        send_empty_json(&self.client, Method::DELETE, url, request).await
    }
}

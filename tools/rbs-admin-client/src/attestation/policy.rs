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

pub use rbs_api_types::attestation_mgmt::AttestationPolicyListResponse as PolicyListResponse;
pub use rbs_api_types::{
    AttestationPolicy, PolicyCreateRequest as AttestationPolicyCreateRequest,
    PolicyDeleteRequest as AttestationPolicyDeleteRequest, PolicyMutation, PolicyMutationResponse,
    PolicyUpdateRequest as AttestationPolicyUpdateRequest,
};

use crate::attestation::{DEFAULT_AS_PROVIDER, POLICY_SEGMENT};
use crate::client::AdminClient;
use crate::error::RbsAdminClientError;
use crate::{send_empty, send_json, validate_path_segment};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AttestationPolicyListParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attester_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
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

    fn item_url(&self, id: &str) -> Result<Url, RbsAdminClientError> {
        validate_path_segment(id, "policy ID")?;
        self.client
            .base_url
            .join(format!("/rbs/v0/attestation/{}/{}/{}", self.as_provider, POLICY_SEGMENT, id).as_str())
            .map_err(|_| RbsAdminClientError::ClientError("base URL cannot be used to build policy item path".to_string()))
    }
}

#[async_trait]
pub trait PolicyService {
    async fn list_policies(
        &self,
        params: &AttestationPolicyListParams,
    ) -> Result<PolicyListResponse, RbsAdminClientError>;

    async fn get_policy(&self, id: &str) -> Result<PolicyListResponse, RbsAdminClientError>;

    async fn create_policy(
        &self,
        request: &AttestationPolicyCreateRequest,
    ) -> Result<PolicyMutationResponse, RbsAdminClientError>;

    async fn update_policy(
        &self,
        request: &AttestationPolicyUpdateRequest,
    ) -> Result<PolicyMutationResponse, RbsAdminClientError>;

    async fn delete_policies(&self, request: &AttestationPolicyDeleteRequest) -> Result<(), RbsAdminClientError>;
}

#[async_trait]
impl PolicyService for PolicyClient {
    async fn list_policies(
        &self,
        params: &AttestationPolicyListParams,
    ) -> Result<PolicyListResponse, RbsAdminClientError> {
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
            if let Some(limit) = params.limit {
                query.append_pair("limit", &limit.to_string());
            }
            if let Some(offset) = params.offset {
                query.append_pair("offset", &offset.to_string());
            }
        }
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn get_policy(&self, id: &str) -> Result<PolicyListResponse, RbsAdminClientError> {
        let url = self.item_url(id)?;
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn create_policy(
        &self,
        request: &AttestationPolicyCreateRequest,
    ) -> Result<PolicyMutationResponse, RbsAdminClientError> {
        let url = self.box_url()?;
        send_json(&self.client, Method::POST, url, Some(request)).await
    }

    async fn update_policy(
        &self,
        request: &AttestationPolicyUpdateRequest,
    ) -> Result<PolicyMutationResponse, RbsAdminClientError> {
        let url = self.box_url()?;
        send_json(&self.client, Method::PUT, url, Some(request)).await
    }

    async fn delete_policies(&self, request: &AttestationPolicyDeleteRequest) -> Result<(), RbsAdminClientError> {
        let url = self.box_url()?;
        send_empty(&self.client, Method::DELETE, url, Some(request)).await
    }
}

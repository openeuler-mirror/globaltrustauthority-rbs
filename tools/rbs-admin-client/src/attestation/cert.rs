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

use crate::attestation::{CERT_SEGMENT, DEFAULT_AS_PROVIDER};
use crate::client::AdminClient;
use crate::error::RbsAdminClientError;
use crate::{send_empty_json, send_json};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertRecord {
    #[serde(default, rename = "cert_id")]
    pub id: Option<String>,
    #[serde(rename = "cert_name")]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default, rename = "cert_type")]
    pub cert_type: Vec<String>,
    #[serde(default)]
    pub is_default: Option<bool>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub create_time: Option<u64>,
    #[serde(default)]
    pub update_time: Option<u64>,
    #[serde(default)]
    pub valid_code: Option<i32>,
    #[serde(default)]
    pub cert_revoked_date: Option<u64>,
    #[serde(default)]
    pub cert_revoked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CrlRecord {
    #[serde(default, rename = "crl_id")]
    pub id: Option<String>,
    #[serde(rename = "crl_name")]
    pub name: String,
    #[serde(default, rename = "crl_content")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertCreateRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub cert_type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "crl_content")]
    pub crl_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertUpdateRequest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub cert_type: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertListParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "cert_type")]
    pub cert_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertDeleteRequest {
    pub delete_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub cert_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertListResponse {
    #[serde(default)]
    pub certs: Vec<CertRecord>,
    #[serde(default)]
    pub crls: Vec<CrlRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertMutationCert {
    #[serde(default, rename = "cert_id")]
    pub id: Option<String>,
    #[serde(rename = "cert_name")]
    pub name: String,
    #[serde(default)]
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertMutationCrl {
    #[serde(default, rename = "crl_id")]
    pub id: Option<String>,
    #[serde(rename = "crl_name")]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertMutationResponse {
    #[serde(default)]
    pub cert: Option<CertMutationCert>,
    #[serde(default)]
    pub crl: Option<CertMutationCrl>,
}

#[derive(Clone, Debug)]
pub struct CertClient {
    client: AdminClient,
    as_provider: String,
}

impl CertClient {
    pub fn new(client: AdminClient, as_provider: Option<String>) -> Self {
        let as_provider = as_provider.unwrap_or_else(|| DEFAULT_AS_PROVIDER.to_string());
        Self { client, as_provider }
    }

    fn box_url(&self) -> Result<Url, RbsAdminClientError> {
        self.client
            .base_url
            .join(format!("/rbs/v0/attestation/{}/{}", self.as_provider, CERT_SEGMENT).as_str())
            .map_err(|_| RbsAdminClientError::ClientError("base URL cannot be used to build cert path".to_string()))
    }
}

#[async_trait]
pub trait CertService {
    async fn list_certs(&self, params: &CertListParams) -> Result<CertListResponse, RbsAdminClientError>;

    async fn create_cert(&self, request: &CertCreateRequest) -> Result<CertMutationResponse, RbsAdminClientError>;

    async fn update_cert(&self, request: &CertUpdateRequest) -> Result<CertMutationResponse, RbsAdminClientError>;

    async fn delete_certs(&self, request: &CertDeleteRequest) -> Result<(), RbsAdminClientError>;
}

#[async_trait]
impl CertService for CertClient {
    async fn list_certs(&self, params: &CertListParams) -> Result<CertListResponse, RbsAdminClientError> {
        let mut url = self.box_url()?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(ids) = &params.ids {
                if !ids.is_empty() {
                    query.append_pair("ids", &ids.join(","));
                }
            }
            if let Some(cert_type) = &params.cert_type {
                if !cert_type.trim().is_empty() {
                    query.append_pair("cert_type", cert_type);
                }
            }
        }
        send_json(&self.client, Method::GET, url, Option::<&()>::None).await
    }

    async fn create_cert(&self, request: &CertCreateRequest) -> Result<CertMutationResponse, RbsAdminClientError> {
        let url = self.box_url()?;
        send_json(&self.client, Method::POST, url, Some(request)).await
    }

    async fn update_cert(&self, request: &CertUpdateRequest) -> Result<CertMutationResponse, RbsAdminClientError> {
        let url = self.box_url()?;
        send_json(&self.client, Method::PUT, url, Some(request)).await
    }

    async fn delete_certs(&self, request: &CertDeleteRequest) -> Result<(), RbsAdminClientError> {
        let url = self.box_url()?;
        send_empty_json(&self.client, Method::DELETE, url, request).await
    }
}

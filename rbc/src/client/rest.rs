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

//! RBS REST API client and TLS configuration.

use std::collections::HashMap;
use reqwest::Client as HttpClient;
use rbs_api_types::{
    AttestRequest, AttestResponse, AuthChallengeResponse, ResourceContentResponse,
};

use crate::error::RbcError;

/// One-way TLS configuration (server certificate verification only).
pub struct TlsConfig {
    pub ca_cert: Option<String>,
}

/// RBS REST API client.
#[derive(Clone)]
pub struct RbsRestClient {
    base_url: String,
    http: HttpClient,
}

impl RbsRestClient {
    pub fn new(base_url: &str, tls: Option<&TlsConfig>, timeout_secs: Option<u64>) -> Result<Self, RbcError> {
        let mut builder = HttpClient::builder();

        if let Some(tls_cfg) = tls {
            if let Some(ca_path) = &tls_cfg.ca_cert {
                let ca_pem = std::fs::read(ca_path)
                    .map_err(|e| RbcError::TlsError(format!("read CA cert {ca_path}: {e}")))?;
                let cert = reqwest::Certificate::from_pem(&ca_pem)
                    .map_err(|e| RbcError::TlsError(format!("parse CA cert: {e}")))?;
                builder = builder.add_root_certificate(cert);
            }
        }

        if let Some(secs) = timeout_secs {
            builder = builder.timeout(std::time::Duration::from_secs(secs));
        }

        let http = builder
            .build()
            .map_err(|e| RbcError::TlsError(e.to_string()))?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// GET /rbs/v0/challenge → AuthChallengeResponse
    pub async fn get_nonce(&self, provider: Option<String>) -> Result<AuthChallengeResponse, RbcError> {
        let url = format!("{}/rbs/v0/challenge", self.base_url);

        // extend url if specify provider: rbs/v0/challenge?as_provider={provider}
        let mut request_builder = self.http.get(&url);
        if let Some(p) = provider {
            request_builder = request_builder.query(&[("as_provider", &p)]);
        }
        let resp = request_builder
            .send()
            .await
            .map_err(|e| RbcError::NetworkError(e.to_string()))?;
        Self::handle_response(resp).await
    }

    /// POST /rbs/v0/attest → AttestResponse
    pub async fn post_attest(&self, req: &AttestRequest, extra_headers: &HashMap<&str, &str>) -> Result<AttestResponse, RbcError> {
        let url = format!("{}/rbs/v0/attest", self.base_url);
        let mut builder = self.http.post(&url).json(req);
        for (name, value) in extra_headers {
            builder = builder.header(*name, *value);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| RbcError::NetworkError(e.to_string()))?;
        Self::handle_response(resp).await
    }

    /// GET /rbs/v0/{uri} + Authorization header → ResourceContentResponse
    pub async fn get_resource(
        &self,
        uri: &str,
        token: &str,
    ) -> Result<ResourceContentResponse, RbcError> {
        let url = format!("{}/rbs/v0/{}", self.base_url, uri);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Attest {token}"))
            .send()
            .await
            .map_err(|e| RbcError::NetworkError(e.to_string()))?;
        Self::handle_response(resp).await
    }

    /// POST /rbs/v0/{uri}/retrieve (pull-by-evidence mode) → ResourceContentResponse
    pub async fn get_resource_by_evidence(
        &self,
        uri: &str,
        evidence: &AttestRequest,
    ) -> Result<ResourceContentResponse, RbcError> {
        let url = format!("{}/rbs/v0/{}/retrieve", self.base_url, uri);
        let resp = self
            .http
            .post(&url)
            .json(evidence)
            .send()
            .await
            .map_err(|e| RbcError::NetworkError(e.to_string()))?;
        Self::handle_response(resp).await
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, RbcError> {
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            resp.json::<T>()
                .await
                .map_err(|e| RbcError::NetworkError(e.to_string()))
        } else {
            let body = resp.text().await.unwrap_or_default();
            match status {
                401 | 403 => Err(RbcError::AuthError(format!("HTTP {status}: {body}"))),
                404 => Err(RbcError::ResourceNotFound(body)),
                408 | 504 => Err(RbcError::TimeoutError(format!("HTTP {status}: {body}"))),
                s if s >= 500 => Err(RbcError::ServerError(format!("HTTP {status}: {body}"))),
                _ => Err(RbcError::AttestError(format!("HTTP {status}: {body}"))),
            }
        }
    }
}

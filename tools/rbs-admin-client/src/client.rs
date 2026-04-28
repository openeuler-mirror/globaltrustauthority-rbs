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
use crate::error::RbsAdminClientError;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Certificate, Url};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AdminClient {
    pub base_url: Url,
    bearer_token: String,
    pub http_client: reqwest::Client,
}

impl AdminClient {
    pub fn new(base_url: &str, bearer_token: &str, cert: &Option<Vec<u8>>) -> Result<Self, RbsAdminClientError> {
        let parsed_base_url =
            Url::parse(base_url).map_err(|_err| RbsAdminClientError::ClientError("invalid base url".to_string()))?;
        let mut headers = HeaderMap::new();
        let bearer_header = HeaderValue::from_str(&format!("Bearer {bearer_token}"))
            .map_err(|_err| RbsAdminClientError::ClientError("invalid bearer token".to_string()))?;
        headers.insert("Authorization", bearer_header);

        let mut client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3));
        if parsed_base_url.scheme() == "https" {
            client = client.https_only(true);
        }
        if let Some(cert) = cert {
            let reqwest_cert = Certificate::from_pem(&cert).map_err(|_| {
                RbsAdminClientError::ClientError(
                    "Unable to use the certificate. Please check that the certificate file is valid.".to_string(),
                )
            })?;

            client = client.add_root_certificate(reqwest_cert);
        }
        let client =
            client.build().map_err(|_err| RbsAdminClientError::ClientError("client init error".to_string()))?;
        Ok(Self { base_url: parsed_base_url, bearer_token: bearer_token.to_string(), http_client: client })
    }

    pub(crate) fn bearer_token(&self) -> &str {
        &self.bearer_token
    }
}

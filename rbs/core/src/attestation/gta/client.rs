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

//! GTA REST API HTTP communication layer.
//!
//! Low-level HTTP client (`GtaRestClient`) for GTA REST API: TLS configuration,
//! timeouts, retries, and error mapping. Does not know about attestation
//! semantics — all paths and bodies are passed by callers.
//!
//! Also defines GTA REST API wire types and `GtaError`.

use reqwest::Client;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use rbs_api_types::config::AttestationRestConfig;
use rbs_api_types::error::RbsError;

// ── GTA REST API wire types (matching GTA service format) ──────────────────

/// GTA Challenge response from `GET /challenge`.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct GtaChallengeResponse {
    #[allow(dead_code)]
    pub(super) service_version: String,
    pub(super) nonce: String,
}

/// GTA Attest request body (RBS → GTA).
#[derive(Debug, Clone, Serialize)]
pub(super) struct GtaAttestRequest {
    pub(super) measurements: Vec<GtaMeasurement>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct GtaMeasurement {
    pub(super) node_id: String,
    pub(super) nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) nonce_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) token_fmt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) attester_data: Option<serde_json::Value>,
    pub(super) evidences: Vec<GtaEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct GtaEvidence {
    pub(super) attester_type: String,
    pub(super) evidence: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) policy_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ref_value_id: Option<String>,
}

/// GTA Attest response from `POST /attest`.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct GtaAttestResponse {
    #[allow(dead_code)]
    pub(super) service_version: String,
    pub(super) tokens: Vec<GtaToken>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct GtaToken {
    #[allow(dead_code)]
    pub(super) node_id: String,
    pub(super) token: String,
}

// ── GtaError ────────────────────────────────────────────────────────────────

/// GTA REST API errors.
#[derive(Debug)]
pub(super) enum GtaError {
    NetworkError(String),
    TimeoutError(String),
    ServerError { status: u16, body: String },
    ParseError(String),
    #[allow(dead_code)]
    ValidationError(String),
}

impl From<GtaError> for RbsError {
    fn from(err: GtaError) -> RbsError {
        match err {
            GtaError::NetworkError(msg) => {
                log::error!("Attestation provider network error: {}", msg);
                RbsError::AttestationProviderUnavailable
            }
            GtaError::TimeoutError(msg) => {
                log::error!("Attestation provider timeout: {}", msg);
                RbsError::ProviderTimeout
            }
            GtaError::ServerError { status, body } => {
                log::error!("Attestation provider server error ({}): {}", status, body);
                RbsError::AttestationProviderError { status, body }
            }
            GtaError::ParseError(context) => {
                log::error!("Attestation provider parse error: {}", context);
                RbsError::InternalUnexpected { context }
            }
            GtaError::ValidationError(msg) => {
                log::warn!("Attestation provider validation error: {}", msg);
                RbsError::InvalidParameter(msg)
            }
        }
    }
}

impl std::fmt::Display for GtaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GtaError::NetworkError(msg) => write!(f, "network error: {}", msg),
            GtaError::TimeoutError(msg) => write!(f, "timeout error: {}", msg),
            GtaError::ServerError { status, body } => write!(f, "server error ({}): {}", status, body),
            GtaError::ParseError(msg) => write!(f, "parse error: {}", msg),
            GtaError::ValidationError(msg) => write!(f, "validation error: {}", msg),
        }
    }
}

// ── GtaRestClient: HTTP Communication Layer ─────────────────────────────────

/// GTA REST API HTTP client.
///
/// Handles low-level HTTP communication: TLS configuration, timeouts,
/// retries, and error mapping. Does not know about attestation semantics.
#[derive(Debug, Clone)]
pub(super) struct GtaRestClient {
    config: AttestationRestConfig,
    client: Client,
    base_url: String,
}

impl GtaRestClient {
    pub(super) fn new(config: AttestationRestConfig) -> Self {
        let client = Self::build_client(&config);
        let base_url = config.base_url.trim_end_matches('/').to_string();
        Self { config, client, base_url }
    }

    fn build_client(config: &AttestationRestConfig) -> Client {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs as u64));
        if !config.tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if !config.ca_file.is_empty() {
            let cert = std::fs::read(&config.ca_file).expect("Failed to read CA certificate file");
            let cert = reqwest::Certificate::from_pem(&cert).expect("Failed to parse CA certificate");
            builder = builder.add_root_certificate(cert);
        }
        // Mutual TLS: load the client certificate + key as a reqwest Identity.
        // Mirrors attestation_agent::utils::client (with_tls_config): both files present
        // enables mTLS; validated as a pair in AttestationRestConfig::validate.
        if !config.client_cert_path.is_empty() && !config.client_key_path.is_empty() {
            let cert_pem = std::fs::read(&config.client_cert_path)
                .expect("Failed to read client certificate file");
            let key_pem = std::fs::read(&config.client_key_path)
                .expect("Failed to read client key file");
            let identity = reqwest::Identity::from_pkcs8_pem(&cert_pem, &key_pem)
                .expect("Failed to build client identity (cert/key must be PKCS#8 PEM)");
            builder = builder.identity(identity);
        }
        builder.build().expect("Failed to build HTTP client")
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    /// Capture GTA's raw error response body for transparent passthrough.
    /// Falls back to `"HTTP {status}"` only when the body cannot be read or is empty.
    async fn extract_error_body(resp: reqwest::Response, status: reqwest::StatusCode) -> String {
        let status_str = format!("HTTP {}", status);
        match resp.text().await {
            Ok(text) if !text.is_empty() => text,
            Ok(_) => status_str,
            Err(_) => status_str,
        }
    }

    /// GET request with retry logic.
    pub(super) async fn get<T: for<'de> serde::Deserialize<'de>>(&self, path: &str) -> Result<T, GtaError> {
        let url = self.url(path);
        let user_id = &self.config.credentials.user_id;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut req = self.client.get(&url);
            if !user_id.is_empty() { req = req.header("User-Id", user_id); }
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp.json().await.map_err(|e| {
                            log::error!("GTA GET {} response parse error: {}", url, e);
                            GtaError::ParseError(e.to_string())
                        });
                    } else if status.is_server_error() && attempt <= self.config.retries {
                        log::warn!("GTA GET {} returned {}, retrying ({}/{})", url, status, attempt, self.config.retries);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    } else {
                        let body = Self::extract_error_body(resp, status).await;
                        log::error!("GTA GET {} failed: HTTP {}", url, status);
                        return Err(GtaError::ServerError { status: status.as_u16(), body });
                    }
                }
                Err(e) if attempt <= self.config.retries => {
                    log::warn!("GTA GET {} network error ({}/{}), retrying: {}", url, attempt, self.config.retries, e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Err(e) => {
                    if e.is_timeout() {
                        log::error!("GTA GET {} timed out after {} retries", url, self.config.retries);
                        return Err(GtaError::TimeoutError(e.to_string()));
                    }
                    log::error!("GTA GET {} network error after {} retries: {}", url, self.config.retries, e);
                    return Err(GtaError::NetworkError(e.to_string()));
                }
            }
        }
    }

    /// POST request with JSON body and custom headers (User-Id + API-Key).
    pub(super) async fn post<T, B>(&self, path: &str, body: &B) -> Result<T, GtaError>
    where T: for<'de> serde::Deserialize<'de>, B: serde::Serialize {
        let url = self.url(path);
        let user_id = &self.config.credentials.user_id;
        let api_key = self.config.credentials.sub_api_key.get();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut req = self.client.post(&url);
            if !user_id.is_empty() { req = req.header("User-Id", user_id); }
            if self.config.credentials.api_key_auth && !api_key.is_empty() { req = req.header("API-Key", api_key); }
            match req.json(body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp.json().await.map_err(|e| {
                            log::error!("GTA POST {} response parse error: {}", url, e);
                            GtaError::ParseError(e.to_string())
                        });
                    } else if status.is_server_error() && attempt <= self.config.retries {
                        log::warn!("GTA POST {} returned {}, retrying ({}/{})", url, status, attempt, self.config.retries);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    } else {
                        let body = Self::extract_error_body(resp, status).await;
                        log::error!("GTA POST {} failed: HTTP {}", url, status);
                        return Err(GtaError::ServerError { status: status.as_u16(), body });
                    }
                }
                Err(e) if attempt <= self.config.retries => {
                    log::warn!("GTA POST {} network error ({}/{}), retrying: {}", url, attempt, self.config.retries, e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Err(e) => {
                    if e.is_timeout() {
                        log::error!("GTA POST {} timed out after {} retries", url, self.config.retries);
                        return Err(GtaError::TimeoutError(e.to_string()));
                    }
                    log::error!("GTA POST {} network error after {} retries: {}", url, self.config.retries, e);
                    return Err(GtaError::NetworkError(e.to_string()));
                }
            }
        }
    }

    /// GET request with query parameters for management operations (User-Id + main_api_key).
    pub(super) async fn get_mgmt_with_query<T, Q>(&self, path: &str, query: &Q) -> Result<T, GtaError>
    where T: for<'de> serde::Deserialize<'de>, Q: serde::Serialize {
        let url = self.url(path);
        let user_id = &self.config.credentials.user_id;
        let api_key = self.config.credentials.main_api_key.get();
        let mut req = self.client.get(&url).query(query);
        if !user_id.is_empty() { req = req.header("User-Id", user_id); }
        if self.config.credentials.api_key_auth && !api_key.is_empty() { req = req.header("API-Key", api_key); }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    resp.json().await.map_err(|e| {
                        log::error!("GTA GET {} response parse error: {}", url, e);
                        GtaError::ParseError(e.to_string())
                    })
                } else {
                    let body = Self::extract_error_body(resp, status).await;
                    log::error!("GTA GET {} failed: HTTP {}", url, status);
                    Err(GtaError::ServerError { status: status.as_u16(), body })
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    log::error!("GTA GET {} timed out", url);
                    Err(GtaError::TimeoutError(e.to_string()))
                } else {
                    log::error!("GTA GET {} network error: {}", url, e);
                    Err(GtaError::NetworkError(e.to_string()))
                }
            }
        }
    }

    /// Core write helper for management POST/PUT/DELETE (User-Id + main_api_key).
    ///
    /// Does NOT retry. Write operations (especially POST) are not idempotent:
    /// if GTA already processed the request but the response was lost, a retry
    /// could create duplicates or trigger spurious 404s. The caller receives
    /// the raw error and can surface it to the user, who may manually verify
    /// (e.g. GET the resource) before deciding to retry.
    async fn send_write_mgmt<B>(&self, method: Method, path: &str, body: &B) -> Result<reqwest::Response, GtaError>
    where B: serde::Serialize {
        let url = self.url(path);
        let user_id = &self.config.credentials.user_id;
        let api_key = self.config.credentials.main_api_key.get();
        let mut req = self.client.request(method.clone(), &url);
        if !user_id.is_empty() { req = req.header("User-Id", user_id); }
        if self.config.credentials.api_key_auth && !api_key.is_empty() { req = req.header("API-Key", api_key); }
        match req.json(body).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    Ok(resp)
                } else {
                    let body = Self::extract_error_body(resp, status).await;
                    log::error!("GTA {} {} failed: HTTP {}", method, url, status);
                    Err(GtaError::ServerError { status: status.as_u16(), body })
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    log::error!("GTA {} {} timed out", method, url);
                    Err(GtaError::TimeoutError(e.to_string()))
                } else {
                    log::error!("GTA {} {} network error: {}", method, url, e);
                    Err(GtaError::NetworkError(e.to_string()))
                }
            }
        }
    }

    /// Management POST; carries User-Id + main_api_key, deserializes response body as `T`.
    pub(super) async fn post_mgmt<T, B>(&self, path: &str, body: &B) -> Result<T, GtaError>
    where T: for<'de> serde::Deserialize<'de>, B: serde::Serialize {
        let resp = self.send_write_mgmt(Method::POST, path, body).await?;
        resp.json().await.map_err(|e| {
            log::error!("GTA POST {} response parse error: {}", self.url(path), e);
            GtaError::ParseError(e.to_string())
        })
    }

    /// Management PUT; carries User-Id + main_api_key, deserializes response body as `T`.
    pub(super) async fn put_mgmt<T, B>(&self, path: &str, body: &B) -> Result<T, GtaError>
    where T: for<'de> serde::Deserialize<'de>, B: serde::Serialize {
        let resp = self.send_write_mgmt(Method::PUT, path, body).await?;
        resp.json().await.map_err(|e| {
            log::error!("GTA PUT {} response parse error: {}", self.url(path), e);
            GtaError::ParseError(e.to_string())
        })
    }

    /// Management DELETE; carries User-Id + main_api_key; GTA returns 204 (no content).
    pub(super) async fn delete_mgmt<B>(&self, path: &str, body: &B) -> Result<(), GtaError>
    where B: serde::Serialize {
        self.send_write_mgmt(Method::DELETE, path, body).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GTA returning a non-2xx with a body maps to AttestationProviderError,
    /// forwarding GTA's status code and the raw body verbatim.
    #[test]
    fn server_error_maps_to_forwarded_status_and_body() {
        let err: RbsError = GtaError::ServerError {
            status: 400,
            body: "{\"message\":\"bad evidence\"}".to_string(),
        }
        .into();
        match err {
            RbsError::AttestationProviderError { status, ref body } => {
                assert_eq!(status, 400);
                assert_eq!(body, "{\"message\":\"bad evidence\"}");
            }
            other => panic!("expected AttestationProviderError, got {:?}", other),
        }
        // status forwarded verbatim, body wrapped in the error message
        assert_eq!(err.http_status(), 400);
        assert_eq!(
            err.external_message(),
            "attestation provider error: {\"message\":\"bad evidence\"}"
        );
    }

    /// Network-layer failures (GTA unreachable) map to 503 + static message.
    #[test]
    fn network_error_maps_to_unavailable_503() {
        let err: RbsError = GtaError::NetworkError("connection refused".to_string()).into();
        assert_eq!(err.http_status(), 503);
        assert_eq!(err.external_message(), "service temporarily unavailable");
    }

    /// Empty upstream body falls back to "HTTP {status}".
    #[test]
    fn server_error_empty_body_falls_back_to_http_status_label() {
        let err: RbsError = GtaError::ServerError {
            status: 500,
            body: "HTTP 500".to_string(),
        }
        .into();
        assert_eq!(err.http_status(), 500);
        assert_eq!(err.external_message(), "attestation provider error: HTTP 500");
    }
}

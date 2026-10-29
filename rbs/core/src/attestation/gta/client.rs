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

/// Maximum number of upstream error-body bytes included in a single log
/// line. The full body is still forwarded to the API client via
/// [`RbsError::AttestationProviderError`]; only log output is truncated so
/// upstream internals (e.g. Java stack traces, database errors) do not land
/// verbatim in error-level logs. Matches the Vault adapter's minimum body
/// cap granularity.
const LOG_BODY_MAX_BYTES: usize = 1024;

/// Truncate an upstream error body for logging.
///
/// Truncation is char-boundary safe and annotated with the original length.
fn truncate_for_log(body: &str) -> std::borrow::Cow<'_, str> {
    if body.len() <= LOG_BODY_MAX_BYTES {
        return std::borrow::Cow::Borrowed(body);
    }
    let mut end = LOG_BODY_MAX_BYTES;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!("{}...[truncated; {} bytes total]", &body[..end], body.len()))
}

/// GTA REST API errors.
#[derive(Debug)]
pub(super) enum GtaError {
    NetworkError(String),
    TimeoutError(String),
    ServerError {
        status: u16,
        body: String,
    },
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
            },
            GtaError::TimeoutError(msg) => {
                log::error!("Attestation provider timeout: {}", msg);
                RbsError::ProviderTimeout
            },
            GtaError::ServerError { status, body } => {
                // Log a capped view; the full body still reaches the API
                // client through AttestationProviderError below.
                log::error!("Attestation provider server error ({}): {}", status, truncate_for_log(&body));
                RbsError::AttestationProviderError { status, body }
            },
            GtaError::ParseError(context) => {
                log::error!("Attestation provider parse error: {}", context);
                RbsError::InternalUnexpected { context }
            },
            GtaError::ValidationError(msg) => {
                log::warn!("Attestation provider validation error: {}", msg);
                RbsError::InvalidParameter(msg)
            },
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
        let mut builder = Client::builder().timeout(Duration::from_secs(config.timeout_secs as u64));
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
            let cert_pem = std::fs::read(&config.client_cert_path).expect("Failed to read client certificate file");
            let key_pem = std::fs::read(&config.client_key_path).expect("Failed to read client key file");
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
            if !user_id.is_empty() {
                req = req.header("User-Id", user_id);
            }
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp.json().await.map_err(|e| {
                            log::error!("GTA GET {} response parse error: {}", url, e);
                            GtaError::ParseError(e.to_string())
                        });
                    } else if status.is_server_error() && attempt <= self.config.retries {
                        log::warn!(
                            "GTA GET {} returned {}, retrying ({}/{})",
                            url,
                            status,
                            attempt,
                            self.config.retries
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    } else {
                        let body = Self::extract_error_body(resp, status).await;
                        log::error!("GTA GET {} failed: HTTP {}", url, status);
                        return Err(GtaError::ServerError { status: status.as_u16(), body });
                    }
                },
                Err(e) if attempt <= self.config.retries => {
                    log::warn!("GTA GET {} network error ({}/{}), retrying: {}", url, attempt, self.config.retries, e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                },
                Err(e) => {
                    if e.is_timeout() {
                        log::error!("GTA GET {} timed out after {} retries", url, self.config.retries);
                        return Err(GtaError::TimeoutError(e.to_string()));
                    }
                    log::error!("GTA GET {} network error after {} retries: {}", url, self.config.retries, e);
                    return Err(GtaError::NetworkError(e.to_string()));
                },
            }
        }
    }

    /// POST request with JSON body and custom headers (User-Id + API-Key).
    pub(super) async fn post<T, B>(&self, path: &str, body: &B) -> Result<T, GtaError>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        let url = self.url(path);
        let user_id = &self.config.credentials.user_id;
        let api_key = self.config.credentials.sub_api_key.get();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut req = self.client.post(&url);
            if !user_id.is_empty() {
                req = req.header("User-Id", user_id);
            }
            if self.config.credentials.api_key_auth && !api_key.is_empty() {
                req = req.header("API-Key", api_key);
            }
            match req.json(body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp.json().await.map_err(|e| {
                            log::error!("GTA POST {} response parse error: {}", url, e);
                            GtaError::ParseError(e.to_string())
                        });
                    } else if status.is_server_error() && attempt <= self.config.retries {
                        log::warn!(
                            "GTA POST {} returned {}, retrying ({}/{})",
                            url,
                            status,
                            attempt,
                            self.config.retries
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    } else {
                        let body = Self::extract_error_body(resp, status).await;
                        log::error!("GTA POST {} failed: HTTP {}", url, status);
                        return Err(GtaError::ServerError { status: status.as_u16(), body });
                    }
                },
                Err(e) if attempt <= self.config.retries => {
                    log::warn!("GTA POST {} network error ({}/{}), retrying: {}", url, attempt, self.config.retries, e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                },
                Err(e) => {
                    if e.is_timeout() {
                        log::error!("GTA POST {} timed out after {} retries", url, self.config.retries);
                        return Err(GtaError::TimeoutError(e.to_string()));
                    }
                    log::error!("GTA POST {} network error after {} retries: {}", url, self.config.retries, e);
                    return Err(GtaError::NetworkError(e.to_string()));
                },
            }
        }
    }

    /// GET request with query parameters for management operations (User-Id + main_api_key).
    pub(super) async fn get_mgmt_with_query<T, Q>(&self, path: &str, query: &Q) -> Result<T, GtaError>
    where
        T: for<'de> serde::Deserialize<'de>,
        Q: serde::Serialize,
    {
        let url = self.url(path);
        let user_id = &self.config.credentials.user_id;
        let api_key = self.config.credentials.main_api_key.get();
        let mut req = self.client.get(&url).query(query);
        if !user_id.is_empty() {
            req = req.header("User-Id", user_id);
        }
        if self.config.credentials.api_key_auth && !api_key.is_empty() {
            req = req.header("API-Key", api_key);
        }
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
            },
            Err(e) => {
                if e.is_timeout() {
                    log::error!("GTA GET {} timed out", url);
                    Err(GtaError::TimeoutError(e.to_string()))
                } else {
                    log::error!("GTA GET {} network error: {}", url, e);
                    Err(GtaError::NetworkError(e.to_string()))
                }
            },
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
    where
        B: serde::Serialize,
    {
        let url = self.url(path);
        let user_id = &self.config.credentials.user_id;
        let api_key = self.config.credentials.main_api_key.get();
        let mut req = self.client.request(method.clone(), &url);
        if !user_id.is_empty() {
            req = req.header("User-Id", user_id);
        }
        if self.config.credentials.api_key_auth && !api_key.is_empty() {
            req = req.header("API-Key", api_key);
        }
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
            },
            Err(e) => {
                if e.is_timeout() {
                    log::error!("GTA {} {} timed out", method, url);
                    Err(GtaError::TimeoutError(e.to_string()))
                } else {
                    log::error!("GTA {} {} network error: {}", method, url, e);
                    Err(GtaError::NetworkError(e.to_string()))
                }
            },
        }
    }

    /// Management POST; carries User-Id + main_api_key, deserializes response body as `T`.
    pub(super) async fn post_mgmt<T, B>(&self, path: &str, body: &B) -> Result<T, GtaError>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        let resp = self.send_write_mgmt(Method::POST, path, body).await?;
        resp.json().await.map_err(|e| {
            log::error!("GTA POST {} response parse error: {}", self.url(path), e);
            GtaError::ParseError(e.to_string())
        })
    }

    /// Management PUT; carries User-Id + main_api_key, deserializes response body as `T`.
    pub(super) async fn put_mgmt<T, B>(&self, path: &str, body: &B) -> Result<T, GtaError>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        let resp = self.send_write_mgmt(Method::PUT, path, body).await?;
        resp.json().await.map_err(|e| {
            log::error!("GTA PUT {} response parse error: {}", self.url(path), e);
            GtaError::ParseError(e.to_string())
        })
    }

    /// Management DELETE; carries User-Id + main_api_key; GTA returns 204 (no content).
    pub(super) async fn delete_mgmt<B>(&self, path: &str, body: &B) -> Result<(), GtaError>
    where
        B: serde::Serialize,
    {
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
        let err: RbsError =
            GtaError::ServerError { status: 400, body: "{\"message\":\"bad evidence\"}".to_string() }.into();
        match err {
            RbsError::AttestationProviderError { status, ref body } => {
                assert_eq!(status, 400);
                assert_eq!(body, "{\"message\":\"bad evidence\"}");
            },
            other => panic!("expected AttestationProviderError, got {:?}", other),
        }
        // status forwarded verbatim, body wrapped in the error message
        assert_eq!(err.http_status(), 400);
        assert_eq!(err.external_message(), "attestation provider error: {\"message\":\"bad evidence\"}");
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
        let err: RbsError = GtaError::ServerError { status: 500, body: "HTTP 500".to_string() }.into();
        assert_eq!(err.http_status(), 500);
        assert_eq!(err.external_message(), "attestation provider error: HTTP 500");
    }

    /// Bodies within the cap are logged verbatim (no marker appended).
    #[test]
    fn truncate_for_log_keeps_short_bodies_verbatim() {
        assert_eq!(truncate_for_log("short"), "short");
        let exactly_cap = "y".repeat(LOG_BODY_MAX_BYTES);
        assert_eq!(truncate_for_log(&exactly_cap).as_ref(), exactly_cap);
    }

    /// Bodies beyond the cap are cut at LOG_BODY_MAX_BYTES and annotated.
    #[test]
    fn truncate_for_log_caps_long_bodies_with_marker() {
        let body = "x".repeat(5 * LOG_BODY_MAX_BYTES);
        let truncated = truncate_for_log(&body);
        assert!(truncated.starts_with(&"x".repeat(LOG_BODY_MAX_BYTES)));
        assert!(truncated.contains(&format!("[truncated; {} bytes total]", body.len())));
        assert!(truncated.len() < LOG_BODY_MAX_BYTES + 128);
    }

    /// Truncation lands on a UTF-8 char boundary even when the cap splits a
    /// multi-byte character (slicing at a non-boundary would panic).
    #[test]
    fn truncate_for_log_is_char_boundary_safe() {
        // '€' is 3 bytes; with a 1024-byte cap the cut lands mid-character.
        let body = "€".repeat(2000);
        let truncated = truncate_for_log(&body);
        assert!(truncated.starts_with('€'));
        assert!(truncated.ends_with(']'));
    }

    /// The log view is capped while the client-facing passthrough body stays
    /// complete — truncation applies to logging only.
    #[test]
    fn long_error_body_is_truncated_in_logs_but_forwarded_in_full() {
        let long_body = "S".repeat(4 * LOG_BODY_MAX_BYTES);
        let err: RbsError = GtaError::ServerError { status: 502, body: long_body.clone() }.into();
        match err {
            RbsError::AttestationProviderError { status, body } => {
                assert_eq!(status, 502);
                assert_eq!(body.len(), long_body.len(), "passthrough body must remain complete");
            },
            other => panic!("expected AttestationProviderError, got {:?}", other),
        }
        assert!(truncate_for_log(&long_body).len() < LOG_BODY_MAX_BYTES + 128);
    }

    // ── HTTP layer (wiremock) ──

    use rbs_api_types::config::{AttestationCredentials, Sensitive};
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config(base_url: &str, retries: u32, api_key_auth: bool) -> AttestationRestConfig {
        AttestationRestConfig {
            base_url: base_url.to_string(),
            timeout_secs: 5,
            retries,
            tls_verify: false,
            ca_file: String::new(),
            client_cert_path: String::new(),
            client_key_path: String::new(),
            credentials: AttestationCredentials {
                user_id: "user-1".to_string(),
                api_key_auth,
                main_api_key: Sensitive::new(format!("m.{}", "a".repeat(32))),
                sub_api_key: Sensitive::new(format!("s.{}", "b".repeat(32))),
            },
        }
    }

    /// GET decodes a successful response and sends the `User-Id` header.
    #[tokio::test]
    async fn get_returns_decoded_body_with_user_id_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/challenge"))
            .and(header("User-Id", "user-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "service_version": "1.0",
                "nonce": "nonce-1"
            })))
            .mount(&server)
            .await;

        let client = GtaRestClient::new(test_config(&server.uri(), 0, false));
        let body: GtaChallengeResponse = client.get("/challenge").await.expect("get challenge");
        assert_eq!(body.nonce, "nonce-1");
    }

    /// Non-2xx GET responses are surfaced as `ServerError` with the raw body.
    #[tokio::test]
    async fn get_forwards_server_error_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("missing baseline"))
            .mount(&server)
            .await;

        let client = GtaRestClient::new(test_config(&server.uri(), 0, false));
        match client.get::<serde_json::Value>("/ref_value/x").await {
            Err(GtaError::ServerError { status, body }) => {
                assert_eq!(status, 404);
                assert_eq!(body, "missing baseline");
            },
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    /// A 2xx response with an undecodable body maps to `ParseError`.
    #[tokio::test]
    async fn get_maps_invalid_json_to_parse_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
            .mount(&server)
            .await;

        let client = GtaRestClient::new(test_config(&server.uri(), 0, false));
        assert!(matches!(client.get::<GtaChallengeResponse>("/challenge").await, Err(GtaError::ParseError(_))));
    }

    /// POST sends the sub API key when API-key auth is enabled.
    #[tokio::test]
    async fn post_sends_sub_api_key_and_decodes_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/attest"))
            .and(header("User-Id", "user-1"))
            .and(header("API-Key", format!("s.{}", "b".repeat(32))))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "service_version": "1.0",
                "tokens": [{"node_id": "node-1", "token": "token-1"}]
            })))
            .mount(&server)
            .await;

        let client = GtaRestClient::new(test_config(&server.uri(), 0, true));
        let body: GtaAttestResponse =
            client.post("/attest", &serde_json::json!({"measurements": []})).await.expect("post attest");
        assert_eq!(body.tokens[0].token, "token-1");
    }

    /// POST forwards GTA's error status and body without retrying.
    #[tokio::test]
    async fn post_forwards_error_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad evidence"))
            .mount(&server)
            .await;

        let client = GtaRestClient::new(test_config(&server.uri(), 3, false));
        match client.post::<serde_json::Value, _>("/attest", &serde_json::json!({})).await {
            Err(GtaError::ServerError { status, body }) => {
                assert_eq!(status, 400);
                assert_eq!(body, "bad evidence");
            },
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    /// Management GET serializes query parameters and sends the main API key.
    #[tokio::test]
    async fn get_mgmt_with_query_sends_query_and_main_api_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ref_value"))
            .and(query_param("attester_type", "tpm"))
            .and(header("API-Key", format!("m.{}", "a".repeat(32))))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"total_count": 1})))
            .mount(&server)
            .await;

        let client = GtaRestClient::new(test_config(&server.uri(), 0, true));
        let body: serde_json::Value =
            client.get_mgmt_with_query("/ref_value", &[("attester_type", "tpm")]).await.expect("get mgmt");
        assert_eq!(body["total_count"], 1);
    }

    /// Management GET maps transport failures to `NetworkError`.
    #[tokio::test]
    async fn get_mgmt_maps_unreachable_host_to_transport_error() {
        let mut config = test_config("http://127.0.0.1:1", 0, false);
        config.timeout_secs = 1;
        let client = GtaRestClient::new(config);
        assert!(matches!(
            client.get_mgmt_with_query::<serde_json::Value, _>("/ref_value", &[("page", "1")]).await,
            Err(GtaError::NetworkError(_) | GtaError::TimeoutError(_))
        ));
    }

    /// Management POST/PUT decode their responses; DELETE accepts 204.
    #[tokio::test]
    async fn management_writes_handle_success_responses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ref_value"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": "rv-1"})))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/ref_value/rv-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "rv-1"})))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/ref_value/rv-1"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let client = GtaRestClient::new(test_config(&server.uri(), 0, false));
        let created: serde_json::Value =
            client.post_mgmt("/ref_value", &serde_json::json!({"name": "rv"})).await.expect("post mgmt");
        assert_eq!(created["id"], "rv-1");
        let updated: serde_json::Value =
            client.put_mgmt("/ref_value/rv-1", &serde_json::json!({"name": "rv"})).await.expect("put mgmt");
        assert_eq!(updated["id"], "rv-1");
        client.delete_mgmt("/ref_value/rv-1", &serde_json::json!({})).await.expect("delete mgmt");
    }

    /// A 5xx response is retried when `retries` allows it, then succeeds.
    #[tokio::test]
    async fn get_retries_server_errors_until_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/challenge"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "service_version": "1.0",
                "nonce": "after-retry"
            })))
            .mount(&server)
            .await;

        let client = GtaRestClient::new(test_config(&server.uri(), 1, false));
        let body: GtaChallengeResponse = client.get("/challenge").await.expect("retry then success");
        assert_eq!(body.nonce, "after-retry");
    }

    /// POST retries a 5xx response and then decodes the successful body.
    #[tokio::test]
    async fn post_retries_server_errors_until_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/attest"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/attest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "service_version": "1.0",
                "tokens": [{"node_id": "n", "token": "retried"}]
            })))
            .mount(&server)
            .await;

        let client = GtaRestClient::new(test_config(&server.uri(), 1, false));
        let body: GtaAttestResponse =
            client.post("/attest", &serde_json::json!({})).await.expect("retry then success");
        assert_eq!(body.tokens[0].token, "retried");
    }

    /// A CA bundle is loaded into the client; unreadable files panic at construction.
    #[test]
    fn build_client_loads_ca_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        write_self_signed_cert(&ca_path);

        let mut config = test_config("https://127.0.0.1:1", 0, false);
        config.ca_file = ca_path.to_string_lossy().to_string();
        let _client = GtaRestClient::new(config);
    }

    /// Invalid CA material fails fast when the HTTP client is built.
    #[test]
    #[should_panic(expected = "Failed to parse CA certificate")]
    fn build_client_rejects_invalid_ca_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, b"not a certificate").expect("write");

        let mut config = test_config("https://127.0.0.1:1", 0, false);
        config.ca_file = ca_path.to_string_lossy().to_string();
        let _client = GtaRestClient::new(config);
    }

    /// mTLS client cert + key are loaded as a reqwest identity.
    #[test]
    fn build_client_loads_client_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("client.key");
        write_self_signed_cert_and_key(&cert_path, &key_path);

        let mut config = test_config("https://127.0.0.1:1", 0, false);
        config.client_cert_path = cert_path.to_string_lossy().to_string();
        config.client_key_path = key_path.to_string_lossy().to_string();
        let _client = GtaRestClient::new(config);
    }

    fn write_self_signed_cert(path: &std::path::Path) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509NameBuilder, X509};

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", "localhost").expect("cn");
        let name = name.build();
        let mut builder = X509::builder().expect("x509");
        builder.set_version(2).expect("version");
        let serial = openssl::bn::BigNum::from_u32(1).expect("serial").to_asn1_integer().expect("int");
        builder.set_serial_number(&serial).expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&key).expect("pubkey");
        builder.set_not_before(&Asn1Time::days_from_now(0).expect("nb")).expect("nb");
        builder.set_not_after(&Asn1Time::days_from_now(1).expect("na")).expect("na");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        std::fs::write(path, builder.build().to_pem().expect("pem")).expect("write cert");
    }

    fn write_self_signed_cert_and_key(cert_path: &std::path::Path, key_path: &std::path::Path) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509NameBuilder, X509};

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", "localhost").expect("cn");
        let name = name.build();
        let mut builder = X509::builder().expect("x509");
        builder.set_version(2).expect("version");
        let serial = openssl::bn::BigNum::from_u32(2).expect("serial").to_asn1_integer().expect("int");
        builder.set_serial_number(&serial).expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&key).expect("pubkey");
        builder.set_not_before(&Asn1Time::days_from_now(0).expect("nb")).expect("nb");
        builder.set_not_after(&Asn1Time::days_from_now(1).expect("na")).expect("na");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        std::fs::write(cert_path, builder.build().to_pem().expect("pem")).expect("write cert");
        std::fs::write(key_path, key.private_key_to_pem_pkcs8().expect("key pem")).expect("write key");
    }

    /// Management writes forward GTA error statuses and map transport failures.
    #[tokio::test]
    async fn management_writes_forward_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(409).set_body_string("already exists"))
            .mount(&server)
            .await;
        let client = GtaRestClient::new(test_config(&server.uri(), 0, false));
        match client.post_mgmt::<serde_json::Value, _>("/ref_value", &serde_json::json!({})).await {
            Err(GtaError::ServerError { status, body }) => {
                assert_eq!(status, 409);
                assert_eq!(body, "already exists");
            },
            other => panic!("expected ServerError, got {other:?}"),
        }

        let mut config = test_config("http://127.0.0.1:1", 0, false);
        config.timeout_secs = 1;
        let unreachable = GtaRestClient::new(config);
        assert!(matches!(
            unreachable.post_mgmt::<serde_json::Value, _>("/ref_value", &serde_json::json!({})).await,
            Err(GtaError::NetworkError(_) | GtaError::TimeoutError(_))
        ));
        assert!(matches!(
            unreachable.put_mgmt::<serde_json::Value, _>("/ref_value/x", &serde_json::json!({})).await,
            Err(GtaError::NetworkError(_) | GtaError::TimeoutError(_))
        ));
        assert!(matches!(
            unreachable.delete_mgmt("/ref_value/x", &serde_json::json!({})).await,
            Err(GtaError::NetworkError(_) | GtaError::TimeoutError(_))
        ));
    }
}

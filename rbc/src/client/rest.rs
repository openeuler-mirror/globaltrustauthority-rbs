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

use rbs_api_types::{AttestRequest, AttestResponse, AuthChallengeResponse, ResourceContentResponse};
use reqwest::{Client as HttpClient, Url};
use std::collections::HashMap;

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
        let mut builder = HttpClient::builder().use_rustls_tls().min_tls_version(reqwest::tls::Version::TLS_1_3);

        if let Some(tls_cfg) = tls {
            if let Some(ca_path) = &tls_cfg.ca_cert {
                let ca_pem =
                    std::fs::read(ca_path).map_err(|e| RbcError::TlsError(format!("read CA cert {ca_path}: {e}")))?;
                let cert = reqwest::Certificate::from_pem(&ca_pem)
                    .map_err(|e| RbcError::TlsError(format!("parse CA cert: {e}")))?;
                builder = builder.add_root_certificate(cert);
            }
        }

        if let Some(secs) = timeout_secs {
            builder = builder.timeout(std::time::Duration::from_secs(secs));
        }

        let http = builder.build().map_err(|e| RbcError::TlsError(e.to_string()))?;

        Ok(Self { base_url: base_url.trim_end_matches('/').to_string(), http })
    }

    /// GET /rbs/v0/challenge → AuthChallengeResponse
    pub async fn get_nonce(&self, provider: Option<String>) -> Result<AuthChallengeResponse, RbcError> {
        let url = format!("{}/rbs/v0/challenge", self.base_url);

        // extend url if specify provider: rbs/v0/challenge?as_provider={provider}
        let mut request_builder = self.http.get(&url);
        if let Some(p) = provider {
            request_builder = request_builder.query(&[("as_provider", &p)]);
        }
        let resp = request_builder.send().await.map_err(|e| RbcError::NetworkError(e.to_string()))?;
        Self::handle_response(resp).await
    }

    /// POST /rbs/v0/attest → AttestResponse
    pub async fn post_attest(
        &self,
        req: &AttestRequest,
        extra_headers: &HashMap<&str, &str>,
    ) -> Result<AttestResponse, RbcError> {
        let url = format!("{}/rbs/v0/attest", self.base_url);
        let mut builder = self.http.post(&url).json(req);
        for (name, value) in extra_headers {
            builder = builder.header(*name, *value);
        }
        let resp = builder.send().await.map_err(|e| RbcError::NetworkError(e.to_string()))?;
        Self::handle_response(resp).await
    }

    /// GET /rbs/v0/{uri} + Authorization header → ResourceContentResponse
    pub async fn get_resource(&self, uri: &str, token: &str) -> Result<ResourceContentResponse, RbcError> {
        let url = self.resource_url(uri, None)?;
        let resp = self
            .http
            .get(url)
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
        let url = self.resource_url(uri, Some("retrieve"))?;
        let resp =
            self.http.post(url).json(evidence).send().await.map_err(|e| RbcError::NetworkError(e.to_string()))?;
        Self::handle_response(resp).await
    }

    fn resource_url(&self, uri: &str, suffix: Option<&str>) -> Result<Url, RbcError> {
        let segments = Self::validate_resource_uri(uri)?;
        let mut url = Url::parse(&format!("{}/rbs/v0/", self.base_url))
            .map_err(|e| RbcError::InvalidInput(format!("invalid RBS base URL: {e}")))?;

        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| RbcError::InvalidInput("RBS base URL cannot be used as a path base".into()))?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
            if let Some(suffix) = suffix {
                path.push(suffix);
            }
        }

        Ok(url)
    }

    fn validate_resource_uri(uri: &str) -> Result<Vec<&str>, RbcError> {
        if uri.is_empty() {
            return Err(RbcError::InvalidInput("resource URI must not be empty".into()));
        }
        if uri.starts_with('/') || uri.ends_with('/') {
            return Err(RbcError::InvalidInput("resource URI must be a relative path without empty segments".into()));
        }
        if uri.contains(['?', '#', '\\', '%']) {
            return Err(RbcError::InvalidInput(
                "resource URI must not contain query, fragment, backslash, or percent encoding".into(),
            ));
        }

        let mut segments = Vec::new();
        for segment in uri.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(RbcError::InvalidInput(
                    "resource URI must not contain empty, '.', or '..' path segments".into(),
                ));
            }
            if segment.chars().any(char::is_control) {
                return Err(RbcError::InvalidInput("resource URI must not contain control characters".into()));
            }
            segments.push(segment);
        }

        Ok(segments)
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T, RbcError> {
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            resp.json::<T>().await.map_err(|e| RbcError::NetworkError(e.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const UNREACHABLE_BASE_URL: &str = "http://127.0.0.1:1";

    /// Write a self-signed certificate and return its path; the crate has no `tempfile`
    /// dev-dependency, so temp paths are derived from the process id and a caller-supplied name.
    fn self_signed_cert(name: &str) -> std::path::PathBuf {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509NameBuilder, X509};

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa keygen")).expect("pkey");
        let mut name_builder = X509NameBuilder::new().expect("x509 name");
        name_builder.append_entry_by_text("CN", "rbc-test-ca").expect("cn");
        let subject = name_builder.build();

        let mut builder = X509::builder().expect("x509 builder");
        builder.set_version(2).expect("version");
        let serial = openssl::bn::BigNum::from_u32(1).expect("serial").to_asn1_integer().expect("asn1 int");
        builder.set_serial_number(&serial).expect("serial");
        builder.set_subject_name(&subject).expect("subject");
        builder.set_issuer_name(&subject).expect("issuer");
        builder.set_pubkey(&key).expect("pubkey");
        builder.set_not_before(&Asn1Time::days_from_now(0).expect("not before")).expect("not before");
        builder.set_not_after(&Asn1Time::days_from_now(1).expect("not after")).expect("not after");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");

        let cert_path = std::env::temp_dir().join(format!("rbc-rest-ca-{}-{name}.pem", std::process::id()));
        std::fs::write(&cert_path, builder.build().to_pem().expect("cert pem")).expect("write cert");
        cert_path
    }

    fn temp_pem(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("rbc-rest-{}-{name}.pem", std::process::id()));
        std::fs::write(&path, contents).expect("write temp pem");
        path
    }

    #[tokio::test]
    async fn new_loads_custom_ca_certificate() {
        let cert_path = self_signed_cert("valid");
        let tls = TlsConfig { ca_cert: Some(cert_path.to_str().expect("utf8 path").to_string()) };

        RbsRestClient::new(UNREACHABLE_BASE_URL, Some(&tls), None).expect("valid CA certificate must be accepted");

        let _ = std::fs::remove_file(cert_path);
    }

    #[tokio::test]
    async fn new_reports_unreadable_ca_certificate() {
        let tls = TlsConfig { ca_cert: Some("/nonexistent/rbc-ca.pem".to_string()) };

        let err = RbsRestClient::new(UNREACHABLE_BASE_URL, Some(&tls), None).err().expect("missing CA must fail");
        assert!(matches!(err, RbcError::TlsError(_)), "expected TlsError, got {err:?}");
        assert!(err.to_string().contains("read CA cert"), "unexpected message: {err}");
    }

    #[tokio::test]
    async fn new_reports_unparsable_ca_certificate() {
        let cert_path = temp_pem("garbage", b"not a certificate\n");
        let tls = TlsConfig { ca_cert: Some(cert_path.to_str().expect("utf8 path").to_string()) };

        let err = RbsRestClient::new(UNREACHABLE_BASE_URL, Some(&tls), None).err().expect("invalid CA must fail");
        assert!(matches!(err, RbcError::TlsError(_)), "expected TlsError, got {err:?}");
        assert!(err.to_string().contains("parse CA cert"), "unexpected message: {err}");

        let _ = std::fs::remove_file(cert_path);
    }

    #[tokio::test]
    async fn new_applies_request_timeout() {
        RbsRestClient::new(UNREACHABLE_BASE_URL, None, Some(5)).expect("timeout must be accepted");
    }

    #[tokio::test]
    async fn get_nonce_sends_provider_query_parameter() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rbs/v0/challenge"))
            .and(query_param("as_provider", "gta"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"nonce": "provider-nonce"})))
            .mount(&server)
            .await;

        let client = RbsRestClient::new(&server.uri(), None, None).expect("client");
        let challenge = client.get_nonce(Some("gta".to_string())).await.expect("challenge");
        assert_eq!(challenge.nonce, "provider-nonce");
    }

    #[tokio::test]
    async fn get_resource_rejects_control_characters_in_uri() {
        let client = RbsRestClient::new(UNREACHABLE_BASE_URL, None, None).expect("client");

        let err = client.get_resource("vault/default/secret/ke\u{1}y", "token").await.err().expect("control char");
        assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
        assert!(err.to_string().contains("control characters"), "unexpected message: {err}");
    }

    #[tokio::test]
    async fn http_auth_statuses_map_to_auth_error() {
        for status in [401u16, 403] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rbs/v0/challenge"))
                .respond_with(ResponseTemplate::new(status).set_body_string("denied"))
                .mount(&server)
                .await;

            let client = RbsRestClient::new(&server.uri(), None, None).expect("client");
            let err = client.get_nonce(None).await.err().expect("auth status must fail");
            assert!(matches!(err, RbcError::AuthError(_)), "status {status}: expected AuthError, got {err:?}");
        }
    }

    #[tokio::test]
    async fn http_timeout_statuses_map_to_timeout_error() {
        for status in [408u16, 504] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rbs/v0/challenge"))
                .respond_with(ResponseTemplate::new(status).set_body_string("timeout"))
                .mount(&server)
                .await;

            let client = RbsRestClient::new(&server.uri(), None, None).expect("client");
            let err = client.get_nonce(None).await.err().expect("timeout status must fail");
            assert!(matches!(err, RbcError::TimeoutError(_)), "status {status}: expected TimeoutError, got {err:?}");
        }
    }

    #[tokio::test]
    async fn unknown_client_status_maps_to_attest_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rbs/v0/challenge"))
            .respond_with(ResponseTemplate::new(418).set_body_string("teapot"))
            .mount(&server)
            .await;

        let client = RbsRestClient::new(&server.uri(), None, None).expect("client");
        let err = client.get_nonce(None).await.err().expect("unexpected status must fail");
        assert!(matches!(err, RbcError::AttestError(_)), "expected AttestError, got {err:?}");
        assert!(err.to_string().contains("HTTP 418"), "unexpected message: {err}");
    }
}

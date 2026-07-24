use super::ResourceBackend;
use crate::resource::error::ResourceError;
use rbs_api_types::config::ResourceProviderConfig;
use std::time::Duration;
use zeroize::Zeroizing;

/// Fixed delay between Vault backend retry attempts (mirrors GTA attestation adapter).
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// VaultBackend - adapter for OpenBao / HashiCorp Vault.
pub struct VaultBackend {
    pub url: String,
    pub token: Zeroizing<String>,
    pub mount_path: String,
    pub kv_version: String,
    max_retries: u32,
    client: reqwest::Client,
}

impl std::fmt::Debug for VaultBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultBackend")
            .field("url", &self.url)
            .field("token", &"[redacted]")
            .field("mount_path", &self.mount_path)
            .field("kv_version", &self.kv_version)
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

impl VaultBackend {
    pub fn new(cfg: &ResourceProviderConfig) -> Self {
        let client = Self::build_client(cfg);
        Self {
            url: cfg.url.clone(),
            token: Zeroizing::new(cfg.token.get().clone()),
            mount_path: cfg.mount_path.clone(),
            kv_version: cfg.kv_version.clone(),
            max_retries: cfg.max_retries,
            client,
        }
    }

    /// Build the HTTP client, honouring timeout / TLS verification / connection
    /// pool limits from the backend config (previously discarded by `Client::new()`).
    fn build_client(cfg: &ResourceProviderConfig) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout as u64))
            .pool_max_idle_per_host(cfg.max_connections as usize);
        if !cfg.verify_ssl {
            builder = builder.danger_accept_invalid_certs(true);
        }
        builder.build().expect("Failed to build Vault HTTP client")
    }

    /// Extract path segments from a resource URI:
    ///   /rbs/v0/{provider}/{repo}/{type}/{name}
    /// Returns (repo_name, resource_type, resource_name).
    fn parse_uri_path(uri: &str) -> Result<(&str, &str, &str), ResourceError> {
        let path = uri.trim_start_matches("/rbs/v0/");
        let segments: Vec<&str> = path.splitn(4, '/').collect();
        if segments.len() < 4 {
            return Err(ResourceError::ParamInvalid { field: "uri" });
        }
        Ok((segments[1], segments[2], segments[3]))
    }

    /// Build the Vault API path for the given resource URI.
    fn build_vault_path(&self, uri: &str) -> Result<String, ResourceError> {
        let (repo, res_type, res_name) = Self::parse_uri_path(uri)?;
        let mount = self.mount_path.trim_matches('/');
        Ok(match self.kv_version.as_str() {
            "v2" => format!("/v1/{}/data/{}/{}/{}", mount, repo, res_type, res_name),
            _ => format!("/v1/{}/{}/{}/{}", mount, repo, res_type, res_name),
        })
    }

    /// Build the Vault metadata check path.
    fn build_check_path(&self, uri: &str) -> Result<String, ResourceError> {
        let (repo, res_type, res_name) = Self::parse_uri_path(uri)?;
        let mount = self.mount_path.trim_matches('/');
        Ok(match self.kv_version.as_str() {
            "v2" => format!("/v1/{}/metadata/{}/{}/{}", mount, repo, res_type, res_name),
            _ => format!("/v1/{}/{}/{}/{}", mount, repo, res_type, res_name),
        })
    }

    /// Issue a GET with retry semantics mirroring the GTA attestation adapter:
    /// retry on HTTP 5xx and on transport errors while attempts remain,
    /// sleeping `RETRY_INTERVAL` between attempts. 4xx responses are returned to
    /// the caller for status-specific handling (e.g. 404 -> "not found").
    async fn get_with_retry(&self, url: &str) -> Result<reqwest::Response, ResourceError> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self
                .client
                .get(url)
                .header("X-Vault-Token", self.token.as_str())
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_server_error() {
                        if attempt <= self.max_retries {
                            log::warn!(
                                "Vault GET {} returned {}, retrying (attempt {}/{})",
                                url,
                                status,
                                attempt,
                                self.max_retries
                            );
                            tokio::time::sleep(RETRY_INTERVAL).await;
                            continue;
                        }
                        let body = resp.text().await.unwrap_or_default();
                        log::error!(
                            "Vault GET {} failed after {} retries: HTTP {} {}",
                            url,
                            self.max_retries,
                            status,
                            body
                        );
                        return Err(ResourceError::BackendError {
                            detail: format!("Vault returned HTTP {}: {}", status.as_u16(), body),
                        });
                    }
                    return Ok(resp);
                }
                Err(e) if attempt <= self.max_retries => {
                    log::warn!(
                        "Vault GET {} network error (attempt {}/{}), retrying: {}",
                        url,
                        attempt,
                        self.max_retries,
                        e
                    );
                    tokio::time::sleep(RETRY_INTERVAL).await;
                    continue;
                }
                Err(e) => {
                    if e.is_timeout() {
                        log::error!(
                            "Vault GET {} timed out after {} retries",
                            url,
                            self.max_retries
                        );
                    } else {
                        log::error!("Vault GET {} network error: {}", url, e);
                    }
                    return Err(ResourceError::BackendError { detail: e.to_string() });
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl ResourceBackend for VaultBackend {
    async fn check_resource_exists(&self, uri: &str) -> Result<bool, ResourceError> {
        let check_path = self.build_check_path(uri)?;
        let url = format!("{}{}", self.url.trim_end_matches('/'), check_path);

        log::debug!("Vault check_resource_exists: GET {}", url);
        let resp = self.get_with_retry(&url).await?;

        match resp.status().as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            other => {
                let body = resp.text().await.unwrap_or_default();
                log::error!("Vault check_resource_exists returned HTTP {}: {}", other, body);
                Err(ResourceError::BackendError {
                    detail: format!("Vault returned HTTP {}: {}", other, body),
                })
            }
        }
    }

    async fn get_resource_content(&self, uri: &str) -> Result<Zeroizing<Vec<u8>>, ResourceError> {
        let data_path = self.build_vault_path(uri)?;
        let url = format!("{}{}", self.url.trim_end_matches('/'), data_path);

        log::debug!("Vault get_resource_content: GET {}", url);
        let resp = self.get_with_retry(&url).await?;

        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.text().await.unwrap_or_default();
            log::error!("Vault get_resource_content returned HTTP {}: {}", status, body);
            return Err(ResourceError::BackendError {
                detail: format!("Vault returned HTTP {}: {}", status, body),
            });
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| {
                log::error!("Vault get_resource_content response parse error: {}", e);
                ResourceError::BackendError { detail: e.to_string() }
            })?;

        // Extract data from Vault response
        // KV v2: { "data": { "data": { ... } } }
        // KV v1: { "data": { ... } }
        let data = if self.kv_version == "v2" {
            json.get("data")
                .and_then(|d| d.get("data"))
        } else {
            json.get("data")
        };

        let data = data.ok_or_else(|| {
            log::error!("Vault get_resource_content failed: response missing 'data' field for uri '{}'", uri);
            ResourceError::BackendError {
                detail: "Vault response missing 'data' field".to_string(),
            }
        })?;

        // Serialise the data map back to bytes
        let content = serde_json::to_vec(data)
            .map_err(|e| {
                log::error!("Vault get_resource_content failed: serde_json serialization error: {}", e);
                ResourceError::BackendError { detail: e.to_string() }
            })?;

        Ok(Zeroizing::new(content))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbs_api_types::Sensitive;
    use serde_json::json;
    use std::time::Instant;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(uri: &str, max_retries: u32) -> ResourceProviderConfig {
        ResourceProviderConfig {
            backend_type: "vault".to_string(),
            url: uri.to_string(),
            token: Sensitive::new("s.test".to_string()),
            mount_path: "secret".to_string(),
            kv_version: "v2".to_string(),
            verify_ssl: false,
            timeout: 30,
            max_connections: 10,
            max_retries,
        }
    }

    const URI: &str = "/rbs/v0/vault/repo1/type1/name1";
    const DATA_PATH: &str = "/v1/secret/data/repo1/type1/name1";

    /// UT-VB-01: max_retries=0 and Vault always returns 503 -> immediate failure,
    /// no retry, single HTTP call, no sleep.
    #[tokio::test]
    async fn ut_vb_01_no_retry_when_max_retries_zero() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path(DATA_PATH))
            .respond_with(ResponseTemplate::new(503).set_body_string("Vault is sealed"))
            .expect(1)
            .mount(&server)
            .await;

        let backend = VaultBackend::new(&cfg(&server.uri(), 0));
        let start = Instant::now();
        let result = backend.get_resource_content(URI).await;
        let elapsed = start.elapsed();

        assert!(matches!(result, Err(ResourceError::BackendError { .. })), "expected BackendError, got {:?}", result);
        assert!(elapsed.as_millis() < 4_900, "expected no retry sleep, took {:?}", elapsed);
        server.verify().await;
    }

    /// UT-VB-02: max_retries=1, Vault returns 503 once then 200 -> retried once
    /// (>=5s elapsed) and succeeds with content.
    #[tokio::test]
    async fn ut_vb_02_retry_then_success() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use wiremock::Request;

        let server = MockServer::start().await;
        // Single mock with a call-count responder: 503 on the first hit, 200 after.
        // (wiremock `expect` only verifies counts; it does not limit matching, so a
        //  two-mock approach cannot guarantee ordering — a counter responder can.)
        let counter = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET")).and(path(DATA_PATH))
            .respond_with(move |_req: &Request| {
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(503).set_body_string("Vault is sealed")
                } else {
                    ResponseTemplate::new(200)
                        .set_body_json(json!({ "data": { "data": { "secret": "value" } } }))
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        let backend = VaultBackend::new(&cfg(&server.uri(), 1));
        let start = Instant::now();
        let result = backend.get_resource_content(URI).await;
        let elapsed = start.elapsed();

        match &result {
            Ok(content) => assert!(!content.is_empty(), "content should not be empty"),
            Err(e) => panic!("expected Ok(content), got Err({:?})", e),
        }
        assert!(elapsed.as_millis() >= 4_900, "expected one 5s retry sleep, took {:?}", elapsed);
        server.verify().await;
    }

    /// UT-VB-03: 4xx (404) is not retried even with max_retries=2; check_resource_exists
    /// returns Ok(false) and only a single HTTP call is made.
    #[tokio::test]
    async fn ut_vb_03_client_error_not_retried() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/v1/secret/metadata/repo1/type1/name1"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let backend = VaultBackend::new(&cfg(&server.uri(), 2));
        let start = Instant::now();
        let result = backend.check_resource_exists(URI).await;
        let elapsed = start.elapsed();

        assert_eq!(result.unwrap(), false, "expected Ok(false) for 404");
        assert!(elapsed.as_millis() < 4_900, "expected no retry sleep for 404, took {:?}", elapsed);
        server.verify().await;
    }

    /// UT-VB-04: non-timeout transport error (connection refused) IS retried when
    /// max_retries>0, with the 5s backoff sleep between attempts. This matches the
    /// doc comment "retry on transport errors" and the manual test point
    /// RUST_GTA_RBS_TP_REL_Retry_001 (network error: temporary/recoverable).
    #[tokio::test]
    async fn ut_vb_04_non_timeout_network_error_retried() {
        use std::net::TcpListener;

        // Reserve an ephemeral port then release it so connections are refused
        // (a non-timeout transport error that should still be retried).
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        drop(listener);

        // max_retries=1 => 2 attempts with one 5s backoff sleep between them.
        let backend = VaultBackend::new(&cfg(&format!("http://{}", addr), 1));
        let start = Instant::now();
        let result = backend.get_resource_content(URI).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ResourceError::BackendError { .. })),
            "expected BackendError, got {:?}", result
        );
        assert!(
            elapsed.as_millis() >= 4_900,
            "expected one 5s retry sleep for non-timeout transport error, took {:?}", elapsed
        );
    }
}

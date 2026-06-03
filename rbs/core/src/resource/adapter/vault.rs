use super::ResourceBackend;
use crate::resource::error::ResourceError;

/// VaultBackend - adapter for OpenBao / HashiCorp Vault.
#[derive(Clone)]
pub struct VaultBackend {
    pub url: String,
    pub token: String,
    pub mount_path: String,
    pub kv_version: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for VaultBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultBackend")
            .field("url", &self.url)
            .field("mount_path", &self.mount_path)
            .field("kv_version", &self.kv_version)
            .finish()
    }
}

impl VaultBackend {
    pub fn new(url: String, token: String, mount_path: String, kv_version: String) -> Self {
        let client = reqwest::Client::new();
        Self { url, token, mount_path, kv_version, client }
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
}

#[async_trait::async_trait]
impl ResourceBackend for VaultBackend {
    async fn check_resource_exists(&self, uri: &str) -> Result<bool, ResourceError> {
        let check_path = self.build_check_path(uri)?;
        let url = format!("{}{}", self.url.trim_end_matches('/'), check_path);

        log::debug!("Vault check_resource_exists: GET {}", url);
        let client = self.client.clone();
        let resp = client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                log::error!("Vault check_resource_exists network error: {}", e);
                ResourceError::BackendError { detail: e.to_string() }
            })?;

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

    async fn get_resource_content(&self, uri: &str) -> Result<Vec<u8>, ResourceError> {
        let data_path = self.build_vault_path(uri)?;
        let url = format!("{}{}", self.url.trim_end_matches('/'), data_path);

        log::debug!("Vault get_resource_content: GET {}", url);
        let client = self.client.clone();
        let resp = client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                log::error!("Vault get_resource_content network error: {}", e);
                ResourceError::BackendError { detail: e.to_string() }
            })?;

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

        Ok(content)
    }
}

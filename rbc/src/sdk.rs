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

//! RBC SDK — Config / Client / Session with TeeKeyPair-based JWE envelope management.

use std::rc::Rc;
use std::sync::Arc;
use serde::Deserialize;
use serde_json::Value;
use base64::Engine;
use rbs_api_types::{AttestResponse, AttesterData, AuthChallengeResponse,
                    ResourceContentResponse, AttestRequest, RbcEvidencesPayload};
use zeroize::Zeroizing;

use crate::client::{RbsRestClient, TlsConfig};
use crate::error::RbcError;
use crate::evidence::{EvidenceProvider, NativeEvidenceProvider};
use crate::token::{TokenProvider, RbsAttestTokenProvider, NativeTokenProvider};
use crate::tools::tee_key::{KeyType, TeeKeyPair, TeePublicKey};

/// Selects the evidence or token provider implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    /// Built-in provider running in the same process.
    Native,
    /// Remote provider accessed via the RBS REST API.
    Rbs,
}

/// Raw provider configuration entry as deserialized from `rbc.yaml`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderRawConfig {
    #[serde(rename = "type")]
    pub provider_type: ProviderType,
    #[serde(default = "ProviderRawConfig::default_enabled")]
    pub enabled: bool,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, Value>,
}

impl ProviderRawConfig {
    fn default_enabled() -> bool { true }
}

/// RBS connection parameters, mapped from the `rbs:` block in `rbc.yaml`.
#[derive(Debug, Clone, Deserialize)]
pub struct RbsConfig {
    pub base_url: String,
    pub timeout_secs: Option<u64>,
    pub ca_cert: Option<String>,
}

/// Full RBC configuration, directly mirrors the structure of `rbc.yaml`.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub rbs: RbsConfig,
    pub evidence_provider: Option<Vec<ProviderRawConfig>>,
    pub token_provider: Option<Vec<ProviderRawConfig>>,
    #[serde(default)]
    pub key_algorithm: KeyType,
}

impl Config {
    /// Load configuration from a YAML file at `path`.
    pub fn from_file(path: &str) -> Result<Self, RbcError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RbcError::ConfigError(format!("read {path}: {e}")))?;
        serde_yaml::from_str(&content)
            .map_err(|e| RbcError::ConfigError(format!("parse {path}: {e}")))
    }

    /// Return a [`ConfigBuilder`] for constructing a [`Config`] programmatically.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Builder for [`Config`]; obtain one via [`Config::builder`].
#[derive(Default)]
pub struct ConfigBuilder {
    base_url: Option<String>,
    ca_cert: Option<String>,
    timeout_secs: Option<u64>,
    evidence_provider: Option<Vec<ProviderRawConfig>>,
    token_provider: Option<Vec<ProviderRawConfig>>,
    key_algorithm: Option<KeyType>,
}

impl ConfigBuilder {
    /// Set the RBS base URL (required).
    pub fn base_url(mut self, url: &str) -> Self {
        self.base_url = Some(url.to_string());
        self
    }
    /// Set the path to a custom CA certificate for TLS verification.
    pub fn ca_cert(mut self, path: &str) -> Self {
        self.ca_cert = Some(path.to_string());
        self
    }
    /// Set the request timeout in seconds.
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }
    /// Set the evidence provider configuration list.
    pub fn evidence_provider(mut self, ep: Vec<ProviderRawConfig>) -> Self {
        self.evidence_provider = Some(ep);
        self
    }
    /// Set the token provider configuration list.
    pub fn token_provider(mut self, tp: Vec<ProviderRawConfig>) -> Self {
        self.token_provider = Some(tp);
        self
    }
    /// Set the key algorithm used for ephemeral TEE key generation.
    pub fn key_algorithm(mut self, alg: KeyType) -> Self {
        self.key_algorithm = Some(alg);
        self
    }

    /// Build the [`Config`], returning an error if `base_url` was not set.
    pub fn build(self) -> Result<Config, RbcError> {
        let base_url = self.base_url
            .ok_or_else(|| RbcError::ConfigError("base_url is required".into()))?;
        Ok(Config {
            rbs: RbsConfig {
                base_url,
                ca_cert: self.ca_cert,
                timeout_secs: self.timeout_secs,
            },
            evidence_provider: self.evidence_provider,
            token_provider: self.token_provider,
            key_algorithm: self.key_algorithm.unwrap_or(KeyType::Rsa),
        })
    }
}

/// Specifies the authorization mode when calling [`Session::get_resource`].
pub enum GetResourceRequest<'a> {
    /// Authorize with a pre-obtained attest token.
    ByAttestToken(&'a str),
    /// Authorize by submitting raw evidence for inline attestation.
    ByEvidence { value: &'a Value },
}

pub struct Resource {
    pub uri: String,
    /// Raw content, possibly a JWE ciphertext; zeroed on `Drop`.
    pub content: Zeroizing<Vec<u8>>,
    pub content_type: Option<String>,
}

pub(crate) struct ClientInner {
    pub(crate) rest_client: RbsRestClient,
    pub(crate) evidence_provider: Option<Arc<dyn EvidenceProvider>>,
    pub(crate) token_provider: Option<Arc<dyn TokenProvider>>,
    pub(crate) key_type: KeyType,
    pub(crate) timeout_secs: Option<u64>,
    pub(crate) runtime: tokio::runtime::Runtime,
}

/// SDK entry point. Holds the RBS connection and provider state; not thread-safe (uses `Rc` internally).
/// Create one instance per thread.
pub struct Client {
    inner: Rc<ClientInner>,
    _marker: std::marker::PhantomData<*mut ()>,
}

impl Client {
    /// Create a `Client` from a [`Config`].
    pub fn new(config: Config) -> Result<Self, RbcError> {
        let tls = config.rbs.ca_cert.as_ref().map(|ca| TlsConfig {
            ca_cert: Some(ca.clone()),
        });
        let rest_client = RbsRestClient::new(
            &config.rbs.base_url,
            tls.as_ref(),
            config.rbs.timeout_secs,
        )?;

        let evidence_provider =
            Self::build_evidence_provider(config.evidence_provider)?;

        let token_provider =
            Self::build_token_provider(config.token_provider, &rest_client)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| RbcError::ConfigError(format!("build tokio runtime: {e}")))?;

        Ok(Self {
            inner: Rc::new(ClientInner {
                rest_client,
                evidence_provider,
                token_provider,
                key_type: config.key_algorithm,
                timeout_secs: config.rbs.timeout_secs,
                runtime,
            }),
            _marker: std::marker::PhantomData,
        })
    }

    /// Iterate the provider list and instantiate the first enabled entry.
    fn build_evidence_provider(
        providers: Option<Vec<ProviderRawConfig>>,
    ) -> Result<Option<Arc<dyn EvidenceProvider>>, RbcError> {
        let Some(providers) = providers else { return Ok(None) };
        let Some(cfg) = providers.into_iter().find(|p| p.enabled) else { return Ok(None) };
        let ep_cfg = Value::Object(cfg.rest);
        let provider: Arc<dyn EvidenceProvider> = match cfg.provider_type {
            ProviderType::Native => Arc::new(NativeEvidenceProvider::new(ep_cfg)?),
            ProviderType::Rbs => return Err(RbcError::ConfigError(
                "evidence_provider does not support type 'rbs'".into(),
            )),
        };
        Ok(Some(provider))
    }

    /// Iterate the provider list and instantiate the first enabled entry.
    fn build_token_provider(
        providers: Option<Vec<ProviderRawConfig>>,
        rest_client: &RbsRestClient,
    ) -> Result<Option<Arc<dyn TokenProvider>>, RbcError> {
        let Some(providers) = providers else { return Ok(None) };
        let Some(cfg) = providers.into_iter().find(|p| p.enabled) else { return Ok(None) };
        let tp_cfg = Value::Object(cfg.rest);
        let provider: Arc<dyn TokenProvider> = match cfg.provider_type {
            ProviderType::Rbs => Arc::new(RbsAttestTokenProvider::new(rest_client.clone(), tp_cfg)?),
            ProviderType::Native => Arc::new(NativeTokenProvider::new(tp_cfg)?),
        };
        Ok(Some(provider))
    }

    /// Create a `Client` by loading configuration from the YAML file at `path`.
    pub fn from_config(path: &str) -> Result<Self, RbcError> {
        Self::new(Config::from_file(path)?)
    }

    /// Request an authentication challenge (nonce) from RBS.
    pub fn get_auth_challenge(&self) -> Result<AuthChallengeResponse, RbcError> {
        let rest = self.inner.rest_client.clone();
        self.inner.runtime.block_on(rest.get_nonce(None))
    }

    /// Begin a new session. If `attester_data` does not contain `tee_pubkey`, an ephemeral
    /// key pair is generated automatically; otherwise the caller is responsible for the key.
    pub fn new_session(
        &self,
        attester_data: Option<&AttesterData>,
    ) -> Result<Session, RbcError> {
        Session::create(Rc::clone(&self.inner), attester_data, self.inner.key_type)
    }
}

/// Represents a single attestation session. Not thread-safe (uses `Rc` internally).
pub struct Session {
    client: Rc<ClientInner>,
    ephemeral_key: Option<TeeKeyPair>,
    enriched_attester_data: Option<AttesterData>,
    caller_manages_key: bool,
    key_algorithm: KeyType,
    _marker: std::marker::PhantomData<*mut ()>,
}

impl Session {
    fn create(
        client: Rc<ClientInner>,
        attester_data: Option<&AttesterData>,
        key_algorithm: KeyType,
    ) -> Result<Self, RbcError> {
        let tee_pubkey = attester_data
            .and_then(|ad| ad.runtime_data.as_ref())
            .and_then(|rd: &serde_json::Map<String, Value>| rd.get("tee_pubkey"));

        if let Some(pubkey) = tee_pubkey {
            let pubkey_json = serde_json::to_string(pubkey).map_err(RbcError::JsonError)?;
            let pubkey = TeePublicKey::from_jwk_json(&pubkey_json)
                .map_err(|e| RbcError::InvalidInput(format!("invalid tee_pubkey: {e}")))?;
            pubkey.validate_params()?;
            let effective_algorithm = pubkey.key_type();
            if effective_algorithm != key_algorithm {
                return Err(RbcError::InvalidInput(format!(
                    "tee_pubkey algorithm ({effective_algorithm:?}) does not match configured key_algorithm ({key_algorithm:?})"
                )));
            }
            Ok(Self {
                client,
                ephemeral_key: None,
                enriched_attester_data: attester_data.cloned(),
                caller_manages_key: true,
                key_algorithm,
                _marker: std::marker::PhantomData,
            })
        } else {
            let key = TeeKeyPair::generate(key_algorithm)?;
            let jwk_json = key.public_jwk_json()?;

            let mut enriched = attester_data.cloned().unwrap_or_default();
            let jwk_value: Value = serde_json::from_str(&jwk_json)?;
            enriched
                .runtime_data
                .get_or_insert_with(Default::default)
                .insert("tee_pubkey".to_string(), jwk_value);

            Ok(Self {
                client,
                ephemeral_key: Some(key),
                enriched_attester_data: Some(enriched),
                caller_manages_key: false,
                key_algorithm,
                _marker: std::marker::PhantomData,
            })
        }
    }

    /// Collect TEE evidence for the given challenge using the configured evidence provider.
    pub fn collect_evidence(
        &self,
        challenge: &AuthChallengeResponse,
    ) -> Result<Value, RbcError> {
        let provider = self.client.evidence_provider.as_ref()
            .ok_or_else(|| RbcError::ProviderError("evidence provider not configured".into()))?;
        let timeout = self.client.timeout_secs.map(std::time::Duration::from_secs);
        self.client.runtime.block_on(async {
            let fut = provider.collect_evidence(challenge, self.enriched_attester_data.as_ref());
            match timeout {
                Some(d) => tokio::time::timeout(d, fut).await
                    .map_err(|_| RbcError::TimeoutError("collect evidence timed out".into()))?,
                None => fut.await,
            }
        })
    }

    /// Obtain an attest token from the configured token provider, optionally passing raw evidence.
    pub fn attest(&self, evidence: Option<&Value>) -> Result<AttestResponse, RbcError> {
        let provider = self.client.token_provider.as_ref()
            .ok_or_else(|| RbcError::ProviderError("token provider not configured".into()))?;
        let timeout = self.client.timeout_secs.map(std::time::Duration::from_secs);
        let token = self.client.runtime.block_on(async {
            let fut = provider.get_token(evidence, self.enriched_attester_data.as_ref());
            match timeout {
                Some(d) => tokio::time::timeout(d, fut).await
                    .map_err(|_| RbcError::TimeoutError("attest timed out".into()))?,
                None => fut.await,
            }
        })?;
        Ok(AttestResponse { token })
    }

    /// Fetch the resource at `uri`, authorized via `request`.
    pub fn get_resource(
        &self,
        uri: &str,
        request: GetResourceRequest<'_>,
    ) -> Result<Resource, RbcError> {
        let rest = self.client.rest_client.clone();
        let resp: ResourceContentResponse = self.client.runtime.block_on(async {
            match request {
                GetResourceRequest::ByAttestToken(token) => {
                    rest.get_resource(uri, token).await
                }
                GetResourceRequest::ByEvidence { value } => {
                    let rbc_evidences: RbcEvidencesPayload = serde_json::from_value(value.clone())
                        .map_err(|e| RbcError::InvalidInput(format!("invalid evidence: {e}")))?;
                    let attest_req = AttestRequest {
                        as_provider: None,
                        rbc_evidences,
                        attester_data: None,
                    };
                    rest.get_resource_by_evidence(uri, &attest_req).await
                }
            }
        })?;

        let content = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(&resp.content)
                .unwrap_or_else(|_| resp.content.into_bytes()),
        );

        Ok(Resource { uri: resp.uri, content, content_type: resp.content_type })
    }

    /// Decrypt a JWE-encrypted resource content. Pass `private_key_pem` when the caller manages
    /// the TEE key; omit it to use the session's ephemeral key.
    pub fn decrypt_content(
        &self,
        jwe_token: &str,
        private_key_pem: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>, RbcError> {
        let bytes = if self.caller_manages_key {
            let pem = private_key_pem
                .ok_or_else(|| RbcError::InvalidInput(
                    "caller manages key but no private key provided".into()
                ))?;
            let kp = TeeKeyPair::from_private_pem(self.key_algorithm, pem)?;
            kp.decrypt_jwe(jwe_token)?
        } else {
            let key = self.ephemeral_key
                .as_ref()
                .ok_or_else(|| RbcError::DecryptError("no ephemeral key available".into()))?;
            key.decrypt_jwe(jwe_token)?
        };
        Ok(Zeroizing::new(bytes))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.ephemeral_key.take();
    }
}

#[cfg(test)]
impl Client {
    /// Construct a `Client` from a pre-built `ClientInner`.
    pub(crate) fn new_for_test(inner: Rc<ClientInner>) -> Self {
        Self { inner, _marker: std::marker::PhantomData }
    }
}

#[cfg(test)]
impl Session {
    /// Return the ephemeral public key as a JWK JSON string.
    pub(crate) fn test_ephemeral_public_jwk_json(&self) -> Option<String> {
        self.ephemeral_key.as_ref().and_then(|k| k.public_jwk_json().ok())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use super::*;
    use crate::client::RbsRestClient;
    use crate::tools::tee_key::TeePublicKey;
    use rbs_api_types::{AttesterData, AuthChallengeResponse};
    use serde_json::json;

    struct MockEvidenceProvider {
        result: Value,
    }

    #[async_trait]
    impl EvidenceProvider for MockEvidenceProvider {
        async fn collect_evidence(
            &self,
            _challenge: &AuthChallengeResponse,
            _attester_data: Option<&AttesterData>,
        ) -> Result<Value, RbcError> {
            Ok(self.result.clone())
        }
    }

    struct MockTokenProvider {
        token: String,
    }

    #[async_trait]
    impl TokenProvider for MockTokenProvider {
        async fn get_token(
            &self,
            _evidence: Option<&Value>,
            _attester_data: Option<&AttesterData>,
        ) -> Result<String, RbcError> {
            Ok(self.token.clone())
        }
    }

    fn make_raw_cfg(typ: ProviderType) -> ProviderRawConfig {
        ProviderRawConfig { provider_type: typ, enabled: true, rest: Default::default() }
    }

    fn make_test_client() -> Client {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        Client {
            inner: Rc::new(ClientInner {
                rest_client: RbsRestClient::new("http://localhost:9999", None, None).unwrap(),
                evidence_provider: Some(Arc::new(MockEvidenceProvider {
                    result: json!({"mock": true}),
                })),
                token_provider: Some(Arc::new(MockTokenProvider {
                    token: "mock.token".to_string(),
                })),
                key_type: KeyType::Ec,
                timeout_secs: None,
                runtime,
            }),
            _marker: std::marker::PhantomData,
        }
    }

    fn make_test_client_no_providers() -> Client {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        Client {
            inner: Rc::new(ClientInner {
                rest_client: RbsRestClient::new("http://localhost:9999", None, None).unwrap(),
                evidence_provider: None,
                token_provider: None,
                key_type: KeyType::Ec,
                timeout_secs: None,
                runtime,
            }),
            _marker: std::marker::PhantomData,
        }
    }

    #[test]
    fn provider_raw_config_captures_type_and_rest() {
        let raw = r#"{"type":"native","config_path":"/etc/foo.yaml","timeout":30}"#;
        let cfg: ProviderRawConfig = serde_json::from_str(raw).unwrap();
        assert_eq!(cfg.provider_type, ProviderType::Native);
        assert_eq!(cfg.rest["config_path"], "/etc/foo.yaml");
        assert_eq!(cfg.rest["timeout"], 30);
        assert!(!cfg.rest.contains_key("type"), "`type` must be consumed, not left in rest");
    }

    #[test]
    fn config_yaml_parses_rbs_section() {
        let yaml = "\
rbs:
  base_url: http://rbs.example.com
evidence_provider:
  - type: native
    enabled: true
token_provider:
  - type: rbs
    enabled: true
";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.rbs.base_url, "http://rbs.example.com");
        assert_eq!(cfg.key_algorithm, KeyType::Rsa, "default algorithm should be RSA");
        assert!(cfg.rbs.ca_cert.is_none());
        assert!(cfg.rbs.timeout_secs.is_none());
    }

    #[test]
    fn config_yaml_deserializes_optional_fields() {
        let yaml = "\
rbs:
  base_url: http://rbs.example.com
  ca_cert: /etc/ssl/ca.pem
  timeout_secs: 30
key_algorithm: ec
evidence_provider:
  - type: native
    enabled: true
token_provider:
  - type: rbs
    enabled: true
";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.rbs.ca_cert.as_deref(), Some("/etc/ssl/ca.pem"));
        assert_eq!(cfg.rbs.timeout_secs, Some(30));
        assert_eq!(cfg.key_algorithm, KeyType::Ec);
    }

    #[test]
    fn config_yaml_first_enabled_provider_wins() {
        let yaml = "\
rbs:
  base_url: http://rbs.example.com
token_provider:
  - type: rbs
    enabled: false
  - type: native
    enabled: true
";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        let tp = cfg.token_provider.unwrap();
        let first_enabled = tp.iter().find(|p| p.enabled).unwrap();
        assert_eq!(first_enabled.provider_type, ProviderType::Native);
    }

    #[test]
    fn config_builder_missing_base_url_returns_error() {
        let err = Config::builder()
            .evidence_provider(vec![make_raw_cfg(ProviderType::Native)])
            .token_provider(vec![make_raw_cfg(ProviderType::Rbs)])
            .build()
            .unwrap_err();
        assert!(matches!(err, RbcError::ConfigError(_)));
    }

    #[test]
    fn attest_without_token_provider_returns_not_configured() {
        let client = make_test_client_no_providers();
        let session = client.new_session(None).unwrap();
        let err = session.attest(None).unwrap_err();
        assert!(matches!(err, RbcError::ProviderError(_)));
    }

    #[test]
    fn collect_evidence_without_evidence_provider_returns_not_configured() {
        let client = make_test_client_no_providers();
        let session = client.new_session(None).unwrap();
        let challenge = AuthChallengeResponse { nonce: "x".into() };
        let err = session.collect_evidence(&challenge).unwrap_err();
        assert!(matches!(err, RbcError::ProviderError(_)));
    }

    #[test]
    fn config_builder_default_key_algorithm_is_rsa() {
        let cfg = Config::builder()
            .base_url("http://rbs.test")
            .evidence_provider(vec![make_raw_cfg(ProviderType::Native)])
            .token_provider(vec![make_raw_cfg(ProviderType::Rbs)])
            .build()
            .unwrap();
        assert_eq!(cfg.key_algorithm, KeyType::Rsa);
    }

    #[test]
    fn config_builder_sets_all_fields() {
        let cfg = Config::builder()
            .base_url("http://rbs.test")
            .ca_cert("/path/to/ca.pem")
            .timeout_secs(60)
            .key_algorithm(KeyType::Ec)
            .evidence_provider(vec![make_raw_cfg(ProviderType::Native)])
            .token_provider(vec![make_raw_cfg(ProviderType::Rbs)])
            .build()
            .unwrap();
        assert_eq!(cfg.rbs.base_url, "http://rbs.test");
        assert_eq!(cfg.rbs.ca_cert.as_deref(), Some("/path/to/ca.pem"));
        assert_eq!(cfg.rbs.timeout_secs, Some(60));
        assert_eq!(cfg.key_algorithm, KeyType::Ec);
    }

    #[test]
    fn session_create_without_caller_key_injects_tee_pubkey() {
        let client = make_test_client();
        let session = Session::create(Rc::clone(&client.inner), None, KeyType::Ec).unwrap();

        assert!(!session.caller_manages_key);
        assert!(session.ephemeral_key.is_some());

        let rd = session
            .enriched_attester_data
            .as_ref()
            .unwrap()
            .runtime_data
            .as_ref()
            .unwrap();
        assert!(rd.contains_key("tee_pubkey"), "tee_pubkey must be injected");
    }

    #[test]
    fn session_create_preserves_existing_runtime_data_fields() {
        let client = make_test_client();
        let mut runtime_data = serde_json::Map::new();
        runtime_data.insert("user_field".to_string(), json!("user_value"));
        let attester_data = AttesterData {
            runtime_data: Some(runtime_data),
        };

        let session = Session::create(Rc::clone(&client.inner), Some(&attester_data), KeyType::Ec).unwrap();

        let rd = session
            .enriched_attester_data
            .as_ref()
            .unwrap()
            .runtime_data
            .as_ref()
            .unwrap();
        assert!(rd.contains_key("tee_pubkey"), "tee_pubkey must be injected");
        assert_eq!(rd["user_field"], "user_value", "pre-existing field must be preserved");
    }

    #[test]
    fn session_create_with_caller_tee_pubkey_skips_ephemeral_key() {
        let client = make_test_client();
        let mut runtime_data = serde_json::Map::new();
        // Valid P-256 public JWK (test vector, not a real key)
        runtime_data.insert("tee_pubkey".to_string(), json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        }));
        let attester_data = AttesterData {
            runtime_data: Some(runtime_data),
        };

        let session = Session::create(Rc::clone(&client.inner), Some(&attester_data), KeyType::Ec).unwrap();

        assert!(session.caller_manages_key);
        assert!(session.ephemeral_key.is_none());
    }

    #[test]
    fn session_attest_returns_token_from_provider() {
        let client = make_test_client();
        let session = Session::create(Rc::clone(&client.inner), None, KeyType::Ec).unwrap();
        let resp = session.attest(None).unwrap();
        assert_eq!(resp.token, "mock.token");
    }

    #[test]
    fn session_collect_evidence_delegates_to_provider() {
        let client = make_test_client();
        let session = Session::create(Rc::clone(&client.inner), None, KeyType::Ec).unwrap();
        let challenge = AuthChallengeResponse {
            nonce: "test-nonce".to_string(),
        };
        let evidence = session.collect_evidence(&challenge).unwrap();
        assert_eq!(evidence["mock"], true);
    }

    #[test]
    fn decrypt_content_caller_manages_key_without_pem_returns_error() {
        let client = make_test_client();
        let session = Session {
            client: Rc::clone(&client.inner),
            ephemeral_key: None,
            enriched_attester_data: None,
            caller_manages_key: true,
            key_algorithm: KeyType::Ec,
            _marker: std::marker::PhantomData,
        };
        let err = session.decrypt_content("fake.jwe.token", None).unwrap_err();
        assert!(matches!(err, RbcError::InvalidInput(_)));
    }

    #[test]
    fn decrypt_content_no_ephemeral_key_returns_error() {
        let client = make_test_client();
        let session = Session {
            client: Rc::clone(&client.inner),
            ephemeral_key: None,
            enriched_attester_data: None,
            caller_manages_key: false,
            key_algorithm: KeyType::Ec,
            _marker: std::marker::PhantomData,
        };
        let err = session.decrypt_content("fake.jwe.token", None).unwrap_err();
        assert!(matches!(err, RbcError::DecryptError(_)));
    }

    #[test]
    fn decrypt_content_roundtrip_with_ec_ephemeral_key() {
        let client = make_test_client();
        let session = Session::create(Rc::clone(&client.inner), None, KeyType::Ec).unwrap();

        let pubkey_json = session
            .ephemeral_key
            .as_ref()
            .unwrap()
            .public_jwk_json()
            .unwrap();
        let pubkey = TeePublicKey::from_jwk_json(&pubkey_json).unwrap();

        let plaintext = b"hello secret resource";
        let jwe = pubkey.encrypt_jwe(plaintext).unwrap();
        let decrypted = session.decrypt_content(&jwe, None).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_ref());
    }
}

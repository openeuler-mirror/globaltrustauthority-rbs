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

use std::sync::Arc;
use serde::Deserialize;
use serde_json::Value;
use base64::Engine;
use rbs_api_types::api::{AttestResponse, AttesterData, AuthChallengeResponse,
                          ResourceContentResponse, AttestRequest, RbcEvidencesPayload};

use crate::client::{RbsRestClient, TlsConfig};
use crate::error::RbcError;
use crate::evidence::{EvidenceProvider, NativeEvidenceProvider};
use crate::token::{TokenProvider, RbsAttestTokenProvider, NativeTokenProvider};
use crate::tools::tee_key::{KeyAlgorithm, TeeKeyPair};


// Captures the full provider config block from YAML:
//   - provider_type: routes to the correct Provider implementation
//   - rest: all remaining fields, passed as-is to Provider::new() (no `type` key)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    Native,
    Rbs,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderRawConfig {
    #[serde(rename = "type")]
    pub provider_type: ProviderType,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(rename = "rbs_base_url", alias = "endpoint")]
    pub endpoint: String,
    pub ca_cert: Option<String>,
    pub timeout_secs: Option<u64>,
    pub evidence_provider: ProviderRawConfig,
    pub token_provider: ProviderRawConfig,
    #[serde(default)]
    pub key_algorithm: KeyAlgorithm,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, RbcError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RbcError::ConfigError(format!("read {path}: {e}")))?;
        serde_yaml::from_str(&content)
            .map_err(|e| RbcError::ConfigError(format!("parse {path}: {e}")))
    }

    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct ConfigBuilder {
    endpoint: Option<String>,
    ca_cert: Option<String>,
    timeout_secs: Option<u64>,
    evidence_provider: Option<ProviderRawConfig>,
    token_provider: Option<ProviderRawConfig>,
    key_algorithm: Option<KeyAlgorithm>,
}

impl ConfigBuilder {
    pub fn endpoint(mut self, url: &str) -> Self {
        self.endpoint = Some(url.to_string());
        self
    }
    pub fn ca_cert(mut self, path: &str) -> Self {
        self.ca_cert = Some(path.to_string());
        self
    }
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }
    pub fn evidence_provider(mut self, ep: ProviderRawConfig) -> Self {
        self.evidence_provider = Some(ep);
        self
    }
    pub fn token_provider(mut self, tp: ProviderRawConfig) -> Self {
        self.token_provider = Some(tp);
        self
    }
    pub fn key_algorithm(mut self, alg: KeyAlgorithm) -> Self {
        self.key_algorithm = Some(alg);
        self
    }
    pub fn build(self) -> Result<Config, RbcError> {
        let endpoint = self.endpoint
            .ok_or_else(|| RbcError::ConfigError("endpoint is required".into()))?;
        let evidence_provider = self.evidence_provider
            .ok_or_else(|| RbcError::ConfigError("evidence_provider is required".into()))?;
        let token_provider = self.token_provider
            .ok_or_else(|| RbcError::ConfigError("token_provider is required".into()))?;
        Ok(Config {
            endpoint,
            ca_cert: self.ca_cert,
            timeout_secs: self.timeout_secs,
            evidence_provider,
            token_provider,
            key_algorithm: self.key_algorithm.unwrap_or_default(),
        })
    }
}

pub enum GetResourceRequest<'a> {
    ByAttestToken(&'a str),
    ByEvidence { value: &'a Value },
}

pub struct Resource {
    pub uri: String,
    pub content: Vec<u8>,
    pub content_type: Option<String>,
}

pub struct Client {
    rest_client: RbsRestClient,
    evidence_provider: Arc<dyn EvidenceProvider>,
    token_provider: Arc<dyn TokenProvider>,
    key_algorithm: KeyAlgorithm,
}

impl Client {
    pub fn new(config: Config) -> Result<Self, RbcError> {
        let tls = config.ca_cert.as_ref().map(|ca| TlsConfig {
            ca_cert: Some(ca.clone()),
        });

        let rest_client = RbsRestClient::new(&config.endpoint, tls.as_ref())?;

        let ep_cfg = Value::Object(config.evidence_provider.rest);
        let evidence_provider: Arc<dyn EvidenceProvider> =
            match config.evidence_provider.provider_type {
                ProviderType::Native => Arc::new(NativeEvidenceProvider::new(ep_cfg)?),
                ProviderType::Rbs => return Err(RbcError::ConfigError(
                    "evidence_provider does not support type 'rbs'".into()
                )),
            };

        let tp_cfg = Value::Object(config.token_provider.rest);
        let token_provider: Arc<dyn TokenProvider> =
            match config.token_provider.provider_type {
                ProviderType::Rbs    => Arc::new(RbsAttestTokenProvider::new(rest_client.clone(), tp_cfg)?),
                ProviderType::Native => Arc::new(NativeTokenProvider::new(tp_cfg)?),
            };

        Ok(Self { rest_client, evidence_provider, token_provider, key_algorithm: config.key_algorithm })
    }

    pub fn from_config(path: &str) -> Result<Self, RbcError> {
        Self::new(Config::from_file(path)?)
    }

    pub fn get_auth_challenge(&self) -> Result<AuthChallengeResponse, RbcError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| RbcError::NetworkError("no tokio runtime".into()))?;
        let client = self.rest_client.clone();
        tokio::task::block_in_place(|| rt.block_on(client.get_nonce(None)))
    }

    pub fn new_session(
        &self,
        attester_data: Option<&AttesterData>,
    ) -> Result<Session<'_>, RbcError> {
        Session::create(self, attester_data, self.key_algorithm)
    }
}

pub struct Session<'c> {
    client: &'c Client,
    ephemeral_key: Option<TeeKeyPair>,
    enriched_attester_data: Option<AttesterData>,
    caller_manages_key: bool,
    key_algorithm: KeyAlgorithm,
}

impl<'c> Session<'c> {
    fn create(
        client: &'c Client,
        attester_data: Option<&AttesterData>,
        key_algorithm: KeyAlgorithm,
    ) -> Result<Self, RbcError> {
        let has_caller_key = attester_data
            .and_then(|ad| ad.runtime_data.as_ref())
            .and_then(|rd: &serde_json::Map<String, Value>| rd.get("tee_pubkey"))
            .is_some();

        if has_caller_key {
            Ok(Self {
                client,
                ephemeral_key: None,
                enriched_attester_data: attester_data.cloned(),
                caller_manages_key: true,
                key_algorithm,
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
            })
        }
    }

    pub fn collect_evidence(
        &self,
        challenge: &AuthChallengeResponse,
    ) -> Result<Value, RbcError> {
        self.client.evidence_provider.collect_evidence(
            challenge,
            self.enriched_attester_data.as_ref(),
        )
    }

    pub fn attest(&self, evidence: Option<&Value>) -> Result<AttestResponse, RbcError> {
        let token = self.client.token_provider.get_token(
            evidence,
            self.enriched_attester_data.as_ref(),
        )?;
        Ok(AttestResponse { token })
    }

    pub fn get_resource(
        &self,
        uri: &str,
        request: GetResourceRequest<'_>,
    ) -> Result<Resource, RbcError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| RbcError::NetworkError("no tokio runtime".into()))?;

        let client = self.client.rest_client.clone();
        let resp: ResourceContentResponse = tokio::task::block_in_place(|| {
            rt.block_on(async {
                match request {
                    GetResourceRequest::ByAttestToken(token) => {
                        client.get_resource(uri, token).await
                    }
                    GetResourceRequest::ByEvidence { value } => {
                        let rbc_evidences: RbcEvidencesPayload = serde_json::from_value(value.clone())
                            .map_err(|e| RbcError::InvalidInput(format!("invalid evidence: {e}")))?;
                        let attest_req = AttestRequest {
                            as_provider: None,
                            rbc_evidences,
                            attester_data: None,
                        };
                        client.get_resource_by_evidence(uri, &attest_req).await
                    }
                }
            })
        })?;

        let content = base64::engine::general_purpose::STANDARD
            .decode(&resp.content)
            .unwrap_or_else(|_| resp.content.into_bytes());

        Ok(Resource { uri: resp.uri, content, content_type: resp.content_type })
    }

    pub fn decrypt_content(
        &self,
        jwe_token: &str,
        private_key_pem: Option<&str>,
    ) -> Result<Vec<u8>, RbcError> {
        if self.caller_manages_key {
            let pem = private_key_pem
                .ok_or_else(|| RbcError::InvalidInput(
                    "caller_manages_key is true but no private_key_pem provided".into()
                ))?;
            let kp = TeeKeyPair::from_private_pem(self.key_algorithm, pem)?;
            kp.decrypt_jwe(jwe_token)
        } else {
            let key = self.ephemeral_key
                .as_ref()
                .ok_or_else(|| RbcError::DecryptError("no ephemeral key available".into()))?;
            key.decrypt_jwe(jwe_token)
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        self.ephemeral_key.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RbsRestClient;
    use crate::tools::tee_key::TeePublicKey;
    use rbs_api_types::api::{AttesterData, AuthChallengeResponse};
    use serde_json::json;

    struct MockEvidenceProvider {
        result: Value,
    }

    impl EvidenceProvider for MockEvidenceProvider {
        fn collect_evidence(
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

    impl TokenProvider for MockTokenProvider {
        fn get_token(
            &self,
            _evidence: Option<&Value>,
            _attester_data: Option<&AttesterData>,
        ) -> Result<String, RbcError> {
            Ok(self.token.clone())
        }
    }

    fn make_raw_cfg(typ: ProviderType) -> ProviderRawConfig {
        ProviderRawConfig {
            provider_type: typ,
            rest: Default::default(),
        }
    }

    fn make_test_client() -> Client {
        Client {
            rest_client: RbsRestClient::new("http://localhost:9999", None).unwrap(),
            evidence_provider: Arc::new(MockEvidenceProvider {
                result: json!({"mock": true}),
            }),
            token_provider: Arc::new(MockTokenProvider {
                token: "mock.token".to_string(),
            }),
            key_algorithm: KeyAlgorithm::Ec,
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
    fn config_yaml_accepts_rbs_base_url_field() {
        let yaml = "\
rbs_base_url: http://rbs.example.com
evidence_provider:
  type: native
token_provider:
  type: rbs
";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.endpoint, "http://rbs.example.com");
        assert_eq!(cfg.key_algorithm, KeyAlgorithm::Rsa, "default algorithm should be RSA");
        assert!(cfg.ca_cert.is_none());
        assert!(cfg.timeout_secs.is_none());
    }

    #[test]
    fn config_yaml_accepts_endpoint_alias() {
        let yaml = "\
endpoint: http://rbs.example.com
evidence_provider:
  type: native
token_provider:
  type: rbs
";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.endpoint, "http://rbs.example.com");
    }

    #[test]
    fn config_yaml_deserializes_optional_fields() {
        let yaml = "\
endpoint: http://rbs.example.com
ca_cert: /etc/ssl/ca.pem
timeout_secs: 30
key_algorithm: ec
evidence_provider:
  type: native
token_provider:
  type: rbs
";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.ca_cert.as_deref(), Some("/etc/ssl/ca.pem"));
        assert_eq!(cfg.timeout_secs, Some(30));
        assert_eq!(cfg.key_algorithm, KeyAlgorithm::Ec);
    }

    #[test]
    fn config_builder_missing_endpoint_returns_error() {
        let err = Config::builder()
            .evidence_provider(make_raw_cfg(ProviderType::Native))
            .token_provider(make_raw_cfg(ProviderType::Rbs))
            .build()
            .unwrap_err();
        assert!(matches!(err, RbcError::ConfigError(_)));
    }

    #[test]
    fn config_builder_missing_evidence_provider_returns_error() {
        let err = Config::builder()
            .endpoint("http://rbs.test")
            .token_provider(make_raw_cfg(ProviderType::Rbs))
            .build()
            .unwrap_err();
        assert!(matches!(err, RbcError::ConfigError(_)));
    }

    #[test]
    fn config_builder_missing_token_provider_returns_error() {
        let err = Config::builder()
            .endpoint("http://rbs.test")
            .evidence_provider(make_raw_cfg(ProviderType::Native))
            .build()
            .unwrap_err();
        assert!(matches!(err, RbcError::ConfigError(_)));
    }

    #[test]
    fn config_builder_default_key_algorithm_is_rsa() {
        let cfg = Config::builder()
            .endpoint("http://rbs.test")
            .evidence_provider(make_raw_cfg(ProviderType::Native))
            .token_provider(make_raw_cfg(ProviderType::Rbs))
            .build()
            .unwrap();
        assert_eq!(cfg.key_algorithm, KeyAlgorithm::Rsa);
    }

    #[test]
    fn config_builder_sets_all_optional_fields() {
        let cfg = Config::builder()
            .endpoint("http://rbs.test")
            .ca_cert("/path/to/ca.pem")
            .timeout_secs(60)
            .key_algorithm(KeyAlgorithm::Ec)
            .evidence_provider(make_raw_cfg(ProviderType::Native))
            .token_provider(make_raw_cfg(ProviderType::Rbs))
            .build()
            .unwrap();
        assert_eq!(cfg.endpoint, "http://rbs.test");
        assert_eq!(cfg.ca_cert.as_deref(), Some("/path/to/ca.pem"));
        assert_eq!(cfg.timeout_secs, Some(60));
        assert_eq!(cfg.key_algorithm, KeyAlgorithm::Ec);
    }

    #[test]
    fn session_create_without_caller_key_injects_tee_pubkey() {
        let client = make_test_client();
        let session = Session::create(&client, None, KeyAlgorithm::Ec).unwrap();

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

        let session = Session::create(&client, Some(&attester_data), KeyAlgorithm::Ec).unwrap();

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
        runtime_data.insert("tee_pubkey".to_string(), json!({"kty": "EC"}));
        let attester_data = AttesterData {
            runtime_data: Some(runtime_data),
        };

        let session = Session::create(&client, Some(&attester_data), KeyAlgorithm::Ec).unwrap();

        assert!(session.caller_manages_key);
        assert!(session.ephemeral_key.is_none());
    }

    #[test]
    fn session_attest_returns_token_from_provider() {
        let client = make_test_client();
        let session = Session::create(&client, None, KeyAlgorithm::Ec).unwrap();
        let resp = session.attest(None).unwrap();
        assert_eq!(resp.token, "mock.token");
    }

    #[test]
    fn session_collect_evidence_delegates_to_provider() {
        let client = make_test_client();
        let session = Session::create(&client, None, KeyAlgorithm::Ec).unwrap();
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
            client: &client,
            ephemeral_key: None,
            enriched_attester_data: None,
            caller_manages_key: true,
            key_algorithm: KeyAlgorithm::Ec,
        };
        let err = session.decrypt_content("fake.jwe.token", None).unwrap_err();
        assert!(matches!(err, RbcError::InvalidInput(_)));
    }

    #[test]
    fn decrypt_content_no_ephemeral_key_returns_error() {
        let client = make_test_client();
        let session = Session {
            client: &client,
            ephemeral_key: None,
            enriched_attester_data: None,
            caller_manages_key: false,
            key_algorithm: KeyAlgorithm::Ec,
        };
        let err = session.decrypt_content("fake.jwe.token", None).unwrap_err();
        assert!(matches!(err, RbcError::DecryptError(_)));
    }

    #[test]
    fn decrypt_content_roundtrip_with_ec_ephemeral_key() {
        let client = make_test_client();
        let session = Session::create(&client, None, KeyAlgorithm::Ec).unwrap();

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

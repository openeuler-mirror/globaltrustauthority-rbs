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

use serde_json::Value;

use crate::cli::args::{ChallengeArgs, ClientAction, DEFAULT_AGENT_CONFIG};
use crate::cli::execute::CliError;
use crate::client::{RbsRestClient, TlsConfig};
use crate::sdk::{Client, Config, ProviderRawConfig, ProviderType};
use crate::tools::tee_key::KeyType;

const DEFAULT_BASE_URL: &str = "https://127.0.0.1:6666";

#[derive(Debug, Clone)]
pub struct ClientCommandContext {
    pub base_url: String,
    pub cert_path: Option<String>,
    pub timeout_secs: Option<u64>,
    pub key_algorithm: KeyType,
    pub agent_config: String,
    pub evidence_provider: Option<Vec<ProviderRawConfig>>,
    pub token_provider: Option<Vec<ProviderRawConfig>>,
}

#[derive(Debug, Clone)]
pub struct ExecutionOptions {
    pub as_provider: String,
}

#[derive(Debug, Clone)]
pub struct ClientRuntimeInputs {
    pub base_url: Option<String>,
    pub cert_path: Option<String>,
    pub timeout_secs: Option<u64>,
    pub key_algorithm: Option<KeyType>,
}

impl ClientCommandContext {
    pub fn build_rest_client(&self) -> Result<RbsRestClient, CliError> {
        let tls = self.cert_path.as_ref().map(|path| TlsConfig { ca_cert: Some(path.clone()) });
        Ok(RbsRestClient::new(&self.base_url, tls.as_ref(), self.timeout_secs)?)
    }

    pub fn build_rbc_client(&self, agent_config_override: Option<&str>) -> Result<Client, CliError> {
        let agent_config_override = agent_config_override.or(Some(self.agent_config.as_str()));
        let mut config = Config::builder().base_url(&self.base_url).key_algorithm(self.key_algorithm);
        if let Some(path) = self.cert_path.as_deref() {
            config = config.ca_cert(path);
        }
        if let Some(timeout_secs) = self.timeout_secs {
            config = config.timeout_secs(timeout_secs);
        }
        if let Some(providers) = self.evidence_provider.clone() {
            config = config.evidence_provider(apply_agent_config_override(providers, agent_config_override));
        }
        if let Some(providers) = self.token_provider.clone() {
            config = config.token_provider(apply_agent_config_override(providers, agent_config_override));
        }
        Ok(Client::new(config.build()?)?)
    }
}

pub fn build_client_context(
    inputs: &ClientRuntimeInputs,
    command: &ClientAction,
) -> Result<ClientCommandContext, CliError> {
    let base_url = inputs.base_url.clone().unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

    let agent_config = command_agent_config(command).to_string();
    let (evidence_provider, token_provider) = command_providers(command, &agent_config);

    Ok(ClientCommandContext {
        base_url,
        cert_path: inputs.cert_path.clone(),
        timeout_secs: inputs.timeout_secs,
        key_algorithm: inputs.key_algorithm.unwrap_or(KeyType::Rsa),
        agent_config,
        evidence_provider,
        token_provider,
    })
}

pub fn command_agent_config(command: &ClientAction) -> &str {
    match command {
        ClientAction::Challenge(args) => &args.agent.agent_config,
        ClientAction::CollectEvidence(args) => &args.agent.agent_config,
        ClientAction::GetToken(args) => &args.agent.agent_config,
        ClientAction::GetResource(args) => &args.agent.agent_config,
    }
}

fn command_providers(
    command: &ClientAction,
    agent_config: &str,
) -> (Option<Vec<ProviderRawConfig>>, Option<Vec<ProviderRawConfig>>) {
    let default_evidence = Some(vec![provider_config(ProviderType::Native, agent_config)]);
    let default_token = Some(vec![provider_config(ProviderType::Rbs, agent_config)]);

    match command {
        ClientAction::GetToken(args) if args.evidence.is_some() => {
            (default_evidence, Some(vec![provider_config(ProviderType::Rbs, agent_config)]))
        },
        ClientAction::GetToken(_) => {
            (default_evidence, Some(vec![provider_config(ProviderType::Native, agent_config)]))
        },
        ClientAction::GetResource(args) if args.passport => {
            (default_evidence, Some(vec![provider_config(ProviderType::Native, agent_config)]))
        },
        ClientAction::CollectEvidence(_) => {
            (Some(vec![provider_config(ProviderType::Native, agent_config)]), default_token)
        },
        ClientAction::Challenge(_) | ClientAction::GetResource(_) => (default_evidence, default_token),
    }
}

fn provider_config(provider_type: ProviderType, agent_config: &str) -> ProviderRawConfig {
    ProviderRawConfig {
        provider_type,
        enabled: true,
        rest: [("config_path".to_string(), Value::String(agent_config.to_string()))].into_iter().collect(),
    }
}

fn apply_agent_config_override(
    mut providers: Vec<ProviderRawConfig>,
    agent_config_override: Option<&str>,
) -> Vec<ProviderRawConfig> {
    let path = agent_config_override.unwrap_or(DEFAULT_AGENT_CONFIG);

    for provider in &mut providers {
        if provider.enabled {
            provider.rest.insert("config_path".to_string(), Value::String(path.to_string()));
        }
    }
    providers
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self { as_provider: "gta".to_string() }
    }
}

impl Default for ClientCommandContext {
    fn default() -> Self {
        build_client_context(
            &ClientRuntimeInputs {
                base_url: None,
                cert_path: None,
                timeout_secs: Some(30),
                key_algorithm: Some(KeyType::Rsa),
            },
            &ClientAction::Challenge(ChallengeArgs::default()),
        )
        .expect("default client command context")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{AgentConfigArgs, CollectEvidenceArgs, GetResourceArgs, GetTokenArgs};
    use crate::error::RbcError;
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509NameBuilder, X509};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Agent config shipped with the crate: both native providers need a readable
    /// config file before they initialize.
    const TEST_AGENT_CONFIG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/agent_config.yaml");

    /// Sequence used to keep concurrent temporary file names unique.
    static TEMP_FILE_SEQ: AtomicUsize = AtomicUsize::new(0);

    /// Temporary file that removes itself when the test ends.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(name: &str, contents: impl AsRef<[u8]>) -> Self {
            let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("rbc-context-{}-{seq}-{name}", std::process::id()));
            std::fs::write(&path, contents.as_ref()).expect("write temporary file");
            Self { path }
        }

        fn path(&self) -> String {
            self.path.display().to_string()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Path that is guaranteed not to exist under the temporary directory.
    fn missing_path(name: &str) -> String {
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("rbc-context-missing-{}-{seq}-{name}", std::process::id()))
            .display()
            .to_string()
    }

    /// Self-signed X.509 certificate PEM that `RbsRestClient` accepts as a CA bundle.
    fn self_signed_cert_pem() -> String {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("create ec group");
        let ec_key = EcKey::generate(&group).expect("generate ec key");
        let pkey = PKey::from_ec_key(ec_key).expect("build ec pkey");

        let mut name = X509NameBuilder::new().expect("create x509 name");
        name.append_entry_by_text("CN", "rbc-context-test").expect("set common name");
        let name = name.build();

        let mut builder = X509::builder().expect("create x509 builder");
        builder.set_version(2).expect("set x509 version");
        let serial = openssl::bn::BigNum::from_u32(1).expect("create serial");
        builder.set_serial_number(&serial.to_asn1_integer().expect("encode serial")).expect("set serial");
        let not_before = Asn1Time::days_from_now(0).expect("not before");
        builder.set_not_before(&not_before).expect("set not before");
        let not_after = Asn1Time::days_from_now(1).expect("not after");
        builder.set_not_after(&not_after).expect("set not after");
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder.set_pubkey(&pkey).expect("set cert pubkey");
        builder.sign(&pkey, MessageDigest::sha256()).expect("sign certificate");
        String::from_utf8(builder.build().to_pem().expect("export certificate pem")).expect("utf8 certificate pem")
    }

    fn agent_args(agent_config: &str) -> AgentConfigArgs {
        AgentConfigArgs { agent_config: agent_config.to_string() }
    }

    fn challenge_action(agent_config: &str) -> ClientAction {
        ClientAction::Challenge(ChallengeArgs { agent: agent_args(agent_config) })
    }

    fn collect_evidence_action(agent_config: &str) -> ClientAction {
        ClientAction::CollectEvidence(CollectEvidenceArgs {
            agent: agent_args(agent_config),
            nonce: "test-nonce".to_string(),
            attester_pubkey: "test-attester-pubkey".to_string(),
            attester_data: None,
            runtime_data: vec![],
        })
    }

    fn get_token_action(agent_config: &str, evidence: Option<&str>) -> ClientAction {
        ClientAction::GetToken(GetTokenArgs {
            agent: agent_args(agent_config),
            attester_pubkey: if evidence.is_some() { None } else { Some("test-attester-pubkey".to_string()) },
            attester_data: None,
            runtime_data: vec![],
            evidence: evidence.map(str::to_string),
        })
    }

    fn get_resource_action(agent_config: &str, passport: bool) -> ClientAction {
        ClientAction::GetResource(GetResourceArgs {
            agent: agent_args(agent_config),
            uri: "vault/default/secret/demo".to_string(),
            attest_token: Some("attest-token".to_string()),
            evidence: None,
            passport,
            background: false,
            attester_data: None,
            runtime_data: vec![],
            private_key_file: None,
            private_key_passphrase: None,
        })
    }

    fn runtime_inputs(
        base_url: Option<&str>,
        cert_path: Option<&str>,
        timeout_secs: Option<u64>,
        key_algorithm: Option<KeyType>,
    ) -> ClientRuntimeInputs {
        ClientRuntimeInputs {
            base_url: base_url.map(str::to_string),
            cert_path: cert_path.map(str::to_string),
            timeout_secs,
            key_algorithm,
        }
    }

    /// Provider context that only configures the RBS token provider, whose
    /// constructor reads `config_path` directly instead of a process-wide singleton.
    fn context_with_token_provider(agent_config: &str) -> ClientCommandContext {
        ClientCommandContext {
            base_url: "http://127.0.0.1:1".to_string(),
            cert_path: None,
            timeout_secs: Some(5),
            key_algorithm: KeyType::Ec,
            agent_config: agent_config.to_string(),
            evidence_provider: None,
            token_provider: Some(vec![provider_config(ProviderType::Rbs, agent_config)]),
        }
    }

    /// Read the `config_path` entry of a provider entry.
    fn config_path(provider: &ProviderRawConfig) -> &str {
        provider.rest.get("config_path").and_then(Value::as_str).expect("provider entry must carry a config_path")
    }

    #[test]
    fn build_client_context_uses_defaults_when_inputs_are_missing() {
        let inputs = runtime_inputs(None, None, None, None);
        let command = challenge_action("/etc/custom.yaml");
        let context = build_client_context(&inputs, &command).expect("context should build");

        assert_eq!(context.base_url, DEFAULT_BASE_URL);
        assert_eq!(context.key_algorithm, KeyType::Rsa, "key algorithm must default to RSA");
        assert_eq!(context.agent_config, "/etc/custom.yaml", "agent config must come from the command");
        assert!(context.cert_path.is_none());
        assert_eq!(context.timeout_secs, None);

        let evidence = context.evidence_provider.expect("challenge must configure an evidence provider");
        assert_eq!(evidence.len(), 1);
        let evidence_entry = evidence.first().expect("evidence provider entry");
        assert_eq!(evidence_entry.provider_type, ProviderType::Native);
        assert!(evidence_entry.enabled);
        assert_eq!(config_path(evidence_entry), "/etc/custom.yaml");

        let token = context.token_provider.expect("challenge must configure a token provider");
        assert_eq!(token.len(), 1);
        let token_entry = token.first().expect("token provider entry");
        assert_eq!(token_entry.provider_type, ProviderType::Rbs);
        assert_eq!(config_path(token_entry), "/etc/custom.yaml");
    }

    #[test]
    fn build_client_context_applies_every_runtime_input() {
        let context = build_client_context(
            &runtime_inputs(Some("https://rbs.example.com"), Some("/tmp/ca.pem"), Some(17), Some(KeyType::Ec)),
            &challenge_action("/etc/custom.yaml"),
        )
        .expect("context should build");

        assert_eq!(context.base_url, "https://rbs.example.com");
        assert_eq!(context.cert_path.as_deref(), Some("/tmp/ca.pem"));
        assert_eq!(context.timeout_secs, Some(17));
        assert_eq!(context.key_algorithm, KeyType::Ec);
    }

    #[test]
    fn command_agent_config_returns_the_path_of_every_command() {
        assert_eq!(command_agent_config(&challenge_action("/etc/challenge.yaml")), "/etc/challenge.yaml");
        assert_eq!(command_agent_config(&collect_evidence_action("/etc/evidence.yaml")), "/etc/evidence.yaml");
        assert_eq!(command_agent_config(&get_token_action("/etc/token.yaml", None)), "/etc/token.yaml");
        assert_eq!(command_agent_config(&get_resource_action("/etc/resource.yaml", false)), "/etc/resource.yaml");
    }

    // Each command selects a different provider pair; assert the exact types so a
    // silent fall-through to another match arm is caught.
    #[test]
    fn command_providers_selects_provider_types_per_command() {
        let config = "/etc/agent.yaml";
        let types = |command: &ClientAction| {
            let (evidence, token) = command_providers(command, config);
            let evidence_types: Vec<ProviderType> =
                evidence.expect("evidence providers must be set").iter().map(|p| p.provider_type).collect();
            let token_types: Vec<ProviderType> =
                token.expect("token providers must be set").iter().map(|p| p.provider_type).collect();
            (evidence_types, token_types)
        };

        assert_eq!(
            types(&get_token_action(config, Some(r#"{"measurements":[]}"#))),
            (vec![ProviderType::Native], vec![ProviderType::Rbs]),
            "get-token with raw evidence must post it to RBS"
        );
        assert_eq!(
            types(&get_token_action(config, None)),
            (vec![ProviderType::Native], vec![ProviderType::Native]),
            "get-token without evidence must run the native flow"
        );
        assert_eq!(
            types(&get_resource_action(config, true)),
            (vec![ProviderType::Native], vec![ProviderType::Native]),
            "passport flow must use the native token provider"
        );
        assert_eq!(
            types(&get_resource_action(config, false)),
            (vec![ProviderType::Native], vec![ProviderType::Rbs]),
            "plain get-resource keeps the default provider pair"
        );
        assert_eq!(
            types(&collect_evidence_action(config)),
            (vec![ProviderType::Native], vec![ProviderType::Rbs]),
            "collect-evidence keeps the default token provider"
        );
        assert_eq!(
            types(&challenge_action(config)),
            (vec![ProviderType::Native], vec![ProviderType::Rbs]),
            "challenge keeps the default provider pair"
        );
    }

    #[test]
    fn apply_agent_config_override_replaces_config_path_of_enabled_providers() {
        let providers = vec![provider_config(ProviderType::Native, "/old/agent.yaml")];
        let overridden = apply_agent_config_override(providers, Some("/new/agent.yaml"));

        assert_eq!(overridden.len(), 1);
        let entry = overridden.first().expect("overridden provider entry");
        assert_eq!(config_path(entry), "/new/agent.yaml");
        assert!(entry.enabled, "override must not change the enabled flag");
    }

    #[test]
    fn apply_agent_config_override_falls_back_to_the_default_agent_config() {
        let providers = vec![provider_config(ProviderType::Rbs, "/old/agent.yaml")];
        let overridden = apply_agent_config_override(providers, None);

        assert_eq!(config_path(overridden.first().expect("overridden provider entry")), DEFAULT_AGENT_CONFIG);
    }

    #[test]
    fn apply_agent_config_override_keeps_disabled_providers_untouched() {
        let mut disabled = provider_config(ProviderType::Native, "/disabled/agent.yaml");
        disabled.enabled = false;
        let enabled = provider_config(ProviderType::Rbs, "/enabled/agent.yaml");

        let overridden = apply_agent_config_override(vec![disabled, enabled], Some("/new/agent.yaml"));

        let disabled_entry = overridden.first().expect("disabled provider entry");
        assert_eq!(config_path(disabled_entry), "/disabled/agent.yaml", "disabled entries must keep their config");
        assert!(!disabled_entry.enabled);
        let enabled_entry = overridden.get(1).expect("enabled provider entry");
        assert_eq!(config_path(enabled_entry), "/new/agent.yaml");
    }

    #[test]
    fn build_rest_client_succeeds_without_cert_path() {
        let context = ClientCommandContext {
            base_url: "https://127.0.0.1:1".to_string(),
            cert_path: None,
            timeout_secs: Some(3),
            key_algorithm: KeyType::Rsa,
            agent_config: TEST_AGENT_CONFIG.to_string(),
            evidence_provider: None,
            token_provider: None,
        };

        assert!(context.build_rest_client().is_ok(), "plain HTTPS client must build");
    }

    #[test]
    fn build_rest_client_succeeds_with_ca_cert_path() {
        let ca = TempFile::new("ca.pem", self_signed_cert_pem());
        let context = ClientCommandContext {
            base_url: "https://127.0.0.1:1".to_string(),
            cert_path: Some(ca.path()),
            timeout_secs: None,
            key_algorithm: KeyType::Rsa,
            agent_config: TEST_AGENT_CONFIG.to_string(),
            evidence_provider: None,
            token_provider: None,
        };

        assert!(context.build_rest_client().is_ok(), "CA cert path must be loaded");
    }

    #[test]
    fn build_rest_client_rejects_missing_ca_cert() {
        let context = ClientCommandContext {
            base_url: "https://127.0.0.1:1".to_string(),
            cert_path: Some(missing_path("ca.pem")),
            timeout_secs: None,
            key_algorithm: KeyType::Rsa,
            agent_config: TEST_AGENT_CONFIG.to_string(),
            evidence_provider: None,
            token_provider: None,
        };

        let err = context.build_rest_client().err().expect("missing CA cert must fail");
        assert!(matches!(err, CliError::Rbc(RbcError::TlsError(_))), "unexpected error: {err}");
    }

    #[test]
    fn build_rbc_client_without_providers_succeeds() {
        let context = ClientCommandContext {
            base_url: "http://127.0.0.1:1".to_string(),
            cert_path: None,
            timeout_secs: Some(4),
            key_algorithm: KeyType::Ec,
            agent_config: TEST_AGENT_CONFIG.to_string(),
            evidence_provider: None,
            token_provider: None,
        };

        assert!(context.build_rbc_client(None).is_ok(), "provider-less client must build");
    }

    #[test]
    fn build_rbc_client_uses_the_context_agent_config_when_no_override_is_given() {
        let context = context_with_token_provider(TEST_AGENT_CONFIG);

        assert!(context.build_rbc_client(None).is_ok(), "context agent config must be applied to the provider");
    }

    #[test]
    fn build_rbc_client_applies_the_agent_config_override() {
        let context = context_with_token_provider(TEST_AGENT_CONFIG);

        assert!(
            context.build_rbc_client(Some(TEST_AGENT_CONFIG)).is_ok(),
            "explicit override must replace the context agent config"
        );
    }

    #[test]
    fn build_rbc_client_fails_when_the_overridden_agent_config_is_missing() {
        let context = context_with_token_provider(TEST_AGENT_CONFIG);
        let override_path = missing_path("agent_config.yaml");

        let err = context
            .build_rbc_client(Some(&override_path))
            .err()
            .expect("provider construction must read the overridden agent config");
        assert!(matches!(err, CliError::Rbc(RbcError::ConfigError(_))), "unexpected error: {err}");
    }

    // The evidence-provider branch is reached here even though the bundled agent
    // config is incomplete: a full config also needs the attester plugin shared
    // objects, which are not available in a unit-test environment, so this test
    // pins the error mapping of the provider-construction branch instead.
    #[test]
    fn build_rbc_client_maps_evidence_provider_construction_failure() {
        let mut context = context_with_token_provider(TEST_AGENT_CONFIG);
        context.evidence_provider = Some(vec![provider_config(ProviderType::Native, TEST_AGENT_CONFIG)]);

        let err = context.build_rbc_client(None).err().expect("incomplete agent config must fail provider setup");
        assert!(matches!(err, CliError::Rbc(RbcError::ProviderError(_))), "unexpected error: {err}");
    }

    #[test]
    fn build_rbc_client_rejects_missing_ca_cert() {
        let mut context = context_with_token_provider(TEST_AGENT_CONFIG);
        context.cert_path = Some(missing_path("ca.pem"));

        let err = context.build_rbc_client(None).err().expect("missing CA cert must fail");
        assert!(matches!(err, CliError::Rbc(RbcError::TlsError(_))), "unexpected error: {err}");
    }

    #[test]
    fn default_implementations_match_the_documented_defaults() {
        let options = ExecutionOptions::default();
        assert_eq!(options.as_provider, "gta");

        let context = ClientCommandContext::default();
        assert_eq!(context.base_url, DEFAULT_BASE_URL);
        assert_eq!(context.timeout_secs, Some(30));
        assert_eq!(context.key_algorithm, KeyType::Rsa);
        // `ChallengeArgs::default()` leaves the agent config empty; clap fills in
        // `DEFAULT_AGENT_CONFIG` only when arguments are parsed.
        assert!(context.agent_config.is_empty());
        assert!(context.cert_path.is_none());
        assert!(context.evidence_provider.is_some());
        assert!(context.token_provider.is_some());
    }
}

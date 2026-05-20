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
    let base_url = inputs
        .base_url
        .clone()
        .ok_or_else(|| CliError::InvalidArgument("missing RBS base URL; pass --base-url".to_string()))?;

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
        ClientAction::GetToken(_) => (default_evidence, Some(vec![provider_config(ProviderType::Native, agent_config)])),
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
        rest: [("config_path".to_string(), Value::String(agent_config.to_string()))]
            .into_iter()
            .collect(),
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
                base_url: Some("http://localhost:8080".to_string()),
                cert_path: None,
                timeout_secs: Some(30),
                key_algorithm: Some(KeyType::Rsa),
            },
            &ClientAction::Challenge(ChallengeArgs::default()),
        )
        .expect("default client command context")
    }
}

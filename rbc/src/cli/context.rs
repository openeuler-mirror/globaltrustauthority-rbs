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

use crate::cli::args::DEFAULT_AGENT_CONFIG;
use crate::cli::execute::CliError;
use crate::client::{RbsRestClient, TlsConfig};
use crate::sdk::{Client, Config, ProviderRawConfig};
use crate::tools::tee_key::KeyType;

#[derive(Debug, Clone)]
pub struct ClientCommandContext {
    pub base_url: String,
    pub cert_path: Option<String>,
    pub timeout_secs: Option<u64>,
    pub key_algorithm: KeyType,
    pub evidence_provider: Option<Vec<ProviderRawConfig>>,
    pub token_provider: Option<Vec<ProviderRawConfig>>,
}

#[derive(Debug, Clone)]
pub struct ExecutionOptions {
    pub as_provider: String,
}

impl ClientCommandContext {
    pub fn build_rest_client(&self) -> Result<RbsRestClient, CliError> {
        let tls = self.cert_path.as_ref().map(|path| TlsConfig { ca_cert: Some(path.clone()) });
        Ok(RbsRestClient::new(&self.base_url, tls.as_ref(), self.timeout_secs)?)
    }

    pub fn build_rbc_client(&self, agent_config_override: Option<&str>) -> Result<Client, CliError> {
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

fn apply_agent_config_override(
    mut providers: Vec<ProviderRawConfig>,
    agent_config_override: Option<&str>,
) -> Vec<ProviderRawConfig> {
    let Some(path) = agent_config_override else {
        return providers;
    };

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
        Self {
            base_url: "http://localhost:8080".to_string(),
            cert_path: None,
            timeout_secs: Some(30),
            key_algorithm: KeyType::Rsa,
            evidence_provider: Some(vec![ProviderRawConfig {
                provider_type: crate::sdk::ProviderType::Native,
                enabled: true,
                rest: [("config_path".to_string(), Value::String(DEFAULT_AGENT_CONFIG.to_string()))]
                    .into_iter()
                    .collect(),
            }]),
            token_provider: None,
        }
    }
}

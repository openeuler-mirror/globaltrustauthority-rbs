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
pub use rbc::cli::{
    ChallengeArgs, ClientAction, ClientCli, CollectEvidenceArgs, GetResourceArgs, GetTokenArgs,
};

use rbc::cli::{execute_action, ClientCommandContext, ClientOutput, ExecutionOptions};
use rbc::ProviderRawConfig;
use serde_json::{Map, Value};

use crate::common::formatter::Formatter;
use crate::common::{AS_PROVIDE, CLIENT_REQUEST_TIMEOUT};
use crate::config::GlobalOptions;
use crate::error::CliError;

pub fn run(cli: &ClientCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let token_provider_type = match &cli.command {
        ClientAction::GetToken(args) if args.evidence.is_some() => rbc::ProviderType::Rbs,
        ClientAction::GetToken(_) => rbc::ProviderType::Native,
        _ => global.token_provider_type,
    };
    let context = ClientCommandContext {
        base_url: global.base_url.clone(),
        cert_path: global.cert_path.clone(),
        timeout_secs: Some(CLIENT_REQUEST_TIMEOUT),
        key_algorithm: rbc::tools::tee_key::KeyType::Rsa,
        evidence_provider: Some(vec![ProviderRawConfig {
            provider_type: global.evidence_provider_type,
            enabled: true,
            rest: Map::from_iter([("config_path".to_string(), Value::String(global.evidence_provider_config.clone()))]),
        }]),
        token_provider: Some(vec![ProviderRawConfig {
            provider_type: token_provider_type,
            enabled: true,
            rest: Map::from_iter([("config_path".to_string(), Value::String(global.token_provider_config.clone()))]),
        }]),
    };
    let options = ExecutionOptions { as_provider: String::from(AS_PROVIDE) };
    let output = execute_action(&cli.command, &context, &options).map_err(map_rbc_error)?;
    Ok(Box::new(ClientFormatter(output)))
}

fn map_rbc_error(err: rbc::cli::CliError) -> CliError {
    match err {
        rbc::cli::CliError::InvalidArgument(message) => CliError::InvalidArgument(message),
        rbc::cli::CliError::Message(message) => CliError::Message(message),
        rbc::cli::CliError::Io(err) => CliError::Io(err),
        rbc::cli::CliError::Json(err) => CliError::Message(err.to_string()),
        rbc::cli::CliError::Rbc(err) => CliError::Message(err.to_string()),
    }
}

struct ClientFormatter(ClientOutput);

impl Formatter for ClientFormatter {
    fn render_text(&self) -> Result<String, CliError> {
        self.0.render_text().map_err(map_rbc_error)
    }

    fn render_json(&self) -> Result<String, CliError> {
        self.0.render_json().map_err(map_rbc_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Root {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(clap::Subcommand, Debug)]
    enum Command {
        Client(ClientCli),
    }

    #[test]
    fn parse_nested_client_challenge_command() {
        let root = Root::parse_from(["rbs-cli", "client", "challenge"]);
        match root.command {
            Command::Client(cli) => assert!(matches!(cli.command, ClientAction::Challenge(_))),
        }
    }

    #[test]
    fn parse_nested_collect_evidence_requires_attester_pubkey() {
        let err = Root::try_parse_from(["rbs-cli", "client", "collect-evidence", "--nonce", "nonce-value"])
            .expect_err("missing attester-pubkey should fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn parse_nested_get_token_requires_attester_pubkey() {
        let err =
            Root::try_parse_from(["rbs-cli", "client", "get-token"]).expect_err("missing attester-pubkey should fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}

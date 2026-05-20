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
    build_client_context, command_agent_config, ChallengeArgs, ClientAction, ClientCli, ClientRuntimeInputs,
    CollectEvidenceArgs, GetResourceArgs, GetTokenArgs,
};

use rbc::cli::{execute_action, ClientOutput, ExecutionOptions};
use rbc::ProviderType;

use crate::common::formatter::Formatter;
use crate::common::{AS_PROVIDE, CLIENT_REQUEST_TIMEOUT};
use crate::config::GlobalOptions;
use crate::error::CliError;
use tracing::info;

pub fn run(cli: &ClientCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let agent_config = command_agent_config(&cli.command);
    let context = build_client_context(
        &ClientRuntimeInputs {
            base_url: Some(global.base_url.clone()),
            cert_path: global.cert_path.clone(),
            timeout_secs: Some(CLIENT_REQUEST_TIMEOUT),
            key_algorithm: Some(rbc::tools::tee_key::KeyType::Rsa),
        },
        &cli.command,
    )
    .map_err(map_rbc_error)?;
    info!(
        action = client_action_name(&cli.command),
        agent_config,
        evidence_provider = ?context.evidence_provider.as_ref().and_then(enabled_provider_type),
        token_provider = ?context.token_provider.as_ref().and_then(enabled_provider_type),
        "preparing client command context"
    );
    let options = ExecutionOptions { as_provider: String::from(AS_PROVIDE) };
    let output = execute_action(&cli.command, &context, &options).map_err(map_rbc_error)?;
    Ok(Box::new(ClientFormatter(output)))
}

fn enabled_provider_type(providers: &Vec<rbc::ProviderRawConfig>) -> Option<ProviderType> {
    providers.iter().find(|provider| provider.enabled).map(|provider| provider.provider_type)
}

fn client_action_name(action: &ClientAction) -> &'static str {
    match action {
        ClientAction::Challenge(_) => "challenge",
        ClientAction::CollectEvidence(_) => "collect-evidence",
        ClientAction::GetToken(_) => "get-token",
        ClientAction::GetResource(_) => "get-resource",
    }
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

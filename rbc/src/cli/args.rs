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

use clap::{ArgAction, ArgGroup, Args, Subcommand};

use crate::cli::execute::{validate_file_path, validate_not_empty};

pub const DEFAULT_AGENT_CONFIG: &str = "/etc/attestation_agent/agent_config.yaml";

#[derive(Args, Debug, Clone)]
pub struct ClientCli {
    #[command(subcommand)]
    pub command: ClientAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ClientAction {
    #[command(about = "Request an authentication nonce from the RBS server")]
    Challenge(ChallengeArgs),
    #[command(about = "Collect local evidence using the attestation agent")]
    CollectEvidence(CollectEvidenceArgs),
    #[command(about = "Submit evidence to the RBS server for attestation")]
    Attest(AttestArgs),
    #[command(about = "Obtain an attestation token via the configured token provider")]
    GetToken(GetTokenArgs),
    #[command(about = "Fetch a protected resource using a token or evidence")]
    GetResource(GetResourceArgs),
}

#[derive(Args, Debug, Clone, Default)]
pub struct ChallengeArgs {}

#[derive(Args, Debug, Clone, Default)]
pub struct AttesterArgs {
    #[arg(long, value_parser = validate_not_empty, help = "Attester public key used to populate tee_pubkey in runtime data")]
    pub attester_pubkey: Option<String>,

    #[arg(long, help = "Attester-data JSON or @file path merged into the request")]
    pub attester_data: Option<String>,

    #[arg(long = "runtime-data", action = ArgAction::Append, help = "Runtime data entry in key=value form; repeat to add multiple entries")]
    pub runtime_data: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct PolicyIdsArgs {
    #[arg(long = "policy-ids", value_delimiter = ',', num_args = 1.., help = "Comma-separated policy IDs to attach to collected evidence")]
    pub policy_ids: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct CollectEvidenceArgs {
    #[arg(long, value_parser = validate_not_empty, help = "Nonce to embed in collected evidence")]
    pub nonce: String,

    #[arg(
        long,
        value_parser = validate_not_empty,
        required = true,
        help = "Attester public key used to populate tee_pubkey in runtime data"
    )]
    pub attester_pubkey: String,

    #[arg(long, help = "Attester-data JSON or @file path merged into the request")]
    pub attester_data: Option<String>,

    #[arg(long = "runtime-data", action = ArgAction::Append, help = "Runtime data entry in key=value form; repeat to add multiple entries")]
    pub runtime_data: Vec<String>,

    #[arg(long, default_value = DEFAULT_AGENT_CONFIG, value_parser = validate_file_path, help = "Path to the attestation agent config file")]
    pub agent_config: String,
}

#[derive(Args, Debug, Clone)]
pub struct AttestArgs {
    #[arg(long, required = true, help = "Evidence JSON or @file path")]
    pub evidence: String,
}

#[derive(Args, Debug, Clone)]
pub struct GetTokenArgs {
    #[arg(
        long,
        value_parser = validate_not_empty,
        required = true,
        help = "Attester public key used to populate tee_pubkey in runtime data"
    )]
    pub attester_pubkey: String,

    #[arg(long, help = "Attester-data JSON or @file path merged into the request")]
    pub attester_data: Option<String>,

    #[arg(long = "runtime-data", action = ArgAction::Append, help = "Runtime data entry in key=value form; repeat to add multiple entries")]
    pub runtime_data: Vec<String>,

    #[command(flatten)]
    pub policy: PolicyIdsArgs,

    #[arg(long, default_value = DEFAULT_AGENT_CONFIG, value_parser = validate_file_path, help = "Path to the attestation agent config file")]
    pub agent_config: String,
}

#[derive(Args, Debug, Clone)]
#[command(group(
    ArgGroup::new("resource_auth")
        .args(["token", "evidence"])
        .required(true)
))]
pub struct GetResourceArgs {
    #[arg(long, value_parser = validate_not_empty, help = "Resource URI to fetch")]
    pub uri: String,

    #[arg(long, value_parser = validate_not_empty, conflicts_with = "evidence", help = "Attestation token used for resource retrieval")]
    pub token: Option<String>,

    #[arg(long, conflicts_with = "token", help = "Evidence JSON or @file path")]
    pub evidence: Option<String>,

    #[arg(long, value_parser = validate_file_path, help = "Path to a PEM private key used to decrypt returned content when needed")]
    pub private_key_file: Option<String>,

    #[arg(long, num_args = 0..=1, value_name = "@PATH", help = "Read the private key passphrase interactively or from @PATH")]
    pub private_key_passphrase: Option<Option<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Args, CommandFactory, Parser};

    #[test]
    fn client_cli_parses_challenge_subcommand() {
        #[derive(clap::Parser)]
        struct Root {
            #[command(flatten)]
            client: ClientCli,
        }

        let root = Root::parse_from(["cmd", "challenge"]);
        assert!(matches!(root.client.command, ClientAction::Challenge(_)));
    }

    #[test]
    fn get_resource_requires_token_or_evidence() {
        let command = GetResourceArgs::augment_args(clap::Command::new("get-resource"));
        let matches = command
            .try_get_matches_from(["get-resource", "--uri", "vault/default/demo"])
            .expect_err("missing auth material should fail");
        assert_eq!(matches.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn get_resource_rejects_both_token_and_evidence() {
        let command = GetResourceArgs::augment_args(clap::Command::new("get-resource"));
        let matches = command
            .try_get_matches_from([
                "get-resource",
                "--uri",
                "vault/default/demo",
                "--token",
                "token",
                "--evidence",
                "@/tmp/evidence.json",
            ])
            .expect_err("conflicting auth material should fail");
        assert_eq!(matches.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn collect_evidence_requires_attester_pubkey() {
        #[derive(Parser, Debug)]
        struct Root {
            #[command(flatten)]
            client: ClientCli,
        }

        let err = Root::try_parse_from(["cmd", "collect-evidence", "--nonce", "nonce-value"])
            .expect_err("missing attester-pubkey should fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn get_token_requires_attester_pubkey() {
        #[derive(Parser, Debug)]
        struct Root {
            #[command(flatten)]
            client: ClientCli,
        }

        let err = Root::try_parse_from(["cmd", "get-token"])
            .expect_err("missing attester-pubkey should fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn client_action_registers_all_commands() {
        #[derive(Parser)]
        struct Root {
            #[command(flatten)]
            client: ClientCli,
        }

        let command = Root::command();
        let names = command.get_subcommands().map(|subcommand| subcommand.get_name().to_string()).collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "challenge".to_string(),
                "collect-evidence".to_string(),
                "attest".to_string(),
                "get-token".to_string(),
                "get-resource".to_string()
            ]
        );
    }
}

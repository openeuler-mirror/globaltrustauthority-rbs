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

use crate::admin::cert::CertCli;
use crate::admin::policy::PolicyCli;
use crate::admin::ref_value::RefValueCli;
use crate::admin::res::ResCli;
use crate::admin::res_policy::ResPolicyCli;
use crate::admin::user::UserCli;
use crate::client::cmd::ClientCli;
use crate::config::cmd::{validate_base_url, validate_cert, validate_output_file, validate_token};
use crate::error::CliError;
use crate::token::cmd::TokenCli;
use crate::version::cmd::VersionCli;
use clap::{Args, Parser, Subcommand};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub mod cmd;

#[derive(Parser, Debug)]
#[command(name = "rbs-cli", arg_required_else_help = true)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalCliArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug, Clone, Default)]
pub struct GlobalCliArgs {
    #[arg(short = 'b', long, display_order = 100, value_parser = validate_base_url, help = "Base URL of the RBS service")]
    pub base_url: Option<String>,

    #[arg(short, long, display_order = 101, value_parser = validate_token, help = "Bearer token used for authenticated requests")]
    pub token: Option<String>,

    #[arg(long, display_order = 102, value_parser = validate_cert, help = "CA certificate file used to verify the RBS server")]
    pub cert: Option<String>,

    #[arg(short, long, display_order = 103, global = true, help = "Output format")]
    pub format: Option<String>,

    #[arg(
        short,
        long,
        display_order = 104,
        global = true,
        value_parser = validate_output_file,
        help = "Write command output to a file"
    )]
    pub output_file: Option<String>,

    #[arg(short, long, display_order = 105, global = true, help = "Enable verbose output")]
    pub verbose: bool,

    #[arg(
        short,
        long,
        display_order = 106,
        global = true,
        conflicts_with = "verbose",
        help = "Suppress non-essential output"
    )]
    pub quiet: bool,

    #[arg(long, display_order = 107, global = true, help = "Do not print command output")]
    pub noout: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Manage GTA certificates and CRLs through RBS.
    Cert(CertCli),
    Client(ClientCli),
    /// Manage GTA attestation policies through RBS.
    Policy(PolicyCli),
    /// Manage GTA reference-value baselines through RBS.
    RefValue(RefValueCli),
    Res(ResCli),
    ResPolicy(ResPolicyCli),
    Token(TokenCli),
    User(UserCli),
    Version(VersionCli),
}

pub const DEFAULT_BASE_URL: &str = "https://127.0.0.1:6666";
pub const DEFAULT_FORMAT: &str = "text";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    #[default]
    Text,
}

impl Display for OutputFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Text => write!(f, "text"),
        }
    }
}

impl FromStr for OutputFormat {
    type Err = CliError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            _ => Err(CliError::InvalidArgument("format is invalid; expected text or json".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GlobalOptions {
    pub base_url: String,
    pub token: Option<String>,
    pub cert: Option<Vec<u8>>,
    pub cert_path: Option<String>,
    pub format: OutputFormat,
    pub format_explicitly_set: bool,
    pub output_file: Option<String>,
    pub verbose: bool,
    pub quiet: bool,
    pub noout: bool,
}

impl Default for GlobalOptions {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            token: None,
            cert: None,
            cert_path: None,
            format: OutputFormat::Text,
            format_explicitly_set: false,
            output_file: None,
            verbose: false,
            quiet: false,
            noout: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn output_format_from_str_rejects_invalid_value() {
        let err = "yaml".parse::<OutputFormat>().expect_err("invalid format should fail");
        assert_eq!(err.to_string(), "format is invalid; expected text or json");
    }

    #[test]
    fn root_command_without_subcommand_prints_help() {
        let err = Cli::try_parse_from(["rbs-cli"]).expect_err("missing subcommand should print help");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand);
    }

    #[test]
    fn token_gen_requires_private_key_file_at_cli_parse_time() {
        let err = Cli::try_parse_from(["rbs-cli", "token", "gen"])
            .expect_err("token generation without a private key should fail during argument parsing");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--private-key-file"));
        assert!(err.to_string().contains("Usage:"));
    }

    #[test]
    fn root_help_describes_client_command() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("Run attestation and protected-resource client commands"));
    }

    #[test]
    fn root_parses_gta_attestation_management_commands() {
        assert!(matches!(
            Cli::try_parse_from(["rbs-cli", "ref-value", "list"]),
            Ok(Cli { command: Command::RefValue(_), .. })
        ));
        assert!(matches!(Cli::try_parse_from(["rbs-cli", "cert", "list"]), Ok(Cli { command: Command::Cert(_), .. })));
        assert!(matches!(
            Cli::try_parse_from(["rbs-cli", "cert", "get", "--id", "cert-1"]),
            Ok(Cli { command: Command::Cert(_), .. })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rbs-cli", "ref-value", "get", "--id", "RV1"]),
            Ok(Cli { command: Command::RefValue(_), .. })
        ));
        assert!(matches!(
            Cli::try_parse_from(["rbs-cli", "policy", "get", "--id", "Policy-1"]),
            Ok(Cli { command: Command::Policy(_), .. })
        ));
        assert!(Cli::try_parse_from(["rbs-cli", "cert", "list", "--limit", "11"]).is_ok());
        assert!(Cli::try_parse_from(["rbs-cli", "ref-value", "list", "--limit", "11"]).is_ok());
        assert!(Cli::try_parse_from(["rbs-cli", "policy", "list", "--offset", "-1"]).is_ok());
        assert!(matches!(
            Cli::try_parse_from(["rbs-cli", "policy", "list"]),
            Ok(Cli { command: Command::Policy(_), .. })
        ));
    }

    #[test]
    fn id_arguments_defer_validation_until_execution() {
        for args in [
            ["rbs-cli", "cert", "get", "--id", "cert_1"],
            ["rbs-cli", "ref-value", "get", "--id", "rv/1"],
            ["rbs-cli", "policy", "get", "--id", "policy?1"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn ids_arguments_defer_validation_until_execution() {
        for args in [
            ["rbs-cli", "cert", "list", "--ids", "cert-1,中文"],
            ["rbs-cli", "policy", "list", "--ids", "policy-1,中文"],
            ["rbs-cli", "ref-value", "list", "--ids", "rv-1,中文"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }

        assert!(Cli::try_parse_from(["rbs-cli", "cert", "list", "--ids", "cert-1,CERT-2"]).is_ok());
        assert!(Cli::try_parse_from(["rbs-cli", "policy", "list", "--ids", "policy-1,POLICY-2"]).is_ok());
        assert!(Cli::try_parse_from(["rbs-cli", "ref-value", "list", "--ids", "rv-1,RV-2"]).is_ok());
    }

    #[test]
    fn id_and_ids_arguments_accept_raw_whitespace_for_execution_validation() {
        for args in [
            ["rbs-cli", "cert", "get", "--id", " cert-1"],
            ["rbs-cli", "policy", "get", "--id", "policy-1 "],
            ["rbs-cli", "ref-value", "list", "--ids", " rv-1,RV-2 "],
        ] {
            assert!(Cli::try_parse_from(args).is_ok(), "surrounding whitespace should be trimmed");
        }

        for args in [
            ["rbs-cli", "ref-value", "get", "--id", "rv 1"],
            ["rbs-cli", "ref-value", "list", "--ids", "rv-1,rv 2"],
            ["rbs-cli", "cert", "list", "--ids", "cert-1,cert 2"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }
}

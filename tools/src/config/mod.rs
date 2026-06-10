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

use crate::admin::res::ResCli;
use crate::admin::res_policy::ResPolicyCli;
use crate::admin::user::UserCli;
use crate::client::cmd::ClientCli;
use crate::config::cmd::{validate_base_url, validate_cert, validate_output_file, validate_token};
use crate::error::CliError;
use crate::token::cmd::TokenCli;
use crate::version::cmd::VersionCli;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub mod cmd;

#[derive(Parser, Debug)]
#[command(name = "rbs-cli")]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalCliArgs,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct GlobalCliArgs {
    #[arg(short = 'b', long, display_order = 100, value_parser = validate_base_url, help = "Base URL of the RBS service")]
    pub base_url: Option<String>,

    #[arg(short, long, display_order = 101, value_parser = validate_token, help = "Bearer token used for authenticated requests")]
    pub token: Option<String>,

    #[arg(long, display_order = 102, value_parser = validate_cert, help = "CA certificate file used to verify the RBS server")]
    pub cert: Option<String>,

    #[arg(short, long, display_order = 103, global = true, value_enum, help = "Output format")]
    pub format: Option<OutputFormat>,

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
    Client(ClientCli),
    Res(ResCli),
    ResPolicy(ResPolicyCli),
    Token(TokenCli),
    User(UserCli),
    Version(VersionCli),
}

pub const DEFAULT_BASE_URL: &str = "https://127.0.0.1:6666";
pub const DEFAULT_FORMAT: &str = "text";

#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
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
            _ => Err(CliError::InvalidConfig(format!("invalid output format `{s}`; expected `text` or `json`"))),
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

    #[test]
    fn output_format_from_str_rejects_invalid_value() {
        let err = "yaml".parse::<OutputFormat>().expect_err("invalid format should fail");
        assert!(err.to_string().contains("invalid output format"));
    }
}

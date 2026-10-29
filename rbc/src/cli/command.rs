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

//! Shared command definition for the RBC binary and generated CLI reference.

use super::{ClientAction, OutputFormat};
use crate::tools::tee_key::KeyType;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rbc-cli", about = "Run RBC CLI commands")]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: ClientAction,
}

#[derive(clap::Args, Debug, Clone)]
pub struct GlobalArgs {
    #[arg(short = 'b', long, value_parser = validate_base_url, help = "Base URL of the RBS service")]
    pub base_url: Option<String>,

    #[arg(long, value_parser = super::execute::validate_file_path, help = "CA certificate file used to verify the RBS server")]
    pub cert: Option<String>,

    #[arg(long, help = "Request timeout in seconds")]
    pub timeout_secs: Option<u64>,

    #[arg(long, value_parser = parse_key_algorithm, help = "Key algorithm used for TEE key generation (rsa, ec, sm2)")]
    pub key_algorithm: Option<KeyType>,

    #[arg(long, default_value = "gta", help = "Provider identifier sent to RBS APIs")]
    pub as_provider: String,

    #[arg(short, long, global = true, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub format: OutputFormat,

    #[arg(short, long, global = true, value_parser = super::execute::validate_file_path, help = "Write command output to a file")]
    pub output_file: Option<String>,

    #[arg(long, global = true, help = "Do not print command output")]
    pub noout: bool,

    #[arg(short, long, global = true, conflicts_with = "verbose", help = "Suppress non-essential output")]
    pub quiet: bool,

    #[arg(short, long, global = true, help = "Enable verbose diagnostics")]
    pub verbose: bool,
}

fn parse_key_algorithm(value: &str) -> Result<KeyType, String> {
    match value {
        "rsa" => Ok(KeyType::Rsa),
        "ec" => Ok(KeyType::Ec),
        "sm2" => Ok(KeyType::Sm2),
        _ => Err(format!("invalid key algorithm `{value}`; expected `rsa`, `ec`, or `sm2`")),
    }
}

fn validate_base_url(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err("base URL must not be empty".to_string());
    }
    let url = reqwest::Url::parse(value).map_err(|err| format!("invalid base URL: {err}"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("base URL must use http or https and include a host".to_string());
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Validate RBC's base URL parser for valid schemes and malformed inputs.
    #[test]
    fn base_url_validator_matrix() {
        assert!(validate_base_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_base_url("https://rbs.example.com").is_ok());
        assert!(validate_base_url("").is_err());
        assert!(validate_base_url("not a url").is_err());
        assert!(validate_base_url("ftp://rbs.example.com").is_err());
    }
}

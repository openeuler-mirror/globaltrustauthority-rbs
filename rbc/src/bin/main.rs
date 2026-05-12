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
use clap::Parser;
use rbc::cli::{execute_action, ClientAction, ClientCommandContext, ClientOutput, ExecutionOptions, OutputFormat};
use rbc::tools::tee_key::KeyType;
use rbc::{Config, ProviderRawConfig, ProviderType};

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
    #[arg(short = 'c', long = "config", value_name = "FILE", help = "Path to the RBC YAML configuration file")]
    pub config_path: Option<String>,

    #[arg(short = 'b', long, help = "Base URL of the RBS service")]
    pub base_url: Option<String>,

    #[arg(long, help = "CA certificate file used to verify the RBS server")]
    pub cert: Option<String>,

    #[arg(long, help = "Request timeout in seconds")]
    pub timeout_secs: Option<u64>,

    #[arg(long, value_parser = parse_key_algorithm, help = "Key algorithm used for TEE key generation")]
    pub key_algorithm: Option<KeyType>,

    #[arg(long, value_parser = parse_provider_type, help = "Override token provider type")]
    pub token_provider_type: Option<ProviderType>,

    #[arg(long, default_value = "gta", help = "Provider identifier sent to RBS APIs")]
    pub as_provider: String,

    #[arg(short, long, global = true, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub format: OutputFormat,

    #[arg(short, long, global = true, help = "Write command output to a file")]
    pub output_file: Option<String>,

    #[arg(long, global = true, help = "Do not print command output")]
    pub noout: bool,
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let context = resolve_context(&cli.global)?;
    let options = ExecutionOptions { as_provider: cli.global.as_provider.clone() };
    let output = execute_action(&cli.command, &context, &options)?;
    emit_output(&output, &cli.global.format, cli.global.output_file.as_deref(), cli.global.noout)?;
    Ok(())
}

fn emit_output(
    output: &ClientOutput,
    format: &OutputFormat,
    output_file: Option<&str>,
    noout: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let rendered = output.render(format)?;
    if let Some(path) = output_file {
        std::fs::write(path, &rendered)?;
        return Ok(());
    }
    if !noout {
        println!("{rendered}");
    }
    Ok(())
}

fn resolve_context(args: &GlobalArgs) -> Result<ClientCommandContext, Box<dyn std::error::Error>> {
    let file_config = match args.config_path.as_deref() {
        Some(path) => Some(Config::from_file(path)?),
        None => None,
    };
    let mut context = file_config.as_ref().map(context_from_config).unwrap_or_else(|| ClientCommandContext {
        base_url: String::new(),
        cert_path: None,
        timeout_secs: None,
        key_algorithm: KeyType::Rsa,
        evidence_provider: None,
        token_provider: None,
    });

    if let Some(base_url) = &args.base_url {
        context.base_url = base_url.clone();
    }
    if let Some(cert) = &args.cert {
        context.cert_path = Some(cert.clone());
    }
    if let Some(timeout_secs) = args.timeout_secs {
        context.timeout_secs = Some(timeout_secs);
    }
    if let Some(key_algorithm) = args.key_algorithm {
        context.key_algorithm = key_algorithm;
    }
    if let Some(provider_type) = args.token_provider_type {
        context.token_provider = Some(override_provider_type(context.token_provider.clone(), provider_type));
    }

    if context.base_url.trim().is_empty() {
        return Err("missing RBS base URL; pass --config or --base-url".into());
    }
    Ok(context)
}

fn context_from_config(config: &Config) -> ClientCommandContext {
    ClientCommandContext {
        base_url: config.rbs.base_url.clone(),
        cert_path: config.rbs.ca_cert.clone(),
        timeout_secs: config.rbs.timeout_secs,
        key_algorithm: config.key_algorithm,
        evidence_provider: config.evidence_provider.clone(),
        token_provider: config.token_provider.clone(),
    }
}

fn parse_key_algorithm(value: &str) -> Result<KeyType, String> {
    match value {
        "rsa" => Ok(KeyType::Rsa),
        "ec" => Ok(KeyType::Ec),
        _ => Err(format!("invalid key algorithm `{value}`; expected `rsa` or `ec`")),
    }
}

fn parse_provider_type(value: &str) -> Result<ProviderType, String> {
    match value {
        "native" => Ok(ProviderType::Native),
        "rbs" => Ok(ProviderType::Rbs),
        _ => Err(format!(
            "invalid token provider type `{value}`; expected `native` or `rbs`"
        )),
    }
}

fn override_provider_type(
    providers: Option<Vec<ProviderRawConfig>>,
    provider_type: ProviderType,
) -> Vec<ProviderRawConfig> {
    match providers {
        Some(mut providers) if !providers.is_empty() => {
            if let Some(provider) = providers.iter_mut().find(|provider| provider.enabled) {
                provider.provider_type = provider_type;
            } else {
                providers[0].provider_type = provider_type;
                providers[0].enabled = true;
            }
            providers
        }
        _ => vec![ProviderRawConfig {
            provider_type,
            enabled: true,
            rest: Default::default(),
        }],
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use rbc::ProviderRawConfig;

    #[test]
    fn parse_flattened_get_resource_command() {
        let cli = Cli::parse_from([
            "rbc-cli",
            "--base-url",
            "https://rbs.example.com",
            "get-resource",
            "--uri",
            "vault/default/demo",
            "--token",
            "token-value",
        ]);
        assert_eq!(cli.global.as_provider, "gta");
        match cli.command {
            ClientAction::GetResource(args) => {
                assert_eq!(args.uri, "vault/default/demo");
                assert_eq!(args.token.as_deref(), Some("token-value"));
            },
            _ => panic!("expected get-resource command"),
        }
    }

    #[test]
    fn config_context_carries_provider_lists() {
        let config = Config {
            rbs: rbc::sdk::RbsConfig {
                base_url: "https://rbs.example.com".to_string(),
                timeout_secs: Some(30),
                ca_cert: Some("/tmp/ca.pem".to_string()),
            },
            evidence_provider: Some(vec![ProviderRawConfig {
                provider_type: rbc::sdk::ProviderType::Native,
                enabled: true,
                rest: Default::default(),
            }]),
            token_provider: None,
            key_algorithm: KeyType::Ec,
        };
        let context = context_from_config(&config);
        assert_eq!(context.base_url, "https://rbs.example.com");
        assert_eq!(context.key_algorithm, KeyType::Ec);
        assert!(context.evidence_provider.is_some());
    }

    #[test]
    fn emit_output_skips_stdout_when_output_file_is_set() {
        let path = std::env::temp_dir().join(format!("rbc-cli-output-{}.txt", std::process::id()));
        let output = ClientOutput::Auth(rbs_api_types::AuthChallengeResponse { nonce: "nonce-value".to_string() });

        emit_output(&output, &OutputFormat::Text, Some(path.to_str().expect("utf8 path")), false).expect("emit output");

        let written = std::fs::read_to_string(&path).expect("read output");
        assert_eq!(written, "nonce-value");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn parse_token_provider_type_override() {
        let cli = Cli::parse_from([
            "rbc-cli",
            "--base-url",
            "https://rbs.example.com",
            "--token-provider-type",
            "rbs",
            "challenge",
        ]);
        assert_eq!(cli.global.token_provider_type, Some(ProviderType::Rbs));
    }

    #[test]
    fn override_provider_type_updates_enabled_provider() {
        let providers = vec![
            ProviderRawConfig {
                provider_type: ProviderType::Native,
                enabled: false,
                rest: Default::default(),
            },
            ProviderRawConfig {
                provider_type: ProviderType::Native,
                enabled: true,
                rest: Default::default(),
            },
        ];
        let providers = override_provider_type(Some(providers), ProviderType::Rbs);
        let provider = providers
            .into_iter()
            .find(|provider| provider.enabled)
            .expect("enabled provider");
        assert_eq!(provider.provider_type, ProviderType::Rbs);
    }
}

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
use rbc::cli::{
    build_client_context, execute_action, ClientAction, ClientCommandContext, ClientOutput, ClientRuntimeInputs,
    ExecutionOptions, OutputFormat,
};
use rbc::tools::tee_key::KeyType;

#[cfg(test)]
use rbc::ProviderType;

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
    #[arg(short = 'b', long, help = "Base URL of the RBS service")]
    pub base_url: Option<String>,

    #[arg(long, help = "CA certificate file used to verify the RBS server")]
    pub cert: Option<String>,

    #[arg(long, help = "Request timeout in seconds")]
    pub timeout_secs: Option<u64>,

    #[arg(long, value_parser = parse_key_algorithm, help = "Key algorithm used for TEE key generation")]
    pub key_algorithm: Option<KeyType>,

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
    let context = resolve_context(&cli.global, &cli.command)?;
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
        eprintln!("output written to {path}");
        return Ok(());
    }
    if !noout {
        println!("{rendered}");
    }
    Ok(())
}

fn resolve_context(args: &GlobalArgs, command: &ClientAction) -> Result<ClientCommandContext, Box<dyn std::error::Error>> {
    build_client_context(
        &ClientRuntimeInputs {
            base_url: args.base_url.clone(),
            cert_path: args.cert.clone(),
            timeout_secs: args.timeout_secs,
            key_algorithm: args.key_algorithm,
        },
        command,
    )
    .map_err(|err| err.into())
}

fn parse_key_algorithm(value: &str) -> Result<KeyType, String> {
    match value {
        "rsa" => Ok(KeyType::Rsa),
        "ec" => Ok(KeyType::Ec),
        _ => Err(format!("invalid key algorithm `{value}`; expected `rsa` or `ec`")),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_flattened_get_resource_command() {
        let cli = Cli::parse_from([
            "rbc-cli",
            "--base-url",
            "https://rbs.example.com",
            "get-resource",
            "--uri",
            "vault/default/demo",
            "--attest-token",
            "token-value",
        ]);
        assert_eq!(cli.global.as_provider, "gta");
        match cli.command {
            ClientAction::GetResource(args) => {
                assert_eq!(args.uri, "vault/default/demo");
                assert_eq!(args.attest_token.as_deref(), Some("token-value"));
            },
            _ => panic!("expected get-resource command"),
        }
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
    fn resolve_context_requires_base_url_without_config_or_override() {
        let args = GlobalArgs {
            base_url: None,
            cert: None,
            timeout_secs: None,
            key_algorithm: None,
            as_provider: "gta".to_string(),
            format: OutputFormat::Text,
            output_file: None,
            noout: false,
        };

        let err = resolve_context(
            &args,
            &ClientAction::Challenge(rbc::cli::ChallengeArgs {
                agent: rbc::cli::AgentConfigArgs { agent_config: "/tmp/agent.yaml".to_string() },
            }),
        )
        .expect_err("missing base url should fail");
        assert!(err.to_string().contains("missing RBS base URL"));
    }

    #[test]
    fn resolve_context_uses_explicit_cli_inputs() {
        let args = GlobalArgs {
            base_url: Some("https://override.example.com".to_string()),
            cert: Some("/tmp/ca.pem".to_string()),
            timeout_secs: Some(30),
            key_algorithm: Some(KeyType::Ec),
            as_provider: "gta".to_string(),
            format: OutputFormat::Text,
            output_file: None,
            noout: false,
        };

        let context = resolve_context(
            &args,
            &ClientAction::Challenge(rbc::cli::ChallengeArgs {
                agent: rbc::cli::AgentConfigArgs { agent_config: "/tmp/agent.yaml".to_string() },
            }),
        )
        .expect("context should resolve");
        assert_eq!(context.base_url, "https://override.example.com");
        assert_eq!(context.cert_path.as_deref(), Some("/tmp/ca.pem"));
        assert_eq!(context.timeout_secs, Some(30));
        assert_eq!(context.key_algorithm, KeyType::Ec);
        assert_eq!(context.agent_config, "/tmp/agent.yaml");
        assert_eq!(
            context
                .token_provider
                .as_ref()
                .and_then(|providers| providers.iter().find(|provider| provider.enabled))
                .map(|provider| provider.provider_type),
            Some(ProviderType::Rbs)
        );
    }

    #[test]
    fn resolve_context_forces_rbs_provider_for_get_token_with_evidence() {
        let args = GlobalArgs {
            base_url: Some("https://override.example.com".to_string()),
            cert: None,
            timeout_secs: None,
            key_algorithm: None,
            as_provider: "gta".to_string(),
            format: OutputFormat::Text,
            output_file: None,
            noout: false,
        };
        let command = ClientAction::GetToken(rbc::cli::GetTokenArgs {
            agent: rbc::cli::AgentConfigArgs { agent_config: "/tmp/agent.yaml".to_string() },
            attester_pubkey: None,
            attester_data: None,
            runtime_data: vec![],
            evidence: Some("@/tmp/evidence.json".to_string()),
        });

        let context = resolve_context(&args, &command).expect("context should resolve");
        assert_eq!(
            context
                .token_provider
                .as_ref()
                .and_then(|providers| providers.iter().find(|provider| provider.enabled))
                .map(|provider| provider.provider_type),
            Some(ProviderType::Rbs)
        );
    }

    #[test]
    fn resolve_context_forces_native_provider_for_get_token_without_evidence() {
        let args = GlobalArgs {
            base_url: Some("https://override.example.com".to_string()),
            cert: None,
            timeout_secs: None,
            key_algorithm: None,
            as_provider: "gta".to_string(),
            format: OutputFormat::Text,
            output_file: None,
            noout: false,
        };
        let command = ClientAction::GetToken(rbc::cli::GetTokenArgs {
            agent: rbc::cli::AgentConfigArgs { agent_config: "/tmp/agent.yaml".to_string() },
            attester_pubkey: Some("@/tmp/pubkey.pem".to_string()),
            attester_data: None,
            runtime_data: vec![],
            evidence: None,
        });

        let context = resolve_context(&args, &command).expect("context should resolve");
        assert_eq!(
            context
                .token_provider
                .as_ref()
                .and_then(|providers| providers.iter().find(|provider| provider.enabled))
                .map(|provider| provider.provider_type),
            Some(ProviderType::Native)
        );
    }

    #[test]
    fn challenge_uses_default_provider_pair() {
        let args = GlobalArgs {
            base_url: Some("https://override.example.com".to_string()),
            cert: None,
            timeout_secs: None,
            key_algorithm: None,
            as_provider: "gta".to_string(),
            format: OutputFormat::Text,
            output_file: None,
            noout: false,
        };

        let context = resolve_context(
            &args,
            &ClientAction::Challenge(rbc::cli::ChallengeArgs {
                agent: rbc::cli::AgentConfigArgs { agent_config: "/tmp/agent.yaml".to_string() },
            }),
        )
        .expect("context should resolve");
        assert_eq!(
            context
                .evidence_provider
                .as_ref()
                .and_then(|providers| providers.iter().find(|provider| provider.enabled))
                .map(|provider| provider.provider_type),
            Some(ProviderType::Native)
        );
        assert_eq!(
            context
                .token_provider
                .as_ref()
                .and_then(|providers| providers.iter().find(|provider| provider.enabled))
                .map(|provider| provider.provider_type),
            Some(ProviderType::Rbs)
        );
    }
}

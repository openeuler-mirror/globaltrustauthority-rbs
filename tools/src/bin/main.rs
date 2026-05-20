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
use rbs_cli::admin::res as res_cmd;
use rbs_cli::admin::res_policy as res_policy_cmd;
use rbs_cli::admin::user as user_cmd;
use rbs_cli::common::logging::{init_logging, LogLevelSource};
use rbs_cli::client::cmd as client_cmd;
use rbs_cli::common::formatter::{emit_err, emit_output, Formatter, TextOutput};
use rbs_cli::config::cmd::resolve_global_options;
use rbs_cli::config::{Cli, Command};
use rbs_cli::token::cmd as token_cmd;
use rbs_cli::version::cmd as version_cmd;
use std::process::ExitCode;
use tracing::{info, warn};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let logging = init_logging(cli.global.verbose, cli.global.quiet);
    info!(
        command = cli.command.as_ref().map(command_name).unwrap_or("config"),
        level = %logging.level,
        source = %log_level_source_name(logging.source),
        "starting rbs-cli"
    );
    let config = match resolve_global_options(&cli.global) {
        Ok(config) => config,
        Err(err) => {
            warn!(error = %err, "failed to resolve global options");
            emit_err(&err, &Default::default());
            return ExitCode::from(1);
        },
    };
    info!(
        base_url = %config.base_url,
        token_present = config.token.is_some(),
        cert_path = ?config.cert_path,
        output_file = ?config.output_file,
        "resolved global options"
    );

    let result = match &cli.command {
        Some(Command::Client(client_cli)) => {
            info!("dispatching client command");
            client_cmd::run(client_cli, &config)
        },
        Some(Command::Res(res_cli)) => {
            info!("dispatching res command");
            res_cmd::run(res_cli, &config)
        },
        Some(Command::ResPolicy(res_policy_cli)) => {
            info!("dispatching res-policy command");
            res_policy_cmd::run(res_policy_cli, &config)
        },
        Some(Command::Token(token_cli)) => {
            info!("dispatching token command");
            token_cmd::run(token_cli, &config)
        },
        Some(Command::User(user_cli)) => {
            info!("dispatching user command");
            user_cmd::run(user_cli, &config)
        },
        Some(Command::Version(version_cli)) => {
            info!("dispatching version command");
            version_cmd::run(version_cli, &config)
        },
        None => Ok(Box::new(TextOutput::new(format!("{config:#?}"))) as Box<dyn Formatter>),
    };

    match result {
        Ok(output) => match emit_output(output.as_ref(), &config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                emit_err(&err, &config);
                ExitCode::from(1)
            },
        },
        Err(err) => {
            emit_err(&err, &config);
            ExitCode::from(1)
        },
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Client(_) => "client",
        Command::Res(_) => "res",
        Command::ResPolicy(_) => "res-policy",
        Command::Token(_) => "token",
        Command::User(_) => "user",
        Command::Version(_) => "version",
    }
}

fn log_level_source_name(source: LogLevelSource) -> &'static str {
    match source {
        LogLevelSource::Default => "default",
        LogLevelSource::Verbose => "verbose",
        LogLevelSource::Quiet => "quiet",
        LogLevelSource::RustLog => "rust_log",
    }
}

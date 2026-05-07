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
use rbs_cli::admin::cert as cert_cmd;
use rbs_cli::admin::policy as policy_cmd;
use rbs_cli::admin::ref_value as ref_value_cmd;
use rbs_cli::admin::res as res_cmd;
use rbs_cli::admin::res_policy as res_policy_cmd;
use rbs_cli::admin::user as user_cmd;
use rbs_cli::client::cmd as client_cmd;
use rbs_cli::common::formatter::{emit_err, emit_output, Formatter, TextOutput};
use rbs_cli::config::cmd::resolve_global_options;
use rbs_cli::config::{Cli, Command};
use rbs_cli::token::cmd as token_cmd;
use rbs_cli::version::cmd as version_cmd;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = match resolve_global_options(&cli.global) {
        Ok(config) => config,
        Err(err) => {
            emit_err(&err, &Default::default());
            return ExitCode::from(1);
        },
    };

    let result = match &cli.command {
        Some(Command::Cert(cert_cli)) => cert_cmd::run(cert_cli, &config),
        Some(Command::Client(client_cli)) => client_cmd::run(client_cli, &config),
        Some(Command::Policy(policy_cli)) => policy_cmd::run(policy_cli, &config),
        Some(Command::RefValue(ref_value_cli)) => ref_value_cmd::run(ref_value_cli, &config),
        Some(Command::Res(res_cli)) => res_cmd::run(res_cli, &config),
        Some(Command::ResPolicy(res_policy_cli)) => res_policy_cmd::run(res_policy_cli, &config),
        Some(Command::Token(token_cli)) => token_cmd::run(token_cli, &config),
        Some(Command::User(user_cli)) => user_cmd::run(user_cli, &config),
        Some(Command::Version(version_cli)) => version_cmd::run(version_cli, &config),
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

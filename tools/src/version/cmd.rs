/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use clap::Args;
use serde::Serialize;

use crate::common::formatter::Formatter;
use crate::config::GlobalOptions;
use crate::error::CliError;

#[derive(Args, Debug, Clone, Default)]
#[command(about = "Print the rbs-cli version")]
pub struct VersionCli {}

#[derive(Debug, Clone, Serialize)]
struct VersionOutput {
    name: &'static str,
    version: &'static str,
}

impl Formatter for VersionOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(format!("{} {}", self.name, self.version))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(self).map_err(|_| CliError::InternalFormat)
    }
}

pub fn run(_cli: &VersionCli, _global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    Ok(Box::new(VersionOutput { name: env!("CARGO_PKG_NAME"), version: env!("CARGO_PKG_VERSION") }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_returns_formatter_with_expected_text_and_json() {
        let output = run(&VersionCli::default(), &GlobalOptions::default()).expect("version output");
        let text = output.render_text().expect("text");
        let json = output.render_json().expect("json");

        assert_eq!(text, format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")));
        assert!(json.contains(env!("CARGO_PKG_NAME")));
        assert!(json.contains(env!("CARGO_PKG_VERSION")));
    }
}

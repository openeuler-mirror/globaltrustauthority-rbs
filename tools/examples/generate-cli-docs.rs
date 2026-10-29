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

//! Generate references from the same command definitions used by the binaries.

use clap::{CommandFactory, Parser};
use std::path::PathBuf;

#[derive(Parser)]
struct Options {
    /// Root under which docs/api/... is written.
    #[arg(long)]
    output_dir: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse();
    for (path, command) in [
        ("docs/api/rbc/cli.md", rbc::cli::Cli::command()),
        ("docs/api/rbs-cli/cli.md", rbs_cli::config::Cli::command()),
    ] {
        let output = options.output_dir.join(path);
        std::fs::create_dir_all(output.parent().expect("document directory"))?;
        let markdown = clap_markdown::help_markdown_command(&command);
        std::fs::write(
            output,
            format!(
                "<!-- Generated from clap command definitions. Run ./scripts/generate-cli-docs.sh. -->\n\n{markdown}"
            ),
        )?;
    }
    Ok(())
}

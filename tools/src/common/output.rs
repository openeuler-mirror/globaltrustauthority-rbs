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

use std::fs;

use crate::config::{GlobalOptions, OutputFormat};
use crate::error::CliError;

/// Renders command output for the selected format and writes it to configured sinks.
pub fn write_formatted_output<F>(global: &GlobalOptions, render: F) -> std::result::Result<(), CliError>
where
    F: FnOnce(OutputFormat) -> std::result::Result<String, CliError>,
{
    let output = render(global.format.clone())?;
    write_output(global, &output)
}

/// Writes an already-rendered output string to the configured targets.
pub fn write_output(global: &GlobalOptions, output: &str) -> std::result::Result<(), CliError> {
    if let Some(output_file) = &global.output_file {
        fs::write(output_file, output)?;
    }
    if !global.noout {
        println!("{output}");
    }
    Ok(())
}

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

use serde::Serialize;

use crate::config::{GlobalOptions, OutputFormat};
use crate::error::CliError;

pub trait Formatter {
    fn render_text(&self) -> Result<String, CliError>;
    fn render_json(&self) -> Result<String, CliError>;
}

#[derive(Debug, Serialize)]
pub struct TextOutput {
    message: String,
}

impl TextOutput {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl Formatter for TextOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(self.message.clone())
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(self).map_err(|_| CliError::InternalFormat)
    }
}

pub fn emit_output(output: &dyn Formatter, global: &GlobalOptions) -> Result<(), CliError> {
    let rendered = match global.format {
        OutputFormat::Json => output.render_json()?,
        OutputFormat::Text => output.render_text()?,
    };

    if let Some(output_file) = &global.output_file {
        fs::write(output_file, &rendered)?;
    }

    if global.quiet {
        return Ok(());
    }

    if !global.noout {
        println!("{rendered}");
    }

    Ok(())
}

pub fn emit_err(err: &CliError, global: &GlobalOptions) {
    if global.quiet {
        return;
    }

    eprintln!("{err}");
}

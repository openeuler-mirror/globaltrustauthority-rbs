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

use clap::ValueEnum;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::error::CliError;

pub mod cmd;

pub const DEFAULT_BASE_URL: &str = "http://localhost:8080";
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
    pub format: OutputFormat,
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
            format: OutputFormat::Text,
            output_file: None,
            verbose: false,
            quiet: false,
            noout: false,
        }
    }
}

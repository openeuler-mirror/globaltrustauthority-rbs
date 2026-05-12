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

use base64::Engine as _;
use clap::ValueEnum;
use rbs_api_types::{AttestResponse, AuthChallengeResponse};
use serde::Serialize;
use serde_json::{json, Value};

use crate::cli::execute::CliError;

#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    #[default]
    Text,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceOutput {
    pub uri: String,
    #[serde(skip_serializing)]
    pub content: Vec<u8>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ClientOutput {
    Auth(AuthChallengeResponse),
    Attest(AttestResponse),
    JsonValue(Value),
    Resource(ResourceOutput),
}

impl ClientOutput {
    pub fn render(&self, format: &OutputFormat) -> Result<String, CliError> {
        match format {
            OutputFormat::Json => self.render_json(),
            OutputFormat::Text => self.render_text(),
        }
    }

    pub fn render_text(&self) -> Result<String, CliError> {
        match self {
            Self::Auth(output) => Ok(output.nonce.clone()),
            Self::Attest(output) => Ok(output.token.clone()),
            Self::JsonValue(output) => Ok(serde_json::to_string_pretty(output)?),
            Self::Resource(output) => match String::from_utf8(output.content.clone()) {
                Ok(text) => Ok(text),
                Err(_) => Ok(base64::engine::general_purpose::STANDARD.encode(&output.content)),
            },
        }
    }

    pub fn render_json(&self) -> Result<String, CliError> {
        match self {
            Self::Auth(output) => Ok(serde_json::to_string_pretty(output)?),
            Self::Attest(output) => Ok(serde_json::to_string_pretty(output)?),
            Self::JsonValue(output) => Ok(serde_json::to_string_pretty(output)?),
            Self::Resource(output) => Ok(serde_json::to_string_pretty(&json!({
                "uri": output.uri,
                "content": base64::engine::general_purpose::STANDARD.encode(&output.content),
                "content_type": output.content_type,
            }))?),
        }
    }
}

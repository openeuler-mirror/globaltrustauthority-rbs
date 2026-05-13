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
use serde::Serialize;

use crate::common::formatter::Formatter;
use crate::error::CliError;

pub mod cmd;

#[derive(Serialize, Debug)]
pub struct Token {
    pub token: String,
}

impl Formatter for Token {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(self.token.clone())
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(self).map_err(|_| CliError::InternalFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_formatter_renders_text_and_json() {
        let token = Token { token: "jwt-token".to_string() };
        assert_eq!(token.render_text().expect("text"), "jwt-token");
        assert!(token.render_json().expect("json").contains("jwt-token"));
    }
}

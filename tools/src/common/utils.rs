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
use crate::error::CliError;
use std::fs;

pub fn read_cert_file(path: &str) -> Result<Vec<u8>, CliError> {
    if path.trim().is_empty() {
        return Err(CliError::InvalidArgument("certificate file path must not be empty".to_string()));
    }
    fs::read(path).map_err(|err| {
        CliError::FileReadError(format!(
            "unable to read certificate file `{path}`. Please check that the file exists and is readable"
        ))
    })
}

pub fn read_path_file(file: &str) -> Result<String, CliError> {
    if let Some(path) = file.strip_prefix('@') {
        return std::fs::read_to_string(path).map_err(|err| {
            CliError::FileReadError(format!(
                "unable to read file `{path}`. Please check that the file exists and is readable"
            ))
        });
    }
    Ok(file.to_string())
}

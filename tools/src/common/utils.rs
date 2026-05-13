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
    fs::read(path).map_err(|_err| {
        CliError::FileReadError(format!(
            "unable to read certificate file `{path}`. Please check that the file exists and is readable"
        ))
    })
}

pub fn read_path_file(file: &str) -> Result<String, CliError> {
    if let Some(path) = file.strip_prefix('@') {
        return std::fs::read_to_string(path).map_err(|_err| {
            CliError::FileReadError(format!(
                "unable to read file `{path}`. Please check that the file exists and is readable"
            ))
        });
    }
    Ok(file.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_cert_file_rejects_blank_path() {
        let err = read_cert_file(" ").expect_err("blank path should fail");
        assert!(err.to_string().contains("certificate file path must not be empty"));
    }

    #[test]
    fn read_path_file_returns_inline_value_or_file_contents() {
        assert_eq!(read_path_file("inline").expect("inline"), "inline");

        let path = std::env::temp_dir().join(format!("tools-read-path-{}.txt", std::process::id()));
        std::fs::write(&path, "file-content").expect("write file");
        let value = read_path_file(&format!("@{}", path.display())).expect("read file");
        assert_eq!(value, "file-content");
        let _ = std::fs::remove_file(path);
    }
}

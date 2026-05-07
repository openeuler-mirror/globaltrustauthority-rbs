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
use crate::common::{CERT_FILE_MAX_SIZE, URL_MAX_LEN};
use crate::error::CliError;
use regex::Regex;
use std::fs;
use std::path::Path;

pub trait HasLen {
    fn len(&self) -> usize;
}

impl HasLen for str {
    fn len(&self) -> usize {
        str::len(self)
    }
}

impl HasLen for String {
    fn len(&self) -> usize {
        String::len(self)
    }
}

impl<T> HasLen for [T] {
    fn len(&self) -> usize {
        <[T]>::len(self)
    }
}

impl<T> HasLen for Vec<T> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
}

pub fn validate_max_len<T>(value: &T, max: usize) -> Result<(), CliError>
where
    T: HasLen + ?Sized,
{
    let len = value.len();
    if len <= max {
        Ok(())
    } else {
        Err(CliError::InvalidArgument(format!("value length must not exceed {max} characters; got {len}")))
    }
}

pub fn validate_string_max_len(value: &str, max: usize) -> Result<String, CliError> {
    validate_max_len(value, max)?;
    Ok(value.to_string())
}

pub fn validate_not_empty(value: &str) -> Result<(), CliError> {
    if value.is_empty() {
        return Err(CliError::InvalidArgument("value is empty".to_string()));
    }
    Ok(())
}

pub fn validate_file_path(file_path: &str) -> Result<String, CliError> {
    if file_path.trim().is_empty() {
        return Err(CliError::InvalidArgument("file path must not be empty".to_string()));
    }

    // Linux path strings may contain almost any character except NUL. This regex
    // also rejects repeated separators and enforces the common 4096-byte limit.
    let path_re = Regex::new(r"^[^\x00]{1,4096}$").map_err(|_| CliError::InternalFormat)?;
    if !path_re.is_match(file_path) {
        return Err(CliError::InvalidArgument(format!("invalid linux file path `{file_path}`")));
    }

    let path = Path::new(file_path);
    if path.exists() && path.is_dir() {
        return Err(CliError::InvalidArgument(format!("output path `{file_path}` points to an existing directory")));
    }
    if path.file_name().is_none() {
        return Err(CliError::InvalidArgument(format!("file path `{file_path}` does not contain a file name")));
    }
    Ok(file_path.into())
}

pub fn validate_file_size(file_path: &str, max_size: u64) -> Result<String, CliError> {
    validate_file_path(file_path)?;
    let file_metadata = fs::metadata(file_path).map_err(|err| {
        CliError::FileReadError(format!(
            "unable to access file `{file_path}`. Please check that the file exists and is readable"
        ))
    })?;
    if file_metadata.len() > max_size {
        return Err(CliError::InvalidArgument(format!(
            "file `{file_path}` exceeds the maximum size of {max_size} bytes; got {} bytes",
            file_metadata.len()
        )));
    }
    Ok(file_path.into())
}

pub fn validate_url(url: &str) -> Result<(), CliError> {
    if url.len() > URL_MAX_LEN {
        return Err(CliError::InvalidArgument(format!(
            "url length must not exceed {URL_MAX_LEN} characters; got {}",
            url.len()
        )));
    }
    url.parse::<reqwest::Url>()
        .map(|_| ())
        .map_err(|err| CliError::InvalidArgument(format!("invalid url `{url}`. Please check the URL format")))
}

pub fn validate_cert_file(file_path: &str) -> Result<String, CliError> {
    if let Some(path) = file_path.strip_prefix('@') {
        validate_file_size(path, CERT_FILE_MAX_SIZE)?;
    } else {
        if file_path.len() > CERT_FILE_MAX_SIZE as usize {
            return Err(CliError::InvalidArgument(format!(
                "certificate content must not exceed {CERT_FILE_MAX_SIZE} bytes; got {} bytes",
                file_path.len()
            )));
        }
    }
    Ok(file_path.to_string())
}

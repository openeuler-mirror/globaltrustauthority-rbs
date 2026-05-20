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
pub mod clap;
pub mod formatter;
pub mod output;
pub mod utils;
pub mod validate;

pub static CERT_FILE_MAX_SIZE: u64 = 1024 * 1024;
pub static PUBKEY_FILE_MAX_SIZE: u64 = 1024 * 1024;
pub static PATH_MAX_SIZE: u64 = 4 * 1024;

pub static ROLE_ARRAY: [&str; 2] = [ROLE_USER, "admin"];

pub static ROLE_USER: &str = "user";

pub static URL_MAX_LEN: usize = 8192;

pub static JWT: &str = "jwt";
pub static JWKS: &str = "jwks";
pub static USERNAME_MAX_LEN: usize = 36;

pub const DEFAULT_PAGE_LIMIT: i64 = 10;
pub const MIN_PAGE_LIMIT: i64 = 1;
pub const MAX_PAGE_LIMIT: i64 = 100;
pub const DEFAULT_PAGE_OFFSET: i64 = 0;
pub const MIN_PAGE_OFFSET: i64 = 0;
pub const MAX_PAGE_OFFSET: i64 = 1000000;

pub const AS_PROVIDE: &str = "gta";
pub const CLIENT_REQUEST_TIMEOUT: u64 = 10;

pub static GTA_CERT_ATTESTER_TYPE_ARRAY: [&str; 8] =
    ["refvalue", "policy", "tpm_boot", "tpm", "tpm_ima", "ascend_npu", "dice", "crl"];

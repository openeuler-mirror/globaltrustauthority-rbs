/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Tests for attestation configuration validation rules.

use rbs_api_types::config::{AttestTokenVerificationConfig, RbsConfig, Sensitive};
use rbs_core::auth::{AuthError, AttestTokenVerifier};
use std::io::Write;
use tempfile::NamedTempFile;

use super::common::make_valid_rbs_config;

fn gta_backend_mut(config: &mut RbsConfig) -> &mut rbs_api_types::config::AttestationRestConfig {
    &mut config
        .attestation
        .backends
        .get_mut("gta")
        .expect("gta backend exists")
        .rest
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Config_056
// mode=rest时base_url为空校验失败
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Config_056
/// 验证mode=rest时base_url为空导致校验失败(panic)。
#[test]
#[should_panic(expected = "base_url is not configured")]
fn test_config_056_rest_mode_empty_base_url_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).base_url = String::new();
    config.validate();
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Config_057
// base_url长度超2048校验失败
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Config_057
/// 验证base_url长度超过2048时校验失败(panic)。
#[test]
#[should_panic(expected = "base_url length 2049 exceeds maximum 2048")]
fn test_config_057_base_url_too_long_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).base_url = "x".repeat(2049);
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_Config_057
/// 验证base_url长度恰好2048(边界值)时校验通过。
#[test]
fn test_config_057_base_url_at_max_length_passes() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).base_url = "h".repeat(2048);
    config.validate();
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Config_058
// timeout_secs超3600和retries超100校验失败
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Config_058
/// 验证timeout_secs=3601(超过上限3600)时校验失败。
#[test]
#[should_panic(expected = "timeout_secs = 3601 exceeds maximum 3600")]
fn test_config_058_timeout_secs_exceeds_max_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).timeout_secs = 3601;
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_Config_058
/// 验证retries=101(超过上限100)时校验失败。
#[test]
#[should_panic(expected = "retries = 101 exceeds maximum 100")]
fn test_config_058_retries_exceed_max_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).retries = 101;
    config.validate();
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Config_059
// credentials.user_id校验规则
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Config_059
/// 验证user_id为空时校验失败。
#[test]
#[should_panic(expected = "user_id must not be empty")]
fn test_config_059_user_id_empty_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).credentials.user_id = String::new();
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_Config_059
/// 验证user_id长度超过36时校验失败。
#[test]
#[should_panic(expected = "user_id length 37 exceeds maximum 36")]
fn test_config_059_user_id_too_long_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).credentials.user_id = "a".repeat(37);
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_Config_059
/// 验证user_id含特殊字符(非[a-zA-Z0-9_-])时校验失败。
#[test]
#[should_panic(expected = "user_id contains invalid characters")]
fn test_config_059_user_id_invalid_chars_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).credentials.user_id = "user@invalid".to_string();
    config.validate();
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Config_060
// credentials API key格式校验
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Config_060
/// 验证main_api_key前缀非"m."时校验失败。
#[test]
#[should_panic(expected = "main_api_key must start with 'm.'")]
fn test_config_060_main_api_key_wrong_prefix_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).credentials.main_api_key =
        Sensitive::new("x.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_Config_060
/// 验证main_api_key长度非34时校验失败。
#[test]
#[should_panic(expected = "main_api_key length 10 != 34")]
fn test_config_060_main_api_key_wrong_length_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).credentials.main_api_key =
        Sensitive::new("m.short123".to_string());
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_Config_060
/// 验证sub_api_key前缀非"s."时校验失败。
#[test]
#[should_panic(expected = "sub_api_key must start with 's.'")]
fn test_config_060_sub_api_key_wrong_prefix_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).credentials.sub_api_key =
        Sensitive::new("x.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_Config_060
/// 验证sub_api_key长度非34时校验失败。
#[test]
#[should_panic(expected = "sub_api_key length 10 != 34")]
fn test_config_060_sub_api_key_wrong_length_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).credentials.sub_api_key =
        Sensitive::new("s.short123".to_string());
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_Config_060
/// 验证main_api_key后缀含非字母数字字符时校验失败。
#[test]
#[should_panic(expected = "main_api_key suffix must be 32 alphanumeric")]
fn test_config_060_main_api_key_non_alnum_suffix_panics() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).credentials.main_api_key =
        Sensitive::new("m.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!".to_string());
    config.validate();
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Config_061
// 公钥/JWKS文件缺失或解析失败启动失败
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Config_061
/// 验证public_key_path指向不存在的文件时AttestTokenVerifier::new返回TokenInvalid。
#[test]
fn test_config_061_public_key_path_missing_fails() {
    let config = AttestTokenVerificationConfig {
        public_key_path: Some("/nonexistent/attest_pubkey.pem".to_string()),
        jwks_file: None,
        issuer: "Global Trust Authority".to_string(),
        audience: Some("rbs".to_string()),
    };
    let result = AttestTokenVerifier::new(config);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthError::TokenInvalid { .. }
    ));
}

/// RUST_GTA_RBS_TP_ATTEST_Config_061
/// 验证jwks_file指向不存在的文件时AttestTokenVerifier::new返回TokenInvalid。
#[test]
fn test_config_061_jwks_file_missing_fails() {
    let config = AttestTokenVerificationConfig {
        public_key_path: None,
        jwks_file: Some("/nonexistent/attest.jwks".to_string()),
        issuer: "Global Trust Authority".to_string(),
        audience: Some("rbs".to_string()),
    };
    let result = AttestTokenVerifier::new(config);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthError::TokenInvalid { .. }
    ));
}

/// RUST_GTA_RBS_TP_ATTEST_Config_061
/// 验证jwks_file内容无效(非JWKS格式)时AttestTokenVerifier::new返回TokenInvalid。
#[test]
fn test_config_061_jwks_file_invalid_content_fails() {
    let mut file = NamedTempFile::new().expect("create temp file");
    file.write_all(b"this is not valid JSON").expect("write");
    file.flush().expect("flush");

    let config = AttestTokenVerificationConfig {
        public_key_path: None,
        jwks_file: Some(file.path().to_str().unwrap().to_string()),
        issuer: "Global Trust Authority".to_string(),
        audience: Some("rbs".to_string()),
    };
    let result = AttestTokenVerifier::new(config);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthError::TokenInvalid { .. }
    ));
}

/// RUST_GTA_RBS_TP_ATTEST_Config_061
/// 验证public_key_path指向无效PEM文件时AttestTokenVerifier::new返回TokenInvalid。
#[test]
fn test_config_061_public_key_path_invalid_pem_fails() {
    let mut file = NamedTempFile::new().expect("create temp file");
    file.write_all(b"not a valid PEM file").expect("write");
    file.flush().expect("flush");

    let config = AttestTokenVerificationConfig {
        public_key_path: Some(file.path().to_str().unwrap().to_string()),
        jwks_file: None,
        issuer: "Global Trust Authority".to_string(),
        audience: Some("rbs".to_string()),
    };
    let result = AttestTokenVerifier::new(config);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AuthError::TokenInvalid { .. }
    ));
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Config_062
// jwks_file和public_key_path互斥校验
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Config_062
/// 验证jwks_file和public_key_path同时配置时panic(互斥校验)。
#[test]
#[should_panic(expected = "jwks_file and public_key_path are mutually exclusive")]
fn test_config_062_both_configured_panics() {
    let mut config = make_valid_rbs_config();
    config.auth.attest_token.jwks_file = Some("/tmp/dummy.jwks".to_string());
    config.auth.attest_token.public_key_path = Some("/tmp/dummy.pem".to_string());
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_Config_062
/// 验证jwks_file和public_key_path都不配置时panic(必须配置其一)。
#[test]
#[should_panic(expected = "must have either jwks_file or public_key_path configured")]
fn test_config_062_neither_configured_panics() {
    let mut config = make_valid_rbs_config();
    config.auth.attest_token.jwks_file = None;
    config.auth.attest_token.public_key_path = None;
    config.validate();
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Config_063
// 配置项边界值校验通过(上限)
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Config_063
/// 验证各配置项在上限边界值时校验通过：base_url=2048, timeout_secs=3600,
/// retries=100, user_id=36, api_key=34(正确前缀)。
#[test]
fn test_config_063_upper_boundary_values_pass() {
    let mut config = make_valid_rbs_config();

    let rest = gta_backend_mut(&mut config);
    rest.base_url = "h".repeat(2048);
    rest.timeout_secs = 3600;
    rest.retries = 100;
    rest.credentials.user_id = "a".repeat(36);
    rest.credentials.main_api_key =
        Sensitive::new("m.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
    rest.credentials.sub_api_key =
        Sensitive::new("s.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string());

    config.validate();
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Config_064
// 配置项下限边界值校验通过
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Config_064
/// 验证timeout_secs=0、retries=0、ca_file为空时校验通过。
#[test]
fn test_config_064_lower_boundary_values_pass() {
    let mut config = make_valid_rbs_config();

    let rest = gta_backend_mut(&mut config);
    rest.timeout_secs = 0;
    rest.retries = 0;
    rest.ca_file = String::new();

    config.validate();
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_GTA_044
// 重试次数和超时配置边界值
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_GTA_044
/// 验证retries=0时校验通过(下限边界，不重试)。
#[test]
fn test_gta_044_retries_zero_passes() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).retries = 0;
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_GTA_044
/// 验证retries=100时校验通过(上限边界，重试上限)。
#[test]
fn test_gta_044_retries_max_passes() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).retries = 100;
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_GTA_044
/// 验证timeout_secs=0时校验通过(下限边界，不限超时)。
#[test]
fn test_gta_044_timeout_zero_passes() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).timeout_secs = 0;
    config.validate();
}

/// RUST_GTA_RBS_TP_ATTEST_GTA_044
/// 验证timeout_secs=3600时校验通过(上限边界，超时上限)。
#[test]
fn test_gta_044_timeout_max_passes() {
    let mut config = make_valid_rbs_config();
    gta_backend_mut(&mut config).timeout_secs = 3600;
    config.validate();
}

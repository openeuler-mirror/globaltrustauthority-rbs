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

//! AuthConfig validation tests.

use rbs_api_types::config::RbsConfig;

use super::common::make_valid_rbs_config;

// ===========================================================================
// RUST_GTA_RBS_TP_AUTH_ConfigValid_032 — AuthConfig合法配置校验通过
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ConfigValid_032
/// A fully valid AuthConfig (non-empty issuer/audience, valid attest_token
/// with public_key_path) passes validate() without panic.
#[test]
fn test_auth_config_valid_032_valid_config_passes() {
    let config: RbsConfig = make_valid_rbs_config();
    config.validate();
}

// ===========================================================================
// RUST_GTA_RBS_TP_AUTH_ConfigBoundary_034 — AuthConfig配置长度边界和可选项边界
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ConfigBoundary_034
/// bearer_token.issuer with length 256 (at the maximum) passes validation.
#[test]
fn test_auth_config_boundary_034_issuer_len_256_passes() {
    let mut config = make_valid_rbs_config();
    config.auth.bearer_token.issuer = "x".repeat(256);
    config.validate();
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ConfigBoundary_034
/// bearer_token.issuer with length 257 (exceeds maximum 256) fails validation.
#[test]
#[should_panic(expected = "issuer length")]
fn test_auth_config_boundary_034_issuer_len_257_panics() {
    let mut config = make_valid_rbs_config();
    config.auth.bearer_token.issuer = "x".repeat(257);
    config.validate();
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ConfigBoundary_034
/// bearer_token.audience with length 256 (at the maximum) passes validation.
#[test]
fn test_auth_config_boundary_034_audience_len_256_passes() {
    let mut config = make_valid_rbs_config();
    config.auth.bearer_token.audience = "x".repeat(256);
    config.validate();
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ConfigBoundary_034
/// bearer_token.audience with length 257 (exceeds maximum 256) fails validation.
#[test]
#[should_panic(expected = "audience length")]
fn test_auth_config_boundary_034_audience_len_257_panics() {
    let mut config = make_valid_rbs_config();
    config.auth.bearer_token.audience = "x".repeat(257);
    config.validate();
}

/// test_point_id: RUST_GTA_RBS_TP_AUTH_ConfigBoundary_034
/// attest_token.audience = None passes validation (aud check is optional).
#[test]
fn test_auth_config_boundary_034_attest_audience_none_passes() {
    let mut config = make_valid_rbs_config();
    config.auth.attest_token.audience = None;
    config.validate();
}

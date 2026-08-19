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

//! Tests for `AttestationManager` provider registration, routing, and error handling.

use rbs_api_types::error::RbsError;
use rbs_core::AttestationManager;

use super::common::{make_attest_request, make_manager_with_gta, make_mock_provider};

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Challenge_008
// as_provider等价类覆盖
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Challenge_008
/// as_provider缺省(None)时使用默认provider，返回200+nonce。
#[tokio::test]
async fn test_challenge_008_as_provider_none_uses_default() {
    let manager = make_manager_with_gta("nonce-default");
    let result = manager.get_auth_challenge(None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().nonce, "nonce-default");
}

/// RUST_GTA_RBS_TP_ATTEST_Challenge_008
/// as_provider=gta(已注册)时路由到gta，返回200+nonce。
#[tokio::test]
async fn test_challenge_008_as_provider_gta_registered() {
    let manager = make_manager_with_gta("nonce-gta");
    let result = manager.get_auth_challenge(Some("gta")).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().nonce, "nonce-gta");
}

/// RUST_GTA_RBS_TP_ATTEST_Challenge_008
/// as_provider=foo(未注册)时返回ManagementProviderNotFound错误(对应404)。
#[tokio::test]
async fn test_challenge_008_as_provider_foo_unregistered_fails() {
    let manager = make_manager_with_gta("nonce");
    let result = manager.get_auth_challenge(Some("foo")).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, RbsError::ManagementProviderNotFound(_)));
    assert!(format!("{}", err).contains("foo"));
}

/// RUST_GTA_RBS_TP_ATTEST_Challenge_008
/// as_provider=空字符串(未注册)时返回ManagementProviderNotFound错误(对应404)。
#[tokio::test]
async fn test_challenge_008_as_provider_empty_string_fails() {
    let manager = make_manager_with_gta("nonce");
    let result = manager.get_auth_challenge(Some("")).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, RbsError::ManagementProviderNotFound(_)));
    assert!(format!("{}", err).contains("management provider not found"));
}

// ===========================================================================
// RUST_GTA_RBS_TP_ATTEST_Provider_032
// AttestationManager默认provider路由
// ===========================================================================

/// RUST_GTA_RBS_TP_ATTEST_Provider_032
/// as_provider=None时AttestationManager使用default_provider(默认"gta")进行路由，
/// 注册了gta provider后get_auth_challenge(None)正常响应。
#[tokio::test]
async fn test_provider_032_default_provider_routing() {
    let manager = make_manager_with_gta("nonce-032");
    assert_eq!(manager.default_name(), "gta");

    let result = manager.get_auth_challenge(None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().nonce, "nonce-032");
}

/// RUST_GTA_RBS_TP_ATTEST_Provider_032
/// 验证切换default_provider后，as_provider=None路由到新的默认provider。
#[tokio::test]
async fn test_provider_032_switch_default_routes_correctly() {
    let mut manager = AttestationManager::new();
    manager.register("gta", make_mock_provider("nonce-gta"));
    manager.register("custom", make_mock_provider("nonce-custom"));

    manager.set_default("custom");
    assert_eq!(manager.default_name(), "custom");

    let result = manager.get_auth_challenge(None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().nonce, "nonce-custom");

    manager.set_default("gta");
    let result = manager.get_auth_challenge(None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().nonce, "nonce-gta");
}

/// RUST_GTA_RBS_TP_ATTEST_Provider_032
/// as_provider=None且默认provider未注册时返回ManagementProviderNotFound。
#[tokio::test]
async fn test_provider_032_default_unregistered_fails() {
    let manager = AttestationManager::new();
    assert_eq!(manager.default_name(), "gta");

    let result = manager.get_auth_challenge(None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), RbsError::ManagementProviderNotFound(_)));
}

/// RUST_GTA_RBS_TP_ATTEST_Provider_032
/// 验证attest()在as_provider=None时也使用默认provider路由。
#[tokio::test]
async fn test_provider_032_attest_uses_default() {
    let manager = make_manager_with_gta("nonce");
    let req = make_attest_request(None);
    let result = manager.attest(req).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().token, "mock-token");
}

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

//! Unit tests for `AttestationManager` -- provider registration, routing, and error handling.
//!
//! Test scenarios UT-AM-001 through UT-AM-010.

use async_trait::async_trait;
use rbs_api_types::error::RbsError;
use rbs_api_types::{AttestRequest, AttestResponse, AuthChallengeResponse, RbcMeasurement};
use rbs_core::{AttestationManager, AttestationProvider};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Mock attestation provider
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockProvider {
    name: String,
    challenge_response: AuthChallengeResponse,
    attest_response: AttestResponse,
    should_fail: bool,
}

#[async_trait]
impl AttestationProvider for MockProvider {
    async fn get_auth_challenge(&self, _as_provider: Option<&str>) -> Result<AuthChallengeResponse, RbsError> {
        if self.should_fail {
            return Err(RbsError::InternalUnexpected { context: "mock challenge fail".to_string() });
        }
        Ok(self.challenge_response.clone())
    }

    async fn attest(&self, _req: AttestRequest) -> Result<AttestResponse, RbsError> {
        if self.should_fail {
            return Err(RbsError::InternalUnexpected { context: "mock attest fail".to_string() });
        }
        Ok(self.attest_response.clone())
    }
}

fn make_mock_provider(name: &str, nonce: &str) -> Arc<dyn AttestationProvider> {
    let challenge = AuthChallengeResponse { nonce: nonce.to_string() };
    let attest = AttestResponse { token: "mock-token".to_string() };
    let provider = MockProvider {
        name: name.to_string(),
        challenge_response: challenge,
        attest_response: attest,
        should_fail: false,
    };
    Arc::new(provider)
}

fn make_attest_request(as_provider: Option<&str>) -> AttestRequest {
    AttestRequest {
        as_provider: as_provider.map(|s| s.to_string()),
        rbc_evidences: rbs_api_types::RbcEvidencesPayload {
            measurements: vec![RbcMeasurement {
                nonce: "test-nonce".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    }
}

// ===========================================================================
// UT-AM-001: new() creates empty manager with default "gta"
// ===========================================================================

/// UT-AM-001: new() creates an empty manager with default "gta".
#[test]
fn test_new_manager_is_empty() {
    let manager = AttestationManager::new();
    assert_eq!(manager.default_name(), "gta");
}

// ===========================================================================
// UT-AM-002: register() adds provider to backends map
// ===========================================================================

/// UT-AM-002: register() makes provider available for routing.
#[tokio::test]
async fn test_register_provider() {
    let mut manager = AttestationManager::new();
    let provider = make_mock_provider("test-provider", "nonce123");
    manager.register("test-provider", provider);

    let result = manager.get_auth_challenge(Some("test-provider")).await;
    assert!(result.is_ok());
}

// ===========================================================================
// UT-AM-003: set_default() changes default provider
// ===========================================================================

/// UT-AM-003: set_default() changes the default provider name.
#[test]
fn test_set_default_provider() {
    let mut manager = AttestationManager::new();
    manager.set_default("custom");
    assert_eq!(manager.default_name(), "custom");
}

// ===========================================================================
// UT-AM-004: get_auth_challenge(None) uses default provider
// ===========================================================================

/// UT-AM-004: get_auth_challenge(None) uses default provider ("gta" by default).
/// Since no provider is registered, it returns ProviderNotFound.
#[tokio::test]
async fn test_get_auth_challenge_default_not_found() {
    let manager = AttestationManager::new();
    let result = manager.get_auth_challenge(None).await;
    assert!(result.is_err());
}

// ===========================================================================
// UT-AM-005: get_auth_challenge with specific registered provider
// ===========================================================================

/// UT-AM-005: get_auth_challenge(Some("provider")) routes to the registered provider.
#[tokio::test]
async fn test_get_auth_challenge_routes_to_named_provider() {
    let mut manager = AttestationManager::new();
    let provider1 = make_mock_provider("provider1", "nonce1");
    let provider2 = make_mock_provider("provider2", "nonce2");
    manager.register("provider1", provider1);
    manager.register("provider2", provider2);

    let result = manager.get_auth_challenge(Some("provider2")).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().nonce, "nonce2");
}

// ===========================================================================
// UT-AM-006: get_auth_challenge with unknown provider returns error
// ===========================================================================

/// UT-AM-006: get_auth_challenge for unregistered provider -> ProviderNotFound.
#[tokio::test]
async fn test_get_auth_challenge_unknown_provider_fails() {
    let manager = AttestationManager::new();
    let result = manager.get_auth_challenge(Some("nonexistent")).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(format!("{}", err).contains("nonexistent"));
}

// ===========================================================================
// UT-AM-007: attest() routes to named provider
// ===========================================================================

/// UT-AM-007: attest() with explicit provider routes to that provider.
#[tokio::test]
async fn test_attest_routes_to_named_provider() {
    let mut manager = AttestationManager::new();
    let provider = make_mock_provider("gta", "nonce");
    manager.register("gta", provider);

    let req = make_attest_request(Some("gta"));
    let result = manager.attest(req).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().token, "mock-token");
}

// ===========================================================================
// UT-AM-008: attest() uses default provider when as_provider is None
// ===========================================================================

/// UT-AM-008: attest() without as_provider uses default "gta" (unregistered -> error).
#[tokio::test]
async fn test_attest_uses_default_provider_unregistered() {
    let mut manager = AttestationManager::new();
    manager.set_default("unregistered");

    let req = make_attest_request(None);
    let result = manager.attest(req).await;
    assert!(result.is_err());
}

// ===========================================================================
// UT-AM-009: attest() with registered default provider succeeds
// ===========================================================================

/// UT-AM-009: attest() with default provider registered succeeds.
#[tokio::test]
async fn test_attest_with_registered_default() {
    let mut manager = AttestationManager::new();
    let provider = make_mock_provider("gta", "nonce");
    manager.register("gta", provider);
    manager.set_default("gta");

    let req = make_attest_request(None);
    let result = manager.attest(req).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().token, "mock-token");
}

// ===========================================================================
// UT-AM-010: multiple providers registered, default switches correctly
// ===========================================================================

/// UT-AM-010: multiple providers registered, switching default routes correctly.
#[tokio::test]
async fn test_multiple_providers_default_switch() {
    let mut manager = AttestationManager::new();
    let provider1 = make_mock_provider("provider1", "nonce1");
    let provider2 = make_mock_provider("provider2", "nonce2");
    manager.register("provider1", provider1);
    manager.register("provider2", provider2);

    manager.set_default("provider1");
    let result = manager.get_auth_challenge(None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().nonce, "nonce1");

    manager.set_default("provider2");
    let result = manager.get_auth_challenge(None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().nonce, "nonce2");
}
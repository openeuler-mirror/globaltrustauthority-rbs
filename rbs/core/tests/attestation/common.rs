/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Shared test helpers for attestation integration tests.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use rbs_api_types::config::{
    AttestationBackendConfig, AttestationBackendMode, AttestationBuiltinConfig, AttestationConfig,
    AttestationCredentials, AttestationRestConfig, AdminConfig, AdminKeyConfig,
    AuthConfig, BearerTokenVerificationConfig, AttestTokenVerificationConfig,
    LoggingConfig, PolicyLimitsConfig, RbsConfig, Sensitive,
};
use rbs_api_types::error::RbsError;
use rbs_api_types::{
    AttestRequest, AttestResponse, AuthChallengeResponse, RbcEvidenceItem, RbcMeasurement,
};
use rbs_core::{AttestationManager, AttestationProvider};

// ---------------------------------------------------------------------------
// Mock attestation provider
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MockProvider {
    pub challenge_response: AuthChallengeResponse,
    pub attest_response: AttestResponse,
    pub should_fail: bool,
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

pub fn make_mock_provider(nonce: &str) -> Arc<dyn AttestationProvider> {
    let provider = MockProvider {
        challenge_response: AuthChallengeResponse { nonce: nonce.to_string() },
        attest_response: AttestResponse { token: "mock-token".to_string() },
        should_fail: false,
    };
    Arc::new(provider)
}

pub fn make_mock_provider_with_token(nonce: &str, token: &str) -> Arc<dyn AttestationProvider> {
    let provider = MockProvider {
        challenge_response: AuthChallengeResponse { nonce: nonce.to_string() },
        attest_response: AttestResponse { token: token.to_string() },
        should_fail: false,
    };
    Arc::new(provider)
}

// ---------------------------------------------------------------------------
// AttestRequest builders
// ---------------------------------------------------------------------------

pub fn make_attest_request(as_provider: Option<&str>) -> AttestRequest {
    AttestRequest {
        as_provider: as_provider.map(|s| s.to_string()),
        rbc_evidences: rbs_api_types::RbcEvidencesPayload {
            measurements: vec![RbcMeasurement {
                nonce: "test-nonce".to_string(),
                evidences: Some(vec![RbcEvidenceItem {
                    attester_type: Some("tpm_boot".to_string()),
                    evidence: Some(serde_json::json!({"quote": "abc123"})),
                    policy_ids: None,
                    ref_value_id: None,
                }]),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Build a manager with a single registered "gta" provider returning the given nonce.
pub fn make_manager_with_gta(nonce: &str) -> AttestationManager {
    let mut manager = AttestationManager::new();
    manager.register("gta", make_mock_provider(nonce));
    manager.set_default("gta");
    manager
}

// ---------------------------------------------------------------------------
// Valid RbsConfig builder for config validation tests
// ---------------------------------------------------------------------------

/// Build a fully valid `RbsConfig` whose `validate()` does not panic.
/// Individual tests clone this and mutate the field under test.
pub fn make_valid_rbs_config() -> RbsConfig {
    let mut backends = HashMap::new();
    backends.insert(
        "gta".to_string(),
        AttestationBackendConfig {
            mode: AttestationBackendMode::Rest,
            rest: AttestationRestConfig {
                base_url: "https://gta.example.com".to_string(),
                timeout_secs: 30,
                retries: 3,
                tls_verify: true,
                ca_file: String::new(),
                client_cert_path: String::new(),
                client_key_path: String::new(),
                credentials: AttestationCredentials {
                    user_id: "valid-user-1".to_string(),
                    main_api_key: Sensitive::new(String::new()),
                    sub_api_key: Sensitive::new(String::new()),
                },
            },
            builtin: AttestationBuiltinConfig::default(),
        },
    );

    RbsConfig {
        rest: None,
        logging: LoggingConfig::default(),
        storage: None,
        attestation: AttestationConfig {
            default_as_provider: "gta".to_string(),
            backends,
        },
        auth: AuthConfig {
            attest_token: AttestTokenVerificationConfig {
                public_key_path: Some("/tmp/dummy_attest.pem".to_string()),
                jwks_file: None,
                issuer: "Global Trust Authority".to_string(),
                audience: Some("rbs".to_string()),
            },
            bearer_token: BearerTokenVerificationConfig {
                issuer: "Global Trust Authority".to_string(),
                audience: "rbs".to_string(),
            },
        },
        admin: AdminConfig {
            max_users: 10,
            admin_key: AdminKeyConfig {
                public_key_path: Some("/tmp/dummy_admin.pem".to_string()),
                jwks_file: None,
            },
        },
        policy: PolicyLimitsConfig::default(),
        resource: None,
    }
}



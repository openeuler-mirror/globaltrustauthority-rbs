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

//! Integration tests for the `as_*()` accessor contract on `AttestationProvider`
//! and `AttestationManager` subtype resolution (`ref_value_for` / `cert_for` /
//! `policy_for`).
//!
//! Verifies the `module_interfaces.md` §3.1 target contract: a single registry
//! with subtype accessors (default `None` → `NotImplemented` / 501), not a
//! parallel management trait.

use async_trait::async_trait;
use rbs_api_types::attestation_mgmt::{PolicyListQuery, AttestationPolicyListResponse};
use rbs_api_types::error::RbsError;
use rbs_api_types::{
    AttestationPolicy, AuthChallengeResponse,
    AttestRequest, AttestResponse, CertCreateRequest, CertDeleteRequest, CertListQuery,
    CertListResponse, CertMutationResponse, CertMutationResult, CertRecord, CertUpdateRequest,
    PolicyCreateRequest, PolicyDeleteRequest, PolicyMutationResponse, PolicyUpdateRequest,
    RefValue, RefValueCreateRequest, RefValueDeleteRequest, RefValueListQuery,
    RefValueListResponse, RefValueMutationResponse, RefValueUpdateRequest,
};
use rbs_core::{
    AttestationManager, AttestationProvider, CertProvider, PolicyProvider, RefValueProvider,
};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Mock full provider — implements AttestationProvider + all 3 subtypes;
// as_*() returns Some(self).
// ---------------------------------------------------------------------------

struct MockFullProvider;

fn mock_ref_value(id: &str) -> RefValue {
    RefValue {
        id: id.to_string(),
        uid: Some("test_01".to_string()),
        name: "mock-baseline".to_string(),
        attester_type: "tpm".to_string(),
        description: None,
        content: Some("mock-content".to_string()),
        content_type: Some("jwt".to_string()),
        version: Some(1),
        valid_code: Some(0),
    }
}

fn mock_mutation(id: &str) -> RefValueMutationResponse {
    RefValueMutationResponse {
        ref_value: rbs_api_types::RefValueMutation {
            id: id.to_string(),
            name: "mock-baseline".to_string(),
            version: 1,
        },
    }
}

#[async_trait]
impl AttestationProvider for MockFullProvider {
    async fn get_auth_challenge(
        &self,
        _as_provider: Option<&str>,
    ) -> Result<AuthChallengeResponse, RbsError> {
        Ok(AuthChallengeResponse {
            nonce: "n".to_string(),
        })
    }

    async fn attest(&self, _req: AttestRequest) -> Result<AttestResponse, RbsError> {
        Ok(AttestResponse {
            token: "t".to_string(),
        })
    }

    fn as_ref_value(&self) -> Option<&dyn RefValueProvider> {
        Some(self)
    }
    fn as_cert(&self) -> Option<&dyn CertProvider> {
        Some(self)
    }
    fn as_policy(&self) -> Option<&dyn PolicyProvider> {
        Some(self)
    }
}

#[async_trait]
impl RefValueProvider for MockFullProvider {
    async fn list_ref_values(
        &self,
        _as_provider: &str,
        _query: RefValueListQuery,
    ) -> Result<RefValueListResponse, RbsError> {
        Ok(RefValueListResponse {
            ref_values: vec![mock_ref_value("R1")],
            total_count: Some(1),
            limit: Some(10),
            offset: Some(0),
        })
    }

    async fn get_ref_value(&self, _as_provider: &str, id: String) -> Result<RefValueListResponse, RbsError> {
        Ok(RefValueListResponse {
            ref_values: vec![mock_ref_value(&id)],
            total_count: None,
            limit: None,
            offset: None,
        })
    }

    async fn create_ref_value(
        &self,
        _as_provider: &str,
        _req: RefValueCreateRequest,
    ) -> Result<RefValueMutationResponse, RbsError> {
        Ok(mock_mutation("new-id"))
    }

    async fn update_ref_value(
        &self,
        _as_provider: &str,
        req: RefValueUpdateRequest,
    ) -> Result<RefValueMutationResponse, RbsError> {
        Ok(mock_mutation(&req.id))
    }

    async fn delete_ref_values(
        &self,
        _as_provider: &str,
        _req: RefValueDeleteRequest,
    ) -> Result<(), RbsError> {
        Ok(())
    }

    async fn delete_ref_value(&self, _as_provider: &str, _id: String) -> Result<(), RbsError> {
        Ok(())
    }
}

#[async_trait]
impl CertProvider for MockFullProvider {
    async fn list_certs(
        &self,
        _as_provider: &str,
        _query: CertListQuery,
    ) -> Result<CertListResponse, RbsError> {
        Ok(CertListResponse {
            certs: vec![],
            crls: vec![],
            total_count: Some(0),
            limit: Some(10),
            offset: Some(0),
        })
    }

    async fn get_cert(&self, _as_provider: &str, id: String) -> Result<CertListResponse, RbsError> {
        Ok(CertListResponse {
            certs: vec![CertRecord {
                cert_id: Some(id),
                cert_name: Some("mock-cert".to_string()),
                description: None,
                content: None,
                cert_type: None,
                is_default: None,
                version: Some(1),
                create_time: None,
                update_time: None,
                valid_code: None,
                cert_revoked_date: None,
                cert_revoked_reason: None,
            }],
            crls: vec![],
            total_count: None,
            limit: None,
            offset: None,
        })
    }

    async fn create_cert(
        &self,
        _as_provider: &str,
        _req: CertCreateRequest,
    ) -> Result<CertMutationResponse, RbsError> {
        Ok(CertMutationResponse {
            cert: Some(CertMutationResult {
                cert_id: Some("new-cert".to_string()),
                cert_name: Some("mock-cert".to_string()),
                version: Some(1),
            }),
            crl: None,
        })
    }

    async fn update_cert(
        &self,
        _as_provider: &str,
        req: CertUpdateRequest,
    ) -> Result<CertMutationResponse, RbsError> {
        Ok(CertMutationResponse {
            cert: Some(CertMutationResult {
                cert_id: Some(req.id),
                cert_name: Some("mock-cert".to_string()),
                version: Some(2),
            }),
            crl: None,
        })
    }

    async fn delete_certs(
        &self,
        _as_provider: &str,
        _req: CertDeleteRequest,
    ) -> Result<(), RbsError> {
        Ok(())
    }

    async fn delete_cert(&self, _as_provider: &str, _id: String) -> Result<(), RbsError> {
        Ok(())
    }
}

#[async_trait]
impl PolicyProvider for MockFullProvider {
    async fn list_policies(
        &self,
        _as_provider: &str,
        _query: PolicyListQuery,
    ) -> Result<AttestationPolicyListResponse, RbsError> {
        Ok(AttestationPolicyListResponse {
            policies: vec![],
            total_count: Some(0),
            limit: Some(10),
            offset: Some(0),
        })
    }

    async fn get_policy(
        &self,
        _as_provider: &str,
        id: String,
    ) -> Result<AttestationPolicyListResponse, RbsError> {
        Ok(AttestationPolicyListResponse {
            policies: vec![AttestationPolicy {
                id,
                name: "mock-policy".to_string(),
                description: None,
                content: None,
                attester_type: vec!["tpm".to_string()],
                is_default: None,
                version: Some(1),
                update_time: None,
                valid_code: None,
            }],
            total_count: None,
            limit: None,
            offset: None,
        })
    }

    async fn create_policy(
        &self,
        _as_provider: &str,
        _req: PolicyCreateRequest,
    ) -> Result<PolicyMutationResponse, RbsError> {
        Ok(PolicyMutationResponse {
            policy: rbs_api_types::PolicyMutation {
                id: "new-policy".to_string(),
                name: "mock-policy".to_string(),
                version: 1,
            },
        })
    }

    async fn update_policy(
        &self,
        _as_provider: &str,
        req: PolicyUpdateRequest,
    ) -> Result<PolicyMutationResponse, RbsError> {
        Ok(PolicyMutationResponse {
            policy: rbs_api_types::PolicyMutation {
                id: req.id,
                name: "mock-policy".to_string(),
                version: 2,
            },
        })
    }

    async fn delete_policies(
        &self,
        _as_provider: &str,
        _req: PolicyDeleteRequest,
    ) -> Result<(), RbsError> {
        Ok(())
    }

    async fn delete_policy(&self, _as_provider: &str, _id: String) -> Result<(), RbsError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mock bare provider — implements only AttestationProvider (as_* → None).
// ---------------------------------------------------------------------------

struct MockBareProvider;

#[async_trait]
impl AttestationProvider for MockBareProvider {
    async fn get_auth_challenge(
        &self,
        _as_provider: Option<&str>,
    ) -> Result<AuthChallengeResponse, RbsError> {
        Ok(AuthChallengeResponse {
            nonce: "n".to_string(),
        })
    }

    async fn attest(&self, _req: AttestRequest) -> Result<AttestResponse, RbsError> {
        Ok(AttestResponse {
            token: "t".to_string(),
        })
    }
    // as_ref_value / as_cert / as_policy default to None
}

// ===========================================================================
// TC1: MockFullProvider implements all traits and as_*() returns Some(self)
// ===========================================================================

#[test]
fn tc1_full_provider_compiles_and_exposes_subtypes() {
    let p = MockFullProvider;
    let ap: &dyn AttestationProvider = &p;
    assert!(ap.as_ref_value().is_some());
    assert!(ap.as_cert().is_some());
    assert!(ap.as_policy().is_some());
}

// ===========================================================================
// TC2: register + ref_value_for returns subtype, methods work
// ===========================================================================

#[tokio::test]
async fn tc2_ref_value_for_returns_subtype_and_works() {
    let mut manager = AttestationManager::new();
    manager.register("gta", Arc::new(MockFullProvider));

    let provider = manager.ref_value_for(Some("gta")).expect("ref_value_for");
    let result = provider
        .list_ref_values(
            "gta",
            RefValueListQuery {
                ids: None,
                attester_type: None,
                limit: None,
                offset: None,
            },
        )
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().ref_values.len(), 1);
}

#[tokio::test]
async fn tc2_ref_value_get_single_via_manager() {
    let mut manager = AttestationManager::new();
    manager.register("gta", Arc::new(MockFullProvider));

    let provider = manager.ref_value_for(Some("gta")).unwrap();
    let result = provider.get_ref_value("gta", "R1".to_string()).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().ref_values[0].id, "R1");
}

#[tokio::test]
async fn tc2_ref_value_create_via_manager() {
    let mut manager = AttestationManager::new();
    manager.register("gta", Arc::new(MockFullProvider));

    let provider = manager.ref_value_for(Some("gta")).unwrap();
    let req = RefValueCreateRequest {
        name: "test-baseline".to_string(),
        attester_type: "tpm".to_string(),
        content: "data".to_string(),
        content_type: Some("jwt".to_string()),
        description: None,
    };
    let result = provider.create_ref_value("gta", req).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().ref_value.id, "new-id");
}

// ===========================================================================
// TC3: cert_for / policy_for return subtypes and methods work
// ===========================================================================

#[tokio::test]
async fn tc3_cert_for_returns_subtype() {
    let mut manager = AttestationManager::new();
    manager.register("gta", Arc::new(MockFullProvider));

    let provider = manager.cert_for(Some("gta")).expect("cert_for");
    let result = provider
        .list_certs(
            "gta",
            CertListQuery {
                ids: None,
                cert_type: None,
                limit: None,
                offset: None,
            },
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn tc3_policy_for_returns_subtype() {
    let mut manager = AttestationManager::new();
    manager.register("gta", Arc::new(MockFullProvider));

    let provider = manager.policy_for(Some("gta")).expect("policy_for");
    let result = provider
        .create_policy(
            "gta",
            PolicyCreateRequest {
                name: "test-policy".to_string(),
                attester_type: vec!["tpm".to_string()],
                content_type: "jwt".to_string(),
                content: "data".to_string(),
                is_default: None,
                description: None,
            },
        )
        .await;
    assert!(result.is_ok());
}

// ===========================================================================
// TC4: unregistered name → ManagementProviderNotFound (404)
// ===========================================================================

#[test]
fn tc4_unregistered_returns_management_provider_not_found() {
    let manager = AttestationManager::new();
    let err = manager.ref_value_for(Some("nonexistent")).err().unwrap();
    assert!(matches!(err, RbsError::ManagementProviderNotFound(_)));
    assert_eq!(err.http_status(), 404);
}

#[test]
fn tc4_empty_registry_returns_not_found() {
    let manager = AttestationManager::new();
    assert!(manager.ref_value_for(Some("gta")).is_err());
    assert!(manager.cert_for(Some("gta")).is_err());
    assert!(manager.policy_for(Some("gta")).is_err());
}

// ===========================================================================
// TC5: bare provider (as_* → None) → NotImplemented (501)
// ===========================================================================

#[test]
fn tc5_bare_provider_returns_not_implemented() {
    let mut manager = AttestationManager::new();
    manager.register("builtin", Arc::new(MockBareProvider));

    let err = manager.ref_value_for(Some("builtin")).err().unwrap();
    assert!(matches!(err, RbsError::NotImplemented));
    assert_eq!(err.http_status(), 501);

    let err = manager.cert_for(Some("builtin")).err().unwrap();
    assert!(matches!(err, RbsError::NotImplemented));

    let err = manager.policy_for(Some("builtin")).err().unwrap();
    assert!(matches!(err, RbsError::NotImplemented));
}

// ===========================================================================
// TC6: default provider resolution (as_provider = None)
// ===========================================================================

#[test]
fn tc6_default_provider_resolution() {
    let mut manager = AttestationManager::new();
    manager.register("gta", Arc::new(MockFullProvider));

    // as_provider = None → resolves to default "gta"
    let provider = manager.ref_value_for(None).expect("default ref_value_for");
    assert!(std::ptr::eq(
        provider as *const _ as *const u8,
        manager.ref_value_for(Some("gta")).unwrap() as *const _ as *const u8,
    ));
}

// ===========================================================================
// TC7: single registry — runtime and management share the same provider
// ===========================================================================

#[tokio::test]
async fn tc7_single_registry_runtime_and_management_share_provider() {
    let mut manager = AttestationManager::new();
    manager.register("gta", Arc::new(MockFullProvider));

    // Runtime attestation works
    let challenge = manager.get_auth_challenge(Some("gta")).await;
    assert!(challenge.is_ok());

    // Management subtypes also work on the same registered provider
    assert!(manager.ref_value_for(Some("gta")).is_ok());
    assert!(manager.cert_for(Some("gta")).is_ok());
    assert!(manager.policy_for(Some("gta")).is_ok());
}

// ===========================================================================
// TC8: subtype traits are exported from rbs_core crate root
// ===========================================================================

#[test]
fn tc8_subtypes_accessible_from_crate_root() {
    fn _check_rv(_p: &dyn rbs_core::RefValueProvider) {}
    fn _check_cert(_p: &dyn rbs_core::CertProvider) {}
    fn _check_policy(_p: &dyn rbs_core::PolicyProvider) {}
    _check_rv(&MockFullProvider);
    _check_cert(&MockFullProvider);
    _check_policy(&MockFullProvider);
}

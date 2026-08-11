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

//! Attestation Provider trait definition.
//!
//! Defines the runtime `AttestationProvider` trait (challenge/attest) and the
//! optional management subtypes (`RefValueProvider`, `CertProvider`,
//! `PolicyProvider`) exposed via `as_ref_value` / `as_cert` / `as_policy`
//! accessors.  Only `AttestationProvider` is registered in the
//! `AttestationManager` registry; subtypes are reached through the accessors
//! (default `None` → `NotImplemented` / 501).
//!
//! This follows the contract in `module_interfaces.md` §3.1: a single registry
//! with subtype accessors, not a parallel management trait.

use async_trait::async_trait;
use rbs_api_types::attestation_mgmt::{PolicyListQuery, AttestationPolicyListResponse};
use rbs_api_types::error::RbsError;
use rbs_api_types::{
    AttestRequest, AttestResponse, AuthChallengeResponse,
    CertCreateRequest, CertDeleteRequest, CertListQuery, CertListResponse,
    CertMutationResponse, CertUpdateRequest, PolicyCreateRequest, PolicyDeleteRequest,
    PolicyMutationResponse, PolicyUpdateRequest, RefValueCreateRequest,
    RefValueDeleteRequest, RefValueListQuery, RefValueListResponse, RefValueMutationResponse,
    RefValueUpdateRequest,
};

/// Result type alias using RbsError.
type Result<T> = std::result::Result<T, RbsError>;

/// Attestation provider trait.
///
/// Implementors handle nonce generation and attestation validation.
/// RBS does NOT implement verify_token; token verification is done internally.
///
/// Optional management subtypes are exposed via `as_ref_value` / `as_cert` /
/// `as_policy` (default `None`).  A full GTA backend implements all three
/// subtypes and returns `Some(self)` from each accessor.
#[async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Get authentication challenge (nonce).
    async fn get_auth_challenge(&self, as_provider: Option<&str>) -> Result<AuthChallengeResponse>;

    /// Submit attestation evidence and obtain AttestToken.
    async fn attest(&self, req: AttestRequest) -> Result<AttestResponse>;

    /// Optional subtype: reference value (baseline) management.
    /// Default `None` → `NotImplemented` / 501 when accessed via
    /// `AttestationManager::ref_value_for`.
    fn as_ref_value(&self) -> Option<&dyn RefValueProvider> {
        None
    }

    /// Optional subtype: certificate management.
    fn as_cert(&self) -> Option<&dyn CertProvider> {
        None
    }

    /// Optional subtype: attestation policy management.
    fn as_policy(&self) -> Option<&dyn PolicyProvider> {
        None
    }
}

/// Subtype: reference value (baseline) management — ref_value CRUD.
///
/// Reached via `AttestationManager::ref_value_for` → `as_ref_value`.
/// Not separately registered; exposed as an accessor on `AttestationProvider`.
#[async_trait]
pub trait RefValueProvider: Send + Sync {
    async fn list_ref_values(
        &self,
        as_provider: &str,
        query: RefValueListQuery,
    ) -> Result<RefValueListResponse>;
    async fn get_ref_value(&self, as_provider: &str, id: String) -> Result<RefValueListResponse>;
    async fn create_ref_value(
        &self,
        as_provider: &str,
        req: RefValueCreateRequest,
    ) -> Result<RefValueMutationResponse>;
    async fn update_ref_value(
        &self,
        as_provider: &str,
        req: RefValueUpdateRequest,
    ) -> Result<RefValueMutationResponse>;
    async fn delete_ref_values(
        &self,
        as_provider: &str,
        req: RefValueDeleteRequest,
    ) -> Result<()>;
    async fn delete_ref_value(&self, as_provider: &str, id: String) -> Result<()>;
}

/// Subtype: certificate management — cert/CRL CRUD.
///
/// Reached via `AttestationManager::cert_for` → `as_cert`.
#[async_trait]
pub trait CertProvider: Send + Sync {
    async fn list_certs(
        &self,
        as_provider: &str,
        query: CertListQuery,
    ) -> Result<CertListResponse>;
    async fn get_cert(&self, as_provider: &str, id: String) -> Result<CertListResponse>;
    async fn create_cert(
        &self,
        as_provider: &str,
        req: CertCreateRequest,
    ) -> Result<CertMutationResponse>;
    async fn update_cert(
        &self,
        as_provider: &str,
        req: CertUpdateRequest,
    ) -> Result<CertMutationResponse>;
    async fn delete_certs(&self, as_provider: &str, req: CertDeleteRequest) -> Result<()>;
    async fn delete_cert(&self, as_provider: &str, id: String) -> Result<()>;
}

/// Subtype: attestation policy management — policy CRUD.
///
/// Reached via `AttestationManager::policy_for` → `as_policy`.
#[async_trait]
pub trait PolicyProvider: Send + Sync {
    async fn list_policies(
        &self,
        as_provider: &str,
        query: PolicyListQuery,
    ) -> Result<AttestationPolicyListResponse>;
    async fn get_policy(&self, as_provider: &str, id: String) -> Result<AttestationPolicyListResponse>;
    async fn create_policy(
        &self,
        as_provider: &str,
        req: PolicyCreateRequest,
    ) -> Result<PolicyMutationResponse>;
    async fn update_policy(
        &self,
        as_provider: &str,
        req: PolicyUpdateRequest,
    ) -> Result<PolicyMutationResponse>;
    async fn delete_policies(
        &self,
        as_provider: &str,
        req: PolicyDeleteRequest,
    ) -> Result<()>;
    async fn delete_policy(&self, as_provider: &str, id: String) -> Result<()>;
}

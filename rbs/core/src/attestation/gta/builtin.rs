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

//! Built-in attestation provider implementation.
//!
//! TODO: Built-in mode requires GTA Core library to be integrated.
//! When GTA Core is available, this provider should delegate to GTA Core for:
//! - Nonce generation (via TEE/TPM hardware attestation)
//! - Evidence verification
//!
//! Currently this is a placeholder that returns NotImplemented for development/testing.

use async_trait::async_trait;
use rbs_api_types::{
    AttestRequest, AttestResponse, AuthChallengeResponse,
};

use crate::attestation::provider::AttestationProvider;
use crate::RbsError;

/// Built-in attestation provider placeholder.
///
/// TODO: This is a placeholder implementation.
/// When GTA Core library is available, this should:
/// - Hold a reference to GTA Core
/// - Call `gta_core.generate_nonce()` for challenge
/// - Call `gta_core.verify_evidence()` for attestation
#[derive(Debug, Clone)]
pub struct BuiltinAttestationProvider;

impl BuiltinAttestationProvider {
    /// Create a new built-in provider placeholder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for BuiltinAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AttestationProvider for BuiltinAttestationProvider {
    async fn get_auth_challenge(&self, _as_provider: Option<&str>) -> Result<AuthChallengeResponse, RbsError> {
        Err(RbsError::NotImplemented)
    }

    async fn attest(&self, _req: AttestRequest) -> Result<AttestResponse, RbsError> {
        Err(RbsError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::provider::AttestationProvider;

    #[test]
    fn new_and_default_are_equivalent() {
        let a = BuiltinAttestationProvider::new();
        let b = BuiltinAttestationProvider::default();
        assert_eq!(format!("{:?}", a), format!("{:?}", b));
    }

    #[tokio::test]
    async fn get_auth_challenge_returns_not_implemented() {
        let provider = BuiltinAttestationProvider::new();
        let result = provider.get_auth_challenge(None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RbsError::NotImplemented));
    }

    #[tokio::test]
    async fn get_auth_challenge_with_provider_name_returns_not_implemented() {
        let provider = BuiltinAttestationProvider::new();
        let result = provider.get_auth_challenge(Some("gta")).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RbsError::NotImplemented));
    }

    #[tokio::test]
    async fn attest_returns_not_implemented() {
        let provider = BuiltinAttestationProvider::new();
        let result = provider.attest(AttestRequest::default()).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RbsError::NotImplemented));
    }
}

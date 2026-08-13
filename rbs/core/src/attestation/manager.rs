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

//! Attestation Manager implementation.
//!
//! Routes attestation requests to the appropriate provider based on `as_provider`.
//! Maintains a **single** registry of `AttestationProvider` instances.
//! Management subtypes (`RefValueProvider` / `CertProvider` / `PolicyProvider`)
//! are reached through the `as_ref_value` / `as_cert` / `as_policy` accessors
//! on the registered provider — not through a parallel registry.
//!
//! This follows the contract in `module_interfaces.md` §3.1.

use std::collections::HashMap;
use std::sync::Arc;

use rbs_api_types::error::RbsError;
use rbs_api_types::{AttestRequest, AttestResponse, AuthChallengeResponse};

use super::provider::{AttestationProvider, CertProvider, PolicyProvider, RefValueProvider};

/// Result type alias using RbsError.
type Result<T> = std::result::Result<T, RbsError>;

/// Attestation manager.
///
/// Routes attestation requests to the appropriate provider based on `as_provider`.
/// Maintains a single registry of `AttestationProvider` instances; management
/// subtypes are exposed via `as_ref_value` / `as_cert` / `as_policy` accessors.
pub struct AttestationManager {
    backends: HashMap<String, Arc<dyn AttestationProvider>>,
    default_provider: String,
}

impl std::fmt::Debug for AttestationManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationManager")
            .field("backends", &self.backends.keys().collect::<Vec<_>>())
            .field("default_provider", &self.default_provider)
            .finish()
    }
}

impl AttestationManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
            default_provider: "gta".to_string(),
        }
    }

    /// Register a provider with the given name.
    ///
    /// Only `AttestationProvider` is registered.  Management subtypes are
    /// reached through the `as_ref_value` / `as_cert` / `as_policy` accessors
    /// on the provider (default `None` → `NotImplemented` / 501).
    pub fn register(&mut self, name: &str, provider: Arc<dyn AttestationProvider>) {
        self.backends.insert(name.to_string(), provider);
    }

    /// Set the default provider name.
    pub fn set_default(&mut self, name: &str) {
        self.default_provider = name.to_string();
    }

    /// Get the default provider name.
    pub fn default_name(&self) -> &str {
        &self.default_provider
    }

    /// Resolve the provider name (defaulting when `as_provider` is `None`).
    fn resolve_name<'a>(&'a self, as_provider: Option<&'a str>) -> &'a str {
        as_provider.unwrap_or(&self.default_provider)
    }

    /// Look up a provider by name, returning `ManagementProviderNotFound` (404)
    /// when the name is not in the registry.
    fn lookup(&self, as_provider: Option<&str>) -> Result<&Arc<dyn AttestationProvider>> {
        let name = self.resolve_name(as_provider);
        self.backends.get(name).ok_or_else(|| {
            log::error!("Attestation provider '{}' not found", name);
            RbsError::ManagementProviderNotFound(name.to_string())
        })
    }

    // ── Runtime attestation ──

    /// Get auth challenge from the appropriate provider.
    pub async fn get_auth_challenge(&self, as_provider: Option<&str>) -> Result<AuthChallengeResponse> {
        let provider_name = self.resolve_name(as_provider);
        log::debug!("Attestation get_auth_challenge: provider='{}'", provider_name);
        let provider = self.lookup(as_provider)?;
        provider.get_auth_challenge(as_provider).await
    }

    /// Submit attestation evidence.
    pub async fn attest(&self, req: AttestRequest) -> Result<AttestResponse> {
        let as_provider = req.as_provider.as_deref();
        let provider_name = self.resolve_name(as_provider);
        log::info!("Attestation attest requested: provider='{}'", provider_name);
        let provider = self.lookup(as_provider)?;
        provider.attest(req).await
    }

    // ── Management subtypes (via as_* accessors) ──

    /// Get the `RefValueProvider` subtype for the given provider.
    ///
    /// Returns `ManagementProviderNotFound` (404) when the provider name is
    /// not registered, or `NotImplemented` (501) when the provider does not
    /// implement the ref_value subtype (e.g. `BuiltinAttestationProvider`).
    pub fn ref_value_for(&self, as_provider: Option<&str>) -> Result<&dyn RefValueProvider> {
        let name = self.resolve_name(as_provider);
        let provider = self.lookup(as_provider)?;
        provider.as_ref_value().ok_or_else(|| {
            log::warn!(
                "Attestation provider '{}' does not implement RefValueProvider",
                name
            );
            RbsError::NotImplemented
        })
    }

    /// Get the `CertProvider` subtype for the given provider.
    pub fn cert_for(&self, as_provider: Option<&str>) -> Result<&dyn CertProvider> {
        let name = self.resolve_name(as_provider);
        let provider = self.lookup(as_provider)?;
        provider.as_cert().ok_or_else(|| {
            log::warn!(
                "Attestation provider '{}' does not implement CertProvider",
                name
            );
            RbsError::NotImplemented
        })
    }

    /// Get the `PolicyProvider` subtype for the given provider.
    pub fn policy_for(&self, as_provider: Option<&str>) -> Result<&dyn PolicyProvider> {
        let name = self.resolve_name(as_provider);
        let provider = self.lookup(as_provider)?;
        provider.as_policy().ok_or_else(|| {
            log::warn!(
                "Attestation provider '{}' does not implement PolicyProvider",
                name
            );
            RbsError::NotImplemented
        })
    }
}

impl Default for AttestationManager {
    fn default() -> Self {
        Self::new()
    }
}

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

use std::collections::HashMap;
use std::sync::Arc;

use rbs_api_types::error::RbsError;
use rbs_api_types::{AttestRequest, AttestResponse, AuthChallengeResponse};

use super::provider::AttestationProvider;

/// Result type alias using RbsError.
type Result<T> = std::result::Result<T, RbsError>;

/// Attestation manager.
///
/// Routes attestation requests to the appropriate provider based on `as_provider`.
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

    /// Get auth challenge from the appropriate provider.
    pub async fn get_auth_challenge(&self, as_provider: Option<&str>) -> Result<AuthChallengeResponse> {
        let provider_name = as_provider.unwrap_or(&self.default_provider);
        let provider = self
            .backends
            .get(provider_name)
            .ok_or_else(|| RbsError::ProviderNotFound(format!("attestation provider '{}' not found", provider_name)))?;
        provider.get_auth_challenge(as_provider).await
    }

    /// Submit attestation evidence.
    pub async fn attest(&self, req: AttestRequest) -> Result<AttestResponse> {
        let as_provider = req.as_provider.as_deref();
        let provider_name = as_provider.unwrap_or(&self.default_provider);
        let provider = self
            .backends
            .get(provider_name)
            .ok_or_else(|| RbsError::ProviderNotFound(format!("attestation provider '{}' not found", provider_name)))?;
        provider.attest(req).await
    }
}

impl Default for AttestationManager {
    fn default() -> Self {
        Self::new()
    }
}

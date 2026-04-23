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

//! RBS core library.
//!
//! Core business logic modules: attestation, resource, auth, user, etc.
//! Provider traits define the interface; concrete implementations are injected at startup.

mod attestation;
pub mod auth;
mod infra;
mod policy_engine;
mod resource;

use std::sync::Arc;

pub mod system;

pub use attestation::{AttestationManager, AttestationProvider, BuiltinAttestationProvider, GtaRestProvider};
pub use auth::Claims;
pub use resource::{ResourceManager, ResourceProvider};
pub use infra::logging::init_logging;
pub use infra::init_database;
pub use infra::rdb;
pub use rbs_api_types::config::{
    AttestationBackendConfig, AttestationBackendMode, AttestationConfig, AttestationRestConfig,
    CoreConfig, LogRotationConfig, LoggingConfig, RotationCompression,
};
pub use rbs_api_types::error::RbsError;
pub use system::{BuildMetadata, RbsVersion, API_VERSION, SERVICE_NAME};

/// Core runtime handle.
///
/// Holds all business logic managers and routes requests to the appropriate provider.
pub struct RbsCore {
    attestation: AttestationManager,
    resource: ResourceManager,
}

impl std::fmt::Debug for RbsCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RbsCore")
            .field("attestation", &self.attestation)
            .field("resource", &self.resource)
            .finish()
    }
}

impl RbsCore {
    /// Create a new RbsCore instance with pre-constructed managers.
    ///
    /// This is the composition root where all managers are assembled.
    #[must_use]
    pub fn new(
        attestation: AttestationManager,
        resource: ResourceManager,
    ) -> Self {
        Self {
            attestation,
            resource,
        }
    }

    /// Returns the attestation manager.
    #[must_use]
    pub fn attestation(&self) -> &AttestationManager {
        &self.attestation
    }

    /// Returns the resource manager.
    #[must_use]
    pub fn resource(&self) -> &ResourceManager {
        &self.resource
    }

    /// System metadata API (version, build info).
    #[must_use]
    pub fn system(&self) -> System {
        System
    }
}

/// Builder for constructing `RbsCore` from configuration.
///
/// Handles provider instantiation and registration as the composition root.
pub struct RbsCoreBuilder {
    config: CoreConfig,
}

impl RbsCoreBuilder {
    /// Create a new builder with the given configuration.
    #[must_use]
    pub fn new(config: CoreConfig) -> Self {
        Self { config }
    }

    /// Build the `RbsCore` instance, registering all providers from config.
    #[must_use]
    pub fn build(self) -> RbsCore {
        let mut attestation = AttestationManager::new();
        attestation.set_default(&self.config.attestation.default_as_provider);

        for (name, backend_config) in &self.config.attestation.backends {
            let provider: Arc<dyn AttestationProvider> = match backend_config.mode {
                AttestationBackendMode::Builtin => {
                    Arc::new(BuiltinAttestationProvider::default()) as Arc<dyn AttestationProvider>
                }
                AttestationBackendMode::Rest => {
                    Arc::new(GtaRestProvider::new(backend_config.rest.clone())) as Arc<dyn AttestationProvider>
                }
            };
            attestation.register(name, provider);
        }

        let resource = ResourceManager::new();

        RbsCore::new(attestation, resource)
    }
}

impl Default for RbsCore {
    fn default() -> Self {
        Self::new(AttestationManager::default(), ResourceManager::default())
    }
}

/// System-scoped operations (version, etc.).
#[derive(Debug, Clone, Copy, Default)]
pub struct System;

impl System {
    /// Returns service version and build metadata.
    #[must_use]
    pub fn version(&self) -> RbsVersion {
        system::get_rbs_version()
    }
}

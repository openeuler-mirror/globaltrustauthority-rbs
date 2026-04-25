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
//! Core business logic modules: attestation, resource, user, etc.
//! Provider traits define the interface; concrete implementations are injected at startup.

mod attestation;
mod resource;
mod user;
mod infra;

pub mod system;

pub use attestation::{AttestationManager, AttestationProvider};
pub use resource::{ResourceManager, ResourceProvider};
pub use user::{UserManager, UserProvider};
pub use infra::logging::init_logging;
pub use infra::init_database;
pub use infra::rdb;
pub use rbs_api_types::config::{CoreConfig, LogRotationConfig, LoggingConfig, RotationCompression};
pub use rbs_api_types::error::RbsError;
pub use system::{BuildMetadata, RbsVersion, API_VERSION, SERVICE_NAME};

/// Core runtime handle.
///
/// Holds all business logic managers and routes requests to the appropriate provider.
pub struct RbsCore {
    attestation: AttestationManager,
    resource: ResourceManager,
    user: UserManager,
}

impl std::fmt::Debug for RbsCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RbsCore")
            .field("attestation", &self.attestation)
            .field("resource", &self.resource)
            .field("user", &self.user)
            .finish()
    }
}

impl RbsCore {
    /// Create a new RbsCore instance with providers registered from config.
    ///
    /// This is the composition root where all providers are assembled.
    #[must_use]
    pub fn new(_config: CoreConfig) -> Self {
        let attestation = AttestationManager::new();
        let resource = ResourceManager::new();
        let user = UserManager::new();

        Self {
            attestation,
            resource,
            user,
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

    /// Returns the user manager.
    #[must_use]
    pub fn user(&self) -> &UserManager {
        &self.user
    }

    /// System metadata API (version, build info).
    #[must_use]
    pub fn system(&self) -> System {
        System
    }
}

impl Default for RbsCore {
    fn default() -> Self {
        Self::new(CoreConfig::default())
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

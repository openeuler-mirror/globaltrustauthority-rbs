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
//! Logging infrastructure (`infra`) and system metadata (`system`, e.g. version). Additional
//! domain modules (attestation, resources, admin, auth) are expected to live here as they are
//! implemented.

mod infra;

pub mod system;

pub use infra::logging::init_logging;
pub use infra::init_database;
pub use infra::rdb;
pub use rbs_api_types::config::{CoreConfig, LogRotationConfig, LoggingConfig, RotationCompression};
pub use system::{BuildMetadata, RbsVersion, API_VERSION, SERVICE_NAME};

/// Core runtime handle.
#[derive(Debug, Default)]
pub struct RbsCore;

impl RbsCore {
    #[must_use]
    pub fn new(_config: CoreConfig) -> Self {
        Self
    }

    /// System metadata API (version, build info).
    #[must_use]
    pub fn system(&self) -> System {
        System
    }
}

/// System-scoped operations (version, health, etc.).
#[derive(Debug, Clone, Copy, Default)]
pub struct System;

impl System {
    /// Returns service version and build metadata.
    #[must_use]
    pub fn version(&self) -> RbsVersion {
        system::get_rbs_version()
    }
}

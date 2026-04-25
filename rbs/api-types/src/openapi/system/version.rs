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

//! JSON types for HTTP responses; [`utoipa::ToSchema`] drives `OpenAPI` `components.schemas` export.
//!
//! `OpenAPI` 3.x labels one optional field on each schema property as `example`: the documented
//! representative value in the machine-readable contract (`openapi.yaml`). That keyword is fixed
//! by the specification and by [`utoipa`]; it denotes **published API documentation**, not informal
//! sample or throwaway code. Helpers below supply the same canonical strings as the running service.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::RbsError;

/// Public service name for APIs, logs, and the exported `OpenAPI` document.
pub const SERVICE_NAME: &str = "globaltrustauthority-rbs";

/// Published REST API contract version string (HTTP `api_version`; independent of Cargo package version).
pub const API_VERSION: &str = "0";

/// Placeholder for `build.git_hash` when no VCS revision is embedded at build time.
///
/// Empty string follows common API practice (e.g. metadata fields where “unset” is represented as
/// `""`); clients should treat a non-empty value as an embedded hex commit hash.
pub const GIT_HASH_PLACEHOLDER: &str = "";

/// Placeholder for `build.build_date` when no timestamp is embedded at build time.
///
/// Empty string follows the same convention as [`GIT_HASH_PLACEHOLDER`]; non-empty values should
/// be RFC 3339 timestamps when provided by the build.
pub const BUILD_DATE_PLACEHOLDER: &str = "";

/// Value written to the exported `OpenAPI` document for `service_name` (same as [`SERVICE_NAME`]).
/// Required by [`utoipa`] as the argument to `#[schema(example = …)]` (`OpenAPI` spec keyword).
fn open_api_schema_service_name() -> &'static str {
    SERVICE_NAME
}

/// Value written to the exported `OpenAPI` document for `api_version` (same as [`API_VERSION`]).
fn open_api_schema_api_version() -> &'static str {
    API_VERSION
}

/// Value written to the exported `OpenAPI` document for `build.version` (compile-time
/// `CARGO_PKG_VERSION` for this crate).
///
/// # Invariant
///
/// All workspace members share one version (`version.workspace = true` in each
/// `Cargo.toml`). If per-crate versioning is ever introduced, this example and the
/// runtime value in `rbs-core` (`env!("CARGO_PKG_VERSION")`) will diverge silently —
/// add a compile-time or CI check before splitting versions.
fn open_api_schema_build_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// OpenAPI `example` for `git_hash` (representative hex string for documentation).
fn open_api_schema_git_hash() -> &'static str {
    "0123456789abcdef0123456789abcdef"
}

/// OpenAPI `example` for `build_date` (representative RFC 3339 timestamp for documentation).
fn open_api_schema_build_date() -> &'static str {
    "2026-04-20T00:00:00Z"
}

/// Error payload for HTTP error responses (e.g. 500).
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ErrorBody {
    /// Error string for the caller: may be a stable code, a short machine-oriented label,
    /// or a concise human-readable message. Must not include stack traces or secrets.
    pub error: String,
}

impl ErrorBody {
    /// Creates a new error body with the given message.
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }
}

impl From<&str> for ErrorBody {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for ErrorBody {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&RbsError> for ErrorBody {
    fn from(e: &RbsError) -> Self {
        ErrorBody::new(e.external_message())
    }
}

/// Build-time identity for the running binary.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct BuildMetadata {
    /// Cargo package / release version (semver).
    #[schema(example = open_api_schema_build_version)]
    pub version: String,
    /// Git commit hash at build time (hex), or empty when not embedded at build.
    #[schema(example = open_api_schema_git_hash)]
    pub git_hash: String,
    /// Build timestamp (UTC), typically RFC 3339, or empty when not embedded at build.
    #[schema(example = open_api_schema_build_date)]
    pub build_date: String,
}

/// JSON emitted by `GET /rbs/version` (`service_name`, `api_version`, structured `build`).
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct RbsVersion {
    /// Logical service display name.
    #[schema(example = open_api_schema_service_name)]
    pub service_name: String,
    /// Published API contract version string.
    #[schema(example = open_api_schema_api_version)]
    pub api_version: String,
    /// Build metadata (`version`, `git_hash`, `build_date`) for this binary; same shape as in the exported `OpenAPI` schema.
    pub build: BuildMetadata,
}

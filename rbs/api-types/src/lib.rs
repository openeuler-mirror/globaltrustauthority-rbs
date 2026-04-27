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

//! RBS API types library.
//!
//! Request/response structs, error types, and constants shared by REST and built-in.
//!
//! All types in this crate are pure data definitions with no business logic.
//! They must stay in sync with the OpenAPI specification at `rbs_api.yaml`.
//!
//! # Modules
//!
//! - [`auth`] - Attestation-related types (challenge, evidence, token)
//! - [`constants`] - API constants (prefix, resource types)
//! - [`error`] - Unified error types with stable error codes
//! - [`resource`] - Resource-related types (content, metadata, upsert)
//! - [`user`] - User management types (create, update, list)
//!
//! # API Contract
//!
//! The types in this crate are derived from the OpenAPI 3.0 specification.
//! The checked-in contract in this repository is [`docs/proto/rbs_rest_api.yaml`](../../../docs/proto/rbs_rest_api.yaml),
//! emitted when building the `rbs` crate with the `rest` feature (`rbs/build.rs`).
//!
//! # Architecture
//!
//! ```text
//! HTTP/JSON  <--serde-->  rbs-api-types  <--->  rbs-core (business logic)
//! ```

pub mod auth;
pub mod config;
pub mod constants;
pub mod error;
pub mod openapi;
pub mod resource;
pub mod user;

// Re-export types from auth module
pub use auth::{
    AttestRequest, AttestResponse, AttesterData, AuthChallengeResponse, RbcEvidenceItem,
    RbcEvidencesPayload, RbcMeasurement,
};

// Re-export types from config module
pub use config::{
    AttestationBackendConfig, AttestationBackendMode, AttestationBuiltinConfig, AttestationConfig,
    AttestationRestConfig, CoreConfig, Database, LogRotationConfig, LoggingConfig,
    PerIpRateLimitConfig, RestConfig, RestHttpsConfig, RbsConfig, RotationCompression, Sensitive,
    TrustedProxyConfig,
};

// Re-export constants from constants module
pub use constants::{
    API_PREFIX, API_VERSION, BUILD_DATE_PLACEHOLDER, GIT_HASH_PLACEHOLDER, RESOURCE_TYPES,
    SERVICE_NAME,
};

// Re-export types from error module
pub use error::RbsError;

// Re-export types from resource module
pub use resource::{
    ResourceContentResponse, ResourceInfoResponse, ResourceMetadataResponse,
    ResourceRetrieveRequest, ResourceUpsertRequest,
};

// Re-export types from openapi module (with ToSchema and example attributes)
pub use openapi::{BuildMetadata, ErrorBody, RbsVersion};

// Re-export types from user module
pub use user::{UserCreateRequest, UserListResponse, UserResponse, UserUpdateRequest};

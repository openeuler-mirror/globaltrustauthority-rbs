/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
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
//! Run configuration (`config`) and related types shared by REST and core.
//!
//! `OpenAPI` `components.schemas` for HTTP JSON bodies live under [`openapi`] as [`utoipa::ToSchema`]
//! types. The checked-in [`docs/proto/rbs_rest_api.yaml`](../../../docs/proto/rbs_rest_api.yaml) is emitted when
//! building the `rbs` crate (`rbs/build.rs`) from the workspace root.
//!
//! **Module layout:** map OpenAPI tag names to `openapi/<snake_case>/` and nest files for related
//! schemas (e.g. System-tagged version metadata → `openapi/system/version.rs`). Crate root
//! re-exports schema types for convenience.

/// HTTP JSON schema types (`OpenAPI` `components.schemas`).
pub mod openapi;

pub use openapi::*;

pub mod config;
pub mod api;

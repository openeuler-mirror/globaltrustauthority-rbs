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

//! RBS API constants.

/// API prefix for all versioned endpoints.
pub const API_PREFIX: &str = "/rbs/v0";

/// Supported resource types.
pub const RESOURCE_TYPES: [&str; 3] = ["key", "secret", "cert"];

/// Service name for RBS (HTTP `service_name`; same as OpenAPI `RbsVersion.service_name` example).
pub const SERVICE_NAME: &str = "globaltrustauthority-rbs";

/// API version string.
pub const API_VERSION: &str = "0";

/// Placeholder for git hash when not available at build time.
pub const GIT_HASH_PLACEHOLDER: &str = "unknown";

/// Placeholder for build date when not available at build time.
pub const BUILD_DATE_PLACEHOLDER: &str = "unknown";

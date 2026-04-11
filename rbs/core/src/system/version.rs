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

//! Version payload for the system API (`GET .../version`) using JSON types from `rbs-api-types`
//! (`openapi` module; `OpenAPI` document is exported from code — see `rbs-rest` `ApiDoc`).

use rbs_api_types::{
    BuildMetadata, RbsVersion, BUILD_DATE_PLACEHOLDER, GIT_HASH_PLACEHOLDER,
};

pub use rbs_api_types::{API_VERSION, SERVICE_NAME};

/// Returns the version payload for `GET .../version` ([`RbsVersion`]).
#[must_use]
pub fn get_rbs_version() -> RbsVersion {
    RbsVersion {
        service_name: SERVICE_NAME.to_string(),
        api_version: API_VERSION.to_string(),
        build: BuildMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_hash: option_env!("GIT_HASH")
                .unwrap_or(GIT_HASH_PLACEHOLDER)
                .to_string(),
            build_date: option_env!("BUILD_DATE")
                .unwrap_or(BUILD_DATE_PLACEHOLDER)
                .to_string(),
        },
    }
}

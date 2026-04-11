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

#![allow(clippy::needless_for_each)] // utoipa `OpenApi` derive

use rbs_api_types::{API_VERSION, BuildMetadata, ErrorBody, RbsVersion};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "RBS REST API",
        version = API_VERSION,
        description = "Resource Broker Service (RBS) HTTP API.",
        license(name = "Mulan Permissive Software License, Version 2", url = "http://license.coscl.org.cn/MulanPSL2"),
        contact(name = "RBS open-source community", url = "https://gitcode.com/openeuler/globaltrustauthority-rbs"),
    ),
    servers(
        (url = "http://localhost:6666", description = "Default local development (see `rbs.yaml` `rest.listen_addr`)"),
    ),
    tags(
        (name = "System", description = "`RbsCore::system` — service identity and API/build version via `GET /rbs/version` (system metadata). Does not require authentication."),
    ),
    paths(
        crate::routes::version::version,
    ),
    components(schemas(RbsVersion, BuildMetadata, ErrorBody))
)]
pub struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_has_version_path_and_schemas() {
        let doc = ApiDoc::openapi();
        let v = serde_json::to_value(&doc).expect("serialize OpenAPI");
        assert!(v.pointer("/paths/~1rbs~1version/get").is_some(), "expected GET /rbs/version in paths");
        assert!(v.pointer("/components/schemas/RbsVersion").is_some(), "expected RbsVersion schema");
        assert_eq!(
            v.pointer("/info/version").and_then(|x| x.as_str()),
            Some(API_VERSION),
            "OpenAPI info.version must match published API_VERSION"
        );
        let sec = v
            .pointer("/paths/~1rbs~1version/get/security")
            .and_then(|x| x.as_array())
            .expect("GET /rbs/version must declare security (empty requirement = no auth)");
        assert_eq!(
            sec.len(),
            1,
            "single empty security requirement marks the operation as requiring no schemes"
        );
        assert!(
            sec[0].as_object().map(|o| o.is_empty()).unwrap_or(false),
            "empty security requirement object must serialize as {{}} in OpenAPI"
        );
    }
}

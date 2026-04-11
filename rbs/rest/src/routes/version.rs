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

//! Version route (`GET /rbs/version`, no auth).

use actix_web::{web, HttpResponse};
use rbs_api_types::RbsVersion;
use rbs_core::RbsCore;
use std::sync::Arc;

/// `GET /rbs/version`: 200 with `RbsVersion` JSON (see `OpenAPI` `RbsVersion` / `BuildMetadata`).
#[utoipa::path(
    get,
    path = "/rbs/version",
    operation_id = "rbsVersion",
    summary = "Get service name, API version, and build metadata",
    tags = ["System"],
    security(()),
    responses(
        (status = 200, description = "Version payload: service name, API contract version, and build metadata (JSON).", body = RbsVersion),
    )
)]
pub async fn version(core: web::Data<Arc<RbsCore>>) -> HttpResponse {
    HttpResponse::Ok().json(core.system().version())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use rbs_api_types::{API_VERSION, SERVICE_NAME};
    use std::sync::Arc;

    #[actix_web::test]
    async fn version_returns_200_and_expected_json() {
        let core = Arc::new(RbsCore::default());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(core))
                .service(web::scope("/rbs").route("/version", web::get().to(version))),
        )
        .await;
        let req = test::TestRequest::get().uri("/rbs/version").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "version endpoint must return 2xx");
        let body = test::read_body(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).expect("response body must be valid JSON");
        assert_eq!(json.get("service_name").and_then(|v| v.as_str()), Some(SERVICE_NAME));
        assert_eq!(json.get("api_version").and_then(|v| v.as_str()), Some(API_VERSION));
        let build = json.get("build").expect("response must contain build object");
        let v = build.get("version").and_then(|x| x.as_str()).unwrap_or_default();
        assert!(!v.is_empty(), "build.version must be non-empty (Cargo release)");
        for key in ["git_hash", "build_date"] {
            assert!(
                build.get(key).and_then(|x| x.as_str()).is_some(),
                "build.{key} must be a string (may be empty when not embedded at build)"
            );
        }
    }
}

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
 * PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Health endpoint contract tests WITHOUT initializing the global DB pool:
//! livez (zero dependencies), readyz 503 with the pool-not-initialized reason,
//! and method/path constraints. This binary never touches `DB_CONN`.

use actix_web::{http::StatusCode, test, App};
use rbs_rest::server::health::configure_health_routes;
use serde_json::{json, Value};

#[actix_web::test]
async fn livez_returns_200_with_exact_body() {
    let app = test::init_service(App::new().configure(configure_health_routes)).await;
    let req = test::TestRequest::get().uri("/livez").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("application/json"),
        "content-type must be application/json, got: {content_type}"
    );
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body, json!({"status": "ok"}));
}

#[actix_web::test]
async fn readyz_pool_not_initialized_returns_503_with_reason() {
    let app = test::init_service(App::new().configure(configure_health_routes)).await;
    let req = test::TestRequest::get().uri("/readyz").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = test::read_body_json(resp).await;
    // Exact JSON equality also proves the response carries no extra content
    // (no connection strings, paths, or other unsanitized details).
    assert_eq!(body, json!({"status": "error", "reason": "sqlite: connection pool not initialized"}));
}

#[actix_web::test]
async fn non_get_methods_return_405_and_unknown_path_returns_404() {
    let app = test::init_service(App::new().configure(configure_health_routes)).await;

    for uri in ["/livez", "/readyz"] {
        let req = test::TestRequest::post().uri(uri).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "POST {uri} must be 405");
    }

    let req = test::TestRequest::get().uri("/healthz").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "unknown path must be 404");
}

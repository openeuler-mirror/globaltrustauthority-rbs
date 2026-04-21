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

//! HTTP server integration tests.

use actix_web::{test, web, App, HttpResponse};
use rbs_api_types::config::RestConfig;
use rbs_core::RbsCore;
use rbs_rest::server::{http::uri_length_guard_middleware, Server};
use serde_json::Value;
use std::sync::Arc;

#[actix_web::test]
async fn uri_length_guard_returns_414_json_error_body() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(20usize))
            .wrap(actix_web::middleware::from_fn(uri_length_guard_middleware))
            .route("/x", web::get().to(|| async { HttpResponse::Ok().body("ok") })),
    )
    .await;
    let long = format!("/{}", "a".repeat(25));
    let req = test::TestRequest::get().uri(&long).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::URI_TOO_LONG);
    let body = test::read_body(resp).await;
    let v: Value = serde_json::from_slice(&body).expect("body must be JSON");
    assert_eq!(v.get("error").and_then(|x| x.as_str()), Some("URI Too Long"));
}

#[actix_web::test]
async fn bind_fails_when_https_enabled_but_cert_file_empty() {
    let mut rest = RestConfig::default();
    rest.https.enabled = true;
    rest.https.cert_file = String::new();
    rest.https.key_file = rbs_api_types::config::Sensitive::new("/dev/null".to_string());
    let server = Server::new(Arc::new(RbsCore::default()), rest);
    let result = server.bind().await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("cert_file") && err_msg.contains("empty"),
        "error should mention empty cert_file, got: {}",
        err_msg
    );
}

#[actix_web::test]
async fn bind_fails_when_https_enabled_but_key_file_empty() {
    let mut rest = RestConfig::default();
    rest.https.enabled = true;
    rest.https.cert_file = "/dev/null".to_string();
    rest.https.key_file = rbs_api_types::config::Sensitive::new(String::new());
    let server = Server::new(Arc::new(RbsCore::default()), rest);
    let result = server.bind().await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("key_file") && err_msg.contains("empty"),
        "error should mention empty key_file, got: {}",
        err_msg
    );
}

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
use rbs_api_types::config::{AuthConfig, HealthConfig, RestConfig};
use rbs_core::auth::LockoutTracker;
use rbs_core::RbsCore;
use rbs_rest::server::{http::uri_length_guard_middleware, Server};
use serde_json::Value;
use std::net::TcpListener;
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

fn stub_auth_provider() -> Arc<dyn rbs_core::auth::UserAuthProvider> {
    use async_trait::async_trait;
    use rbs_core::auth::{AuthError, UserAuthInfo, UserAuthProvider};

    #[derive(Debug, Clone, Default)]
    struct Stub;

    #[async_trait]
    impl UserAuthProvider for Stub {
        async fn get_user_auth(&self, _sub: &str) -> Result<UserAuthInfo, AuthError> {
            Err(AuthError::TokenInvalid { reason: "stub".to_string() })
        }
    }

    Arc::new(Stub)
}

#[actix_web::test]
async fn bind_fails_when_https_enabled_but_cert_file_empty() {
    let mut rest = RestConfig::default();
    rest.https.enabled = true;
    rest.https.cert_file = String::new();
    rest.https.key_file = rbs_api_types::config::Sensitive::new("/dev/null".to_string());
    let lockout_tracker = LockoutTracker::new_shared();
    let server = Server::new(
        Arc::new(RbsCore::default()),
        rest,
        None,
        AuthConfig::default(),
        stub_auth_provider(),
        lockout_tracker,
    );
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
    let lockout_tracker = LockoutTracker::new_shared();
    let server = Server::new(
        Arc::new(RbsCore::default()),
        rest,
        None,
        AuthConfig::default(),
        stub_auth_provider(),
        lockout_tracker,
    );
    let result = server.bind().await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("key_file") && err_msg.contains("empty"),
        "error should mention empty key_file, got: {}",
        err_msg
    );
}

/// Bind a loopback socket on an OS-assigned port, return the port, and close the socket.
fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral listener");
    listener.local_addr().expect("local addr").port()
}

fn server_with(rest_port: u16, health: Option<HealthConfig>) -> Server {
    let mut rest = RestConfig::default();
    rest.listen_addr = format!("127.0.0.1:{rest_port}");
    Server::new(
        Arc::new(RbsCore::default()),
        rest,
        health,
        AuthConfig::default(),
        stub_auth_provider(),
        LockoutTracker::new_shared(),
    )
}

// TC15: health listener on an occupied port -> bind fails fast, error identifies the listener.
#[actix_web::test]
async fn bind_fails_when_health_port_occupied() {
    let rest_port = free_port();
    // Occupy a port and keep it bound for the duration of the test.
    let holder = TcpListener::bind(("127.0.0.1", 0)).expect("bind holder");
    let health_addr = holder.local_addr().expect("local addr").to_string();

    let result = server_with(rest_port, Some(HealthConfig { listen_addr: health_addr })).bind().await;
    let msg = format!("{:#}", result.unwrap_err());
    assert!(msg.contains("bind health listener"), "error should mention the health listener, got: {msg}");
}

// TC16: health address that passes string-level validation but is not a valid SocketAddr
// -> bind fails with the invalid-address error (runtime guard behind the config validation).
#[actix_web::test]
async fn bind_fails_when_health_addr_not_parseable() {
    let result = server_with(free_port(), Some(HealthConfig { listen_addr: "invalid:addr".to_string() }))
        .bind()
        .await;
    let msg = format!("{:#}", result.unwrap_err());
    assert!(msg.contains("invalid listen address"), "error should mention invalid listen address, got: {msg}");
}

// TC17: dual-listener happy path — both listeners on free ports binds successfully.
#[actix_web::test]
async fn bind_succeeds_with_health_listener_on_free_ports() {
    let result = server_with(
        free_port(),
        Some(HealthConfig { listen_addr: format!("127.0.0.1:{}", free_port()) }),
    )
    .bind()
    .await;
    assert!(result.is_ok(), "dual bind on free ports must succeed");
    // BoundServer dropped without run(); both listeners close.
}

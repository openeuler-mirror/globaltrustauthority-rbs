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

//! Success-path tests for the public attestation routes (`GET /rbs/v0/challenge`
//! and `POST /rbs/v0/attest`).
//!
//! `RbsCore::default()` registers no provider, so the route-level suites can
//! only reach the error mapping. Here the core is built with a REST attestation
//! backend pointing at a local stub that speaks the GTA wire format, which lets
//! the 200 responses (nonce / token) be asserted end to end.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Once};

use actix_web::{http::StatusCode, test, web, App};
use rbs_api_types::config::{
    AttestationBackendConfig, AttestationBackendMode, AttestationConfig, AttestationCredentials, AttestationRestConfig,
    CoreConfig, Database,
};
use rbs_core::{RbsCore, RbsCoreBuilder};
use rbs_rest::routes::config as routes_config;
use serde_json::{json, Value};

const STUB_NONCE: &str = "stub-nonce-0001";
const STUB_TOKEN: &str = "stub-token-0001";

static DB_INIT: Once = Once::new();

/// `RbsCoreBuilder::build` requires the global pool; a temp-file SQLite pool is
/// enough for these route tests (only the attestation backend is exercised).
fn ensure_db() {
    DB_INIT.call_once(|| {
        std::thread::spawn(|| {
            tokio::runtime::Runtime::new().expect("tokio runtime").block_on(async {
                let path = std::env::temp_dir().join("rbs_rest_attestation_route_success.sqlite");
                for suffix in ["", "-wal", "-shm"] {
                    let _ = std::fs::remove_file(format!("{}{}", path.to_string_lossy(), suffix));
                }
                let config = Database {
                    db_type: "sqlite".to_string(),
                    url: format!("sqlite:{}?mode=rwc", path.to_string_lossy()),
                    max_connections: 2,
                    timeout: 30,
                    sql_file_path: String::new(),
                };
                rbs_core::rdb::init_database(&config).await.expect("init database");
            });
        })
        .join()
        .expect("db init thread");
    });
}

/// Minimal blocking HTTP stub answering the two GTA endpoints this test needs.
/// Returns the base URL the attestation backend should point at.
fn spawn_stub_gta() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind stub listener");
    let addr = listener.local_addr().expect("stub addr");

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            if let Some(response) = read_request_and_respond(&mut stream) {
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        }
    });

    format!("http://{addr}")
}

fn read_request_and_respond(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    // Read headers.
    loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let request_line = headers.lines().next().unwrap_or_default().to_string();

    // Drain the body so the client never sees a reset while still sending.
    let content_length: usize = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut remaining = content_length.saturating_sub(buf.len().saturating_sub(header_end));
    while remaining > 0 {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        remaining = remaining.saturating_sub(n);
    }

    let (status, body) = if request_line.starts_with("GET /global-trust-authority/service/v1/challenge") {
        (200, json!({"service_version": "1.0.0", "nonce": STUB_NONCE}))
    } else if request_line.starts_with("POST /global-trust-authority/service/v1/attest") {
        (
            200,
            json!({
                "service_version": "1.0.0",
                "tokens": [{"node_id": "node-1", "token": STUB_TOKEN}],
            }),
        )
    } else {
        (404, json!({"message": "unexpected stub path"}))
    };

    let body = body.to_string();
    Some(format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ))
}

fn core_with_stub_backend(base_url: String) -> Arc<RbsCore> {
    ensure_db();
    let mut backends = HashMap::new();
    backends.insert(
        "gta".to_string(),
        AttestationBackendConfig {
            mode: AttestationBackendMode::Rest,
            rest: AttestationRestConfig {
                base_url,
                timeout_secs: 5,
                retries: 0,
                tls_verify: false,
                ca_file: String::new(),
                client_cert_path: String::new(),
                client_key_path: String::new(),
                credentials: AttestationCredentials {
                    user_id: "user-1".to_string(),
                    ..AttestationCredentials::default()
                },
            },
            builtin: Default::default(),
        },
    );
    let config = CoreConfig {
        attestation: AttestationConfig { default_as_provider: "gta".to_string(), backends },
        ..CoreConfig::default()
    };
    Arc::new(RbsCoreBuilder::new(config).build())
}

async fn build_app(
    core: Arc<RbsCore>,
) -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
    Error = actix_web::Error,
> {
    test::init_service(
        App::new()
            .app_data(web::Data::new(core))
            .service(web::scope("/rbs").service(web::scope("/v0").configure(routes_config))),
    )
    .await
}

#[actix_web::test]
async fn challenge_returns_nonce_from_attestation_backend() {
    let app = build_app(core_with_stub_backend(spawn_stub_gta())).await;
    let resp = test::call_service(&app, test::TestRequest::get().uri("/rbs/v0/challenge").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body, json!({"nonce": STUB_NONCE}));
}

#[actix_web::test]
async fn challenge_accepts_as_provider_selector() {
    let app = build_app(core_with_stub_backend(spawn_stub_gta())).await;
    let resp =
        test::call_service(&app, test::TestRequest::get().uri("/rbs/v0/challenge?as_provider=gta").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["nonce"], STUB_NONCE);
}

#[actix_web::test]
async fn attest_returns_token_from_attestation_backend() {
    let app = build_app(core_with_stub_backend(spawn_stub_gta())).await;
    let payload = json!({
        "rbc_evidences": {
            "agent_version": "1.0.0",
            "measurements": [{
                "nonce": STUB_NONCE,
                "nonce_type": "verifier",
                "token_fmt": "eat",
                "node_id": "node-1",
                "evidences": [{
                    "attester_type": "tpm_boot",
                    "evidence": {"quote": "abc123"}
                }]
            }]
        }
    });
    let resp =
        test::call_service(&app, test::TestRequest::post().uri("/rbs/v0/attest").set_json(payload).to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body, json!({"token": STUB_TOKEN}));
}

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! HTTP tests for the attestation management routes
//! (`/rbs/v0/attestation/...`) and the public challenge/attest routes.
//!
//! `RbsCore::default()` registers no attestation providers, so provider-backed
//! handlers stop at provider resolution (404). That is exactly the boundary
//! these tests pin down: auth/admin gating, request validation, route wiring,
//! and the default-provider variants.

use std::sync::{Arc, Once};

use actix_web::http::StatusCode;
use actix_web::middleware::from_fn;
use actix_web::{test, web, App};
use async_trait::async_trait;
use rbs_api_types::config::Database;
use rbs_core::auth::{Auth, AuthContext, AuthError, BearerContext, TokenType};
use rbs_core::RbsCore;
use rbs_rest::middleware::auth_middleware;
use rbs_rest::routes::config as routes_config;
use serde_json::{json, Value};

static INIT: Once = Once::new();

fn ensure_db() {
    INIT.call_once(|| {
        std::thread::spawn(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let path = std::env::temp_dir().join("rbs_rest_attestation_mgmt_routes.sqlite");
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
                let db = rbs_core::rdb::init_pool(&config).await.expect("init pool");
                rbs_core::rdb::migrate_core_tables(&db).await.expect("migrate core tables");
            });
        })
        .join()
        .expect("db init thread");
    });
}

async fn seed_user(username: &str, role: &str) {
    use sea_orm::ConnectionTrait;
    let db = rbs_core::rdb::get_connection_from_pool().expect("db pool");
    let backend = db.get_database_backend();
    let sql = format!(
        "INSERT OR IGNORE INTO t_user_info (user_id, username, role, auth_type, auth_value, auth_alg, status, created_at, updated_at) \
         VALUES ('id-{username}', '{username}', '{role}', 'jwt', 'stub', 'RSA', 1, 0, 0)"
    );
    db.execute(sea_orm::Statement::from_string(backend, sql)).await.expect("seed user");
}

#[derive(Clone)]
struct StubAuth {
    sub: String,
    role: String,
}

#[async_trait]
impl Auth for StubAuth {
    async fn authenticate(&self, _token: &str, token_type: TokenType) -> Result<AuthContext, AuthError> {
        match token_type {
            TokenType::Bearer => Ok(AuthContext::Bearer(BearerContext {
                iss: "test-issuer".to_string(),
                sub: self.sub.clone(),
                role: self.role.clone(),
                claims: Value::Null,
                token_type: TokenType::Bearer,
            })),
            TokenType::Attest => {
                Ok(AuthContext::Attest(rbs_core::AttestContext { claims: Value::Null, token_type: TokenType::Attest }))
            },
        }
    }
}

async fn build_app(
    sub: &str,
    role: &str,
) -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
    Error = actix_web::Error,
> {
    ensure_db();
    seed_user("Administrator", "admin").await;
    seed_user(sub, role).await;
    let core = Arc::new(RbsCore::default());
    let auth: Arc<dyn Auth> = Arc::new(StubAuth { sub: sub.to_string(), role: role.to_string() });
    test::init_service(
        App::new()
            .app_data(web::Data::new(core))
            .app_data(web::Data::new(auth))
            .wrap(from_fn(auth_middleware))
            .service(web::scope("/rbs").service(web::scope("/v0").configure(routes_config))),
    )
    .await
}

fn admin_request(method: &str, uri: &str) -> actix_web::test::TestRequest {
    let req = match method {
        "get" => test::TestRequest::get(),
        "post" => test::TestRequest::post(),
        "put" => test::TestRequest::put(),
        "delete" => test::TestRequest::delete(),
        other => panic!("unsupported method {other}"),
    };
    req.uri(uri).insert_header(("Authorization", "Bearer admin-token"))
}

async fn status(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    req: actix_http::Request,
) -> StatusCode {
    test::call_service(app, req).await.status()
}

#[actix_web::test]
async fn challenge_and_attest_report_missing_provider() {
    let app = build_app("Administrator", "admin").await;

    let resp = test::call_service(&app, test::TestRequest::get().uri("/rbs/v0/challenge").to_request()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = test::call_service(
        &app,
        test::TestRequest::post().uri("/rbs/v0/attest").set_json(json!({"measurements": []})).to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn management_routes_require_bearer_admin() {
    let anonymous = build_app("Administrator", "admin").await;
    let resp =
        test::call_service(&anonymous, test::TestRequest::get().uri("/rbs/v0/attestation/gta/ref_value").to_request())
            .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let attest = test::TestRequest::get()
        .uri("/rbs/v0/attestation/gta/ref_value")
        .insert_header(("Authorization", "Attest attest-token"))
        .to_request();
    assert_eq!(status(&anonymous, attest).await, StatusCode::UNAUTHORIZED);

    let user = build_app("routes_mgmt_user", "user").await;
    let req = test::TestRequest::get()
        .uri("/rbs/v0/attestation/gta/ref_value")
        .insert_header(("Authorization", "Bearer user-token"))
        .to_request();
    assert_eq!(status(&user, req).await, StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn ref_value_routes_report_missing_provider() {
    let app = build_app("Administrator", "admin").await;
    let requests = vec![
        admin_request("get", "/rbs/v0/attestation/gta/ref_value").to_request(),
        admin_request("get", "/rbs/v0/attestation/gta/ref_value/rv-1").to_request(),
        admin_request("get", "/rbs/v0/attestation/ref_value").to_request(),
        admin_request("get", "/rbs/v0/attestation/ref_value/rv-1").to_request(),
        admin_request("post", "/rbs/v0/attestation/gta/ref_value")
            .set_json(json!({"name": "n", "attester_type": "tpm", "content": "c"}))
            .to_request(),
        admin_request("post", "/rbs/v0/attestation/ref_value")
            .set_json(json!({"name": "n", "attester_type": "tpm", "content": "c"}))
            .to_request(),
        admin_request("put", "/rbs/v0/attestation/gta/ref_value")
            .set_json(json!({"id": "rv-1", "name": "n"}))
            .to_request(),
        admin_request("put", "/rbs/v0/attestation/ref_value").set_json(json!({"id": "rv-1", "name": "n"})).to_request(),
        admin_request("delete", "/rbs/v0/attestation/gta/ref_value")
            .set_json(json!({"delete_type": "all"}))
            .to_request(),
        admin_request("delete", "/rbs/v0/attestation/ref_value").set_json(json!({"delete_type": "all"})).to_request(),
        admin_request("delete", "/rbs/v0/attestation/gta/ref_value/rv-1").to_request(),
        admin_request("delete", "/rbs/v0/attestation/ref_value/rv-1").to_request(),
    ];
    for req in requests {
        let method = req.method().clone();
        let path = req.path().to_string();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "unexpected status for {method} {path}");
    }
}

#[actix_web::test]
async fn cert_routes_report_missing_provider() {
    let app = build_app("Administrator", "admin").await;
    let requests = vec![
        admin_request("get", "/rbs/v0/attestation/gta/cert").to_request(),
        admin_request("get", "/rbs/v0/attestation/gta/cert/c-1").to_request(),
        admin_request("get", "/rbs/v0/attestation/cert").to_request(),
        admin_request("get", "/rbs/v0/attestation/cert/c-1").to_request(),
        admin_request("post", "/rbs/v0/attestation/gta/cert")
            .set_json(json!({"name": "c", "type": ["tpm"], "content": "x"}))
            .to_request(),
        admin_request("post", "/rbs/v0/attestation/cert")
            .set_json(json!({"name": "c", "type": ["tpm"], "content": "x"}))
            .to_request(),
        admin_request("put", "/rbs/v0/attestation/gta/cert").set_json(json!({"id": "c-1", "name": "c"})).to_request(),
        admin_request("put", "/rbs/v0/attestation/cert").set_json(json!({"id": "c-1", "name": "c"})).to_request(),
        admin_request("delete", "/rbs/v0/attestation/gta/cert").set_json(json!({"delete_type": "all"})).to_request(),
        admin_request("delete", "/rbs/v0/attestation/cert").set_json(json!({"delete_type": "all"})).to_request(),
        admin_request("delete", "/rbs/v0/attestation/gta/cert/c-1").to_request(),
        admin_request("delete", "/rbs/v0/attestation/cert/c-1").to_request(),
    ];
    for req in requests {
        let method = req.method().clone();
        let path = req.path().to_string();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "unexpected status for {method} {path}");
    }
}

#[actix_web::test]
async fn policy_routes_report_missing_provider() {
    let app = build_app("Administrator", "admin").await;
    let requests = vec![
        admin_request("get", "/rbs/v0/attestation/gta/policy").to_request(),
        admin_request("get", "/rbs/v0/attestation/gta/policy/p-1").to_request(),
        admin_request("get", "/rbs/v0/attestation/policy").to_request(),
        admin_request("get", "/rbs/v0/attestation/policy/p-1").to_request(),
        admin_request("post", "/rbs/v0/attestation/gta/policy")
            .set_json(json!({"name": "p", "attester_type": ["tpm"], "content_type": "jwt", "content": "x"}))
            .to_request(),
        admin_request("post", "/rbs/v0/attestation/policy")
            .set_json(json!({"name": "p", "attester_type": ["tpm"], "content_type": "jwt", "content": "x"}))
            .to_request(),
        admin_request("put", "/rbs/v0/attestation/gta/policy").set_json(json!({"id": "p-1", "name": "p"})).to_request(),
        admin_request("put", "/rbs/v0/attestation/policy").set_json(json!({"id": "p-1", "name": "p"})).to_request(),
        admin_request("delete", "/rbs/v0/attestation/gta/policy").set_json(json!({"delete_type": "all"})).to_request(),
        admin_request("delete", "/rbs/v0/attestation/policy").set_json(json!({"delete_type": "all"})).to_request(),
        admin_request("delete", "/rbs/v0/attestation/gta/policy/p-1").to_request(),
        admin_request("delete", "/rbs/v0/attestation/policy/p-1").to_request(),
    ];
    for req in requests {
        let method = req.method().clone();
        let path = req.path().to_string();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "unexpected status for {method} {path}");
    }
}

#[actix_web::test]
async fn create_routes_validate_request_bodies() {
    let app = build_app("Administrator", "admin").await;

    let resp = test::call_service(
        &app,
        admin_request("post", "/rbs/v0/attestation/gta/ref_value")
            .set_json(json!({"name": "", "attester_type": "tpm", "content": "c"}))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = test::call_service(
        &app,
        admin_request("post", "/rbs/v0/attestation/gta/cert")
            .set_json(json!({"name": "", "type": ["tpm"], "content": "x"}))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = test::call_service(
        &app,
        admin_request("post", "/rbs/v0/attestation/gta/policy")
            .set_json(json!({"name": "", "attester_type": ["tpm"], "content_type": "jwt", "content": "x"}))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn management_routes_reject_unsupported_methods() {
    let app = build_app("Administrator", "admin").await;
    let req = test::TestRequest::patch()
        .uri("/rbs/v0/attestation/gta/ref_value")
        .insert_header(("Authorization", "Bearer admin-token"))
        .to_request();
    assert_eq!(status(&app, req).await, StatusCode::NOT_FOUND);
}

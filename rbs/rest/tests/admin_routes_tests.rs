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

//! HTTP tests for the admin/user management routes (`/rbs/v0/users`).
//!
//! These tests exercise the handlers against a real `AdminManager` backed by a
//! file-based SQLite pool. The pool is the process-global one from `rbs_core`,
//! so the database is initialized exactly once and every test uses a unique
//! username to stay independent of the others.

use std::sync::{Arc, Once};

use actix_web::http::StatusCode;
use actix_web::middleware::from_fn;
use actix_web::{test, web, App};
use async_trait::async_trait;
use base64::Engine;
use rbs_api_types::config::Database;
use rbs_core::auth::{Auth, AuthContext, AuthError, BearerContext, TokenType};
use rbs_core::RbsCore;
use rbs_rest::middleware::auth_middleware;
use rbs_rest::routes::config as routes_config;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Database setup and seeding
// ---------------------------------------------------------------------------

static INIT: Once = Once::new();

fn ensure_db() {
    INIT.call_once(|| {
        std::thread::spawn(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let path = std::env::temp_dir().join("rbs_rest_admin_routes.sqlite");
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
    let escaped = username.replace('\'', "''");
    let sql = format!(
        "INSERT OR IGNORE INTO t_user_info (user_id, username, role, auth_type, auth_value, auth_alg, status, created_at, updated_at) \
         VALUES ('id-{escaped}', '{escaped}', '{role}', 'jwt', 'stub', 'RSA', 1, 0, 0)"
    );
    db.execute(sea_orm::Statement::from_string(backend, sql)).await.expect("seed user");
}

async fn seed_policy_owner(username: &str) {
    use sea_orm::ConnectionTrait;
    let db = rbs_core::rdb::get_connection_from_pool().expect("db pool");
    let backend = db.get_database_backend();
    let sql = format!(
        "INSERT INTO t_res_policy (policy_id, username, policy_name, policy_version, policy_content, content_type, created_at, updated_at) \
         VALUES ('routes-policy-{username}', '{username}', 'p', 1, 'c', 'base64', 0, 0)"
    );
    db.execute(sea_orm::Statement::from_string(backend, sql)).await.expect("seed policy");
}

// ---------------------------------------------------------------------------
// Mock authenticators
// ---------------------------------------------------------------------------

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

fn admin_auth() -> Arc<dyn Auth> {
    Arc::new(StubAuth { sub: "Administrator".to_string(), role: "admin".to_string() })
}

fn user_auth(sub: &str) -> Arc<dyn Auth> {
    Arc::new(StubAuth { sub: sub.to_string(), role: "user".to_string() })
}

// ---------------------------------------------------------------------------
// App builder
// ---------------------------------------------------------------------------

async fn build_app(
    auth: Arc<dyn Auth>,
) -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
    Error = actix_web::Error,
> {
    ensure_db();
    seed_user("Administrator", "admin").await;
    let core = Arc::new(RbsCore::default());
    test::init_service(
        App::new()
            .app_data(web::Data::new(core))
            .app_data(web::Data::new(auth))
            .wrap(from_fn(auth_middleware))
            .service(web::scope("/rbs").service(web::scope("/v0").configure(routes_config))),
    )
    .await
}

fn bearer(token: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {token}"))
}

fn rsa_public_key_b64() -> String {
    let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa key");
    let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("pkey");
    base64::engine::general_purpose::STANDARD.encode(pkey.public_key_to_pem().expect("public pem"))
}

fn create_body(username: &str) -> Value {
    json!({
        "username": username,
        "auth_type": "jwt",
        "public_key": rsa_public_key_b64(),
    })
}

async fn body_json(resp: actix_web::dev::ServiceResponse<actix_web::body::BoxBody>) -> Value {
    let body = test::read_body(resp).await;
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}

// ===========================================================================
// List
// ===========================================================================

#[actix_web::test]
async fn list_users_returns_seeded_user_and_applies_defaults() {
    let app = build_app(admin_auth()).await;
    seed_user("routes_list_seed", "user").await;

    let req = test::TestRequest::get().uri("/rbs/v0/users").insert_header(bearer("admin-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["users"].as_array().expect("users array").iter().any(|u| u["username"] == "routes_list_seed"));
    assert_eq!(json["limit"], 10);
    assert_eq!(json["offset"], 0);

    // Filters are forwarded to the manager.
    let req = test::TestRequest::get()
        .uri("/rbs/v0/users?role=admin&limit=100")
        .insert_header(bearer("admin-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["users"].as_array().expect("users array").iter().all(|u| u["role"] == "admin"));
    assert_eq!(json["limit"], 100);
}

#[actix_web::test]
async fn list_users_rejects_out_of_range_limit() {
    let app = build_app(admin_auth()).await;
    let req = test::TestRequest::get().uri("/rbs/v0/users?limit=101").insert_header(bearer("admin-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert!(json["error"].as_str().expect("error message").contains("limit"));
}

#[actix_web::test]
async fn list_users_requires_admin_role() {
    let app = build_app(user_auth("routes_plain_user")).await;
    seed_user("routes_plain_user", "user").await;
    let req = test::TestRequest::get().uri("/rbs/v0/users").insert_header(bearer("user-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn list_users_without_token_returns_401() {
    let app = build_app(admin_auth()).await;
    let req = test::TestRequest::get().uri("/rbs/v0/users").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// Create
// ===========================================================================

#[actix_web::test]
async fn create_user_persists_and_rejects_duplicate() {
    let app = build_app(admin_auth()).await;
    let body = create_body("routes_create_user");

    let req = test::TestRequest::post()
        .uri("/rbs/v0/users")
        .insert_header(bearer("admin-token"))
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert_eq!(json["username"], "routes_create_user");
    assert_eq!(json["role"], "user");
    assert_eq!(json["enabled"], true);

    let req = test::TestRequest::post()
        .uri("/rbs/v0/users")
        .insert_header(bearer("admin-token"))
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[actix_web::test]
async fn create_user_rejects_admin_role_and_missing_key() {
    let app = build_app(admin_auth()).await;

    let req = test::TestRequest::post()
        .uri("/rbs/v0/users")
        .insert_header(bearer("admin-token"))
        .set_json(json!({"username": "routes_bad_role", "role": "admin", "auth_type": "jwt", "public_key": rsa_public_key_b64()}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = test::TestRequest::post()
        .uri("/rbs/v0/users")
        .insert_header(bearer("admin-token"))
        .set_json(json!({"username": "routes_no_key", "auth_type": "jwt"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===========================================================================
// Get
// ===========================================================================

#[actix_web::test]
async fn get_user_returns_record_or_not_found() {
    let app = build_app(admin_auth()).await;
    seed_user("routes_get_user", "user").await;

    let req =
        test::TestRequest::get().uri("/rbs/v0/users/routes_get_user").insert_header(bearer("admin-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["username"], "routes_get_user");

    let req = test::TestRequest::get()
        .uri("/rbs/v0/users/routes_missing_user")
        .insert_header(bearer("admin-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Invalid usernames are rejected before hitting the store.
    let req =
        test::TestRequest::get().uri("/rbs/v0/users/bad%20name").insert_header(bearer("admin-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn get_user_non_admin_may_only_read_self() {
    let app = build_app(user_auth("routes_self_reader")).await;
    seed_user("routes_self_reader", "user").await;

    let req = test::TestRequest::get()
        .uri("/rbs/v0/users/routes_self_reader")
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let req =
        test::TestRequest::get().uri("/rbs/v0/users/Administrator").insert_header(bearer("user-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ===========================================================================
// Update
// ===========================================================================

#[actix_web::test]
async fn update_user_rotates_key_and_validates_body() {
    let app = build_app(admin_auth()).await;
    seed_user("routes_update_user", "user").await;

    let req = test::TestRequest::put()
        .uri("/rbs/v0/users/routes_update_user")
        .insert_header(bearer("admin-token"))
        .set_json(json!({"public_key": rsa_public_key_b64()}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["username"], "routes_update_user");

    let req = test::TestRequest::put()
        .uri("/rbs/v0/users/routes_update_user")
        .insert_header(bearer("admin-token"))
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = test::TestRequest::put()
        .uri("/rbs/v0/users/routes_missing_user")
        .insert_header(bearer("admin-token"))
        .set_json(json!({"enabled": false}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn update_user_non_admin_self_cannot_change_role() {
    let app = build_app(user_auth("routes_self_updater")).await;
    seed_user("routes_self_updater", "user").await;

    let req = test::TestRequest::put()
        .uri("/rbs/v0/users/routes_self_updater")
        .insert_header(bearer("user-token"))
        .set_json(json!({"role": "admin"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert!(json["error"].as_str().expect("error message").contains("role"));
}

// ===========================================================================
// Delete
// ===========================================================================

#[actix_web::test]
async fn delete_user_removes_record_and_guards_dependents() {
    let app = build_app(admin_auth()).await;
    seed_user("routes_delete_user", "user").await;

    let req = test::TestRequest::delete()
        .uri("/rbs/v0/users/routes_delete_user")
        .insert_header(bearer("admin-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let req = test::TestRequest::get()
        .uri("/rbs/v0/users/routes_delete_user")
        .insert_header(bearer("admin-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    seed_user("routes_delete_owner", "user").await;
    seed_policy_owner("routes_delete_owner").await;
    let req = test::TestRequest::delete()
        .uri("/rbs/v0/users/routes_delete_owner")
        .insert_header(bearer("admin-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert!(json["error"].as_str().expect("error message").contains("still owns"));
}

#[actix_web::test]
async fn delete_user_rejects_self_and_missing_target() {
    let app = build_app(admin_auth()).await;

    let req = test::TestRequest::delete()
        .uri("/rbs/v0/users/Administrator")
        .insert_header(bearer("admin-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let req = test::TestRequest::delete()
        .uri("/rbs/v0/users/routes_missing_delete")
        .insert_header(bearer("admin-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn attest_token_is_rejected_on_user_routes() {
    let app = build_app(admin_auth()).await;
    let req = test::TestRequest::get()
        .uri("/rbs/v0/users")
        .insert_header(("Authorization", "Attest attest-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

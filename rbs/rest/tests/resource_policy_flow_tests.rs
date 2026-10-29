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

//! End-to-end HTTP tests for the policy and resource routes, the framework
//! error helpers (`RequestDeserializeError`, the JSON/query payload error
//! handlers) and the authentication middleware branches.
//!
//! The route handlers delegate to `rbs-core` services that are bound to the
//! core database, so these tests build a real `RbsCore` over the
//! process-global SQLite pool (`RbsCoreBuilder` on top of
//! `rdb::init_pool` + `migrate_core_tables`) and seed their own rows. The
//! resource backend (Vault) and the attestation backend (GTA) are pointed at an
//! in-process mock HTTP server, so the success paths run without an external
//! service. Every test uses unique user / policy / resource names so the tests
//! stay independent of each other.

use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::{Arc, Once};
use std::time::Duration;

use actix_web::http::StatusCode;
use actix_web::middleware::from_fn;
use actix_web::{test, web, App, HttpResponse};
use async_trait::async_trait;
use base64::Engine;
use rbs_api_types::config::{
    AttestationBackendConfig, AttestationBackendMode, AttestationBuiltinConfig, AttestationRestConfig, CoreConfig,
    Database, ResourceProviderConfig, ResourceProvidersConfig, Sensitive, VaultConfig,
};
use rbs_api_types::CreatePolicyRequest;
use rbs_core::auth::{Auth, AuthContext, AuthError, BearerContext, TokenType};
use rbs_core::{AttestContext, RbsCore, RbsCoreBuilder};
use rbs_rest::middleware::auth_middleware;
use rbs_rest::routes::config as routes_config;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

static INIT: Once = Once::new();

/// Initialize the process-global SQLite pool exactly once per test binary.
///
/// `RbsCoreBuilder::build` resolves the core database from this pool, so the
/// handlers under test talk to the same rows the tests seed.
fn ensure_db() {
    INIT.call_once(|| {
        std::thread::spawn(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let path = std::env::temp_dir().join("rbs_rest_resource_policy_flow.sqlite");
                for suffix in ["", "-wal", "-shm"] {
                    let _ = std::fs::remove_file(format!("{}{}", path.to_string_lossy(), suffix));
                }
                let config = Database {
                    db_type: "sqlite".to_string(),
                    url: format!("sqlite:{}?mode=rwc", path.to_string_lossy()),
                    max_connections: 4,
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

/// Insert a user row so the resource repository's per-user row lock matches.
async fn seed_user(username: &str) {
    use sea_orm::ConnectionTrait;
    let db = rbs_core::rdb::get_connection_from_pool().expect("db pool");
    let backend = db.get_database_backend();
    let escaped = username.replace('\'', "''");
    let sql = format!(
        "INSERT OR IGNORE INTO t_user_info (user_id, username, role, auth_type, auth_value, auth_alg, status, created_at, updated_at) \
         VALUES ('id-{escaped}', '{escaped}', 'user', 'jwt', 'stub', 'RSA', 1, 0, 0)"
    );
    db.execute(sea_orm::Statement::from_string(backend, sql)).await.expect("seed user");
}

// ---------------------------------------------------------------------------
// Mock upstream (Vault KV + GTA attest)
// ---------------------------------------------------------------------------

/// Start a loopback mock upstream and return its base URL.
///
/// Vault paths answer as a KV v2 engine (`metadata` check + `data` read); the
/// GTA attest endpoint answers with a single-token response so
/// `POST /rbs/v0/{uri}/retrieve` can complete its first step.
async fn start_mock_upstream() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mock upstream");
    let addr = listener.local_addr().expect("mock upstream addr");

    let server = actix_web::HttpServer::new(|| {
        App::new()
            .route(
                "/v1/{mount}/metadata/{repo}/{res_type}/{res_name}",
                web::get().to(|| async { HttpResponse::Ok().json(json!({"data": {}})) }),
            )
            .route(
                "/v1/{mount}/data/{repo}/{res_type}/{res_name}",
                web::get()
                    .to(|| async { HttpResponse::Ok().json(json!({"data": {"data": {"secret": "mock-secret"}}})) }),
            )
            .route(
                "/global-trust-authority/service/v1/attest",
                web::post().to(|| async {
                    HttpResponse::Ok().json(json!({
                        "service_version": "1.0.0",
                        "tokens": [{"node_id": "mock-node", "token": "mock-attest-token"}],
                    }))
                }),
            )
    })
    .workers(1)
    .listen(listener)
    .expect("mock upstream listener")
    .run();
    actix_web::rt::spawn(server);

    // Readiness: the listener is already bound, this only waits until the
    // accept loop is running so the first backend call cannot race it.
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// Core / app construction
// ---------------------------------------------------------------------------

/// Build a real `RbsCore` whose Vault backend and GTA attestation backend both
/// point at the mock upstream.
fn build_core(upstream: &str) -> Arc<RbsCore> {
    let mut config = CoreConfig::default();
    config.attestation.default_as_provider = "gta".to_string();
    config.attestation.backends.insert(
        "gta".to_string(),
        AttestationBackendConfig {
            mode: AttestationBackendMode::Rest,
            rest: AttestationRestConfig {
                base_url: upstream.to_string(),
                timeout_secs: 5,
                retries: 0,
                tls_verify: false,
                ..Default::default()
            },
            builtin: AttestationBuiltinConfig::default(),
        },
    );

    let mut backends = HashMap::new();
    backends.insert(
        "vault".to_string(),
        ResourceProviderConfig::Vault(VaultConfig {
            url: upstream.to_string(),
            token: Sensitive::new("mock-vault-token".to_string()),
            mount_path: "secret".to_string(),
            kv_version: "v2".to_string(),
            verify_ssl: false,
            timeout: 5,
            max_connections: 4,
            max_retries: 0,
            max_response_body_bytes: 1024 * 1024,
            allowed_resource_types: vec!["secret".to_string(), "cert".to_string()],
        }),
    );
    config.resource = Some(ResourceProvidersConfig { max_per_user: 20, backends });

    Arc::new(RbsCoreBuilder::new(config).build())
}

async fn build_app(
    core: Arc<RbsCore>,
    auth: Arc<dyn Auth>,
) -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
    Error = actix_web::Error,
> {
    test::init_service(
        App::new()
            .app_data(web::Data::new(core))
            .app_data(web::Data::new(auth))
            .wrap(from_fn(auth_middleware))
            .service(web::scope("/rbs").service(web::scope("/v0").configure(routes_config))),
    )
    .await
}

// ---------------------------------------------------------------------------
// Mock authenticator
// ---------------------------------------------------------------------------

/// How the mock authenticator answers a token.
#[derive(Clone)]
enum AuthMode {
    /// Bearer succeeds with the given subject, role and claims.
    Bearer { sub: String, role: String, claims: Value },
    /// Attest succeeds with the given claims.
    Attest { claims: Value },
    /// Attest tokens resolve to a Bearer context (an authenticator bug).
    AttestAsBearer,
    /// Every authentication attempt fails.
    AlwaysFail,
}

#[derive(Clone)]
struct FlowAuth {
    mode: AuthMode,
}

#[async_trait]
impl Auth for FlowAuth {
    async fn authenticate(&self, _token: &str, token_type: TokenType) -> Result<AuthContext, AuthError> {
        match (&self.mode, token_type) {
            (AuthMode::Bearer { sub, role, claims }, TokenType::Bearer) => Ok(AuthContext::Bearer(BearerContext {
                iss: "test-issuer".to_string(),
                sub: sub.clone(),
                role: role.clone(),
                claims: claims.clone(),
                token_type: TokenType::Bearer,
            })),
            (AuthMode::Attest { claims }, TokenType::Attest) => {
                Ok(AuthContext::Attest(AttestContext { claims: claims.clone(), token_type: TokenType::Attest }))
            },
            (AuthMode::AttestAsBearer, TokenType::Attest) => Ok(AuthContext::Bearer(BearerContext {
                iss: "test-issuer".to_string(),
                sub: "unexpected-subject".to_string(),
                role: "user".to_string(),
                claims: Value::Null,
                token_type: TokenType::Bearer,
            })),
            _ => Err(AuthError::TokenInvalid { reason: "mock auth failure".to_string() }),
        }
    }
}

fn bearer_auth(sub: &str) -> Arc<dyn Auth> {
    Arc::new(FlowAuth {
        mode: AuthMode::Bearer { sub: sub.to_string(), role: "user".to_string(), claims: Value::Null },
    })
}

fn bearer_auth_with_claims(sub: &str, claims: Value) -> Arc<dyn Auth> {
    Arc::new(FlowAuth { mode: AuthMode::Bearer { sub: sub.to_string(), role: "user".to_string(), claims } })
}

fn auth_with_mode(mode: AuthMode) -> Arc<dyn Auth> {
    Arc::new(FlowAuth { mode })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bearer(token: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {token}"))
}

fn attest(token: &str) -> (&'static str, String) {
    ("Authorization", format!("Attest {token}"))
}

fn b64(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
}

async fn body_json(resp: actix_web::dev::ServiceResponse<actix_web::body::BoxBody>) -> Value {
    let body = test::read_body(resp).await;
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}

fn bearer_ctx(sub: &str, claims: Value) -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: sub.to_string(),
        role: "user".to_string(),
        claims,
        token_type: TokenType::Bearer,
    })
}

/// RSA JWK used as the Bearer `enc-pubkey` claim (JWE recipient key).
fn rsa_jwk() -> Value {
    let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa key");
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
    json!({"kty": "RSA", "n": n, "e": e})
}

/// A Rego policy that authorizes every attestation token.
///
/// The engine evaluates the `verification` package, so user policies must use
/// that package name and expose `policy_matched` in their `result` document.
fn allow_all_rego() -> String {
    "package verification\n\nallow { true }\n\nresult = {\"policy_matched\": allow}\n".to_string()
}

/// Create a policy through the core service so it is owned by `sub`.
async fn seed_policy(core: &RbsCore, sub: &str, name: &str, rego: &str) -> String {
    let req = CreatePolicyRequest { name: name.to_string(), content_type: "base64".to_string(), content: b64(rego) };
    core.policy()
        .create(&bearer_ctx(sub, Value::Null), &req)
        .await
        .unwrap_or_else(|e| panic!("seed policy '{name}': {e}"))
        .policy_id
}

// ===========================================================================
// Policy routes — success paths
// ===========================================================================

/// Full policy lifecycle through the HTTP layer: create → get → list (with and
/// without an IDs filter) → update → delete → get (404).
#[actix_web::test]
async fn policy_crud_flow_succeeds() {
    ensure_db();
    let upstream = start_mock_upstream().await;
    let core = build_core(&upstream);
    let app = build_app(core.clone(), bearer_auth("flow_policy_user")).await;

    // Create → 201 with the generated UUID policy id.
    let create_body = json!({"name": "flow-policy-a", "content_type": "base64", "content": b64("package rbs\n")});
    let req = test::TestRequest::post()
        .uri("/rbs/v0/resource/policy")
        .insert_header(bearer("user-token"))
        .set_json(&create_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED, "policy create must succeed");
    let created = body_json(resp).await;
    assert_eq!(created["policy_name"], "flow-policy-a");
    assert_eq!(created["policy_version"], 1);
    let policy_id = created["policy_id"].as_str().expect("policy id").to_string();

    // Get → 200 with `applied_resources` (no resource bound yet).
    let req = test::TestRequest::get()
        .uri(&format!("/rbs/v0/resource/policy/{policy_id}"))
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "policy get must succeed");
    let fetched = body_json(resp).await;
    assert_eq!(fetched["policy_id"], policy_id.as_str());
    assert_eq!(fetched["applied_resources"], json!([]));

    // List → 200 with the created policy.
    let req = test::TestRequest::get().uri("/rbs/v0/resource/policy").insert_header(bearer("user-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "policy list must succeed");
    let listed = body_json(resp).await;
    assert_eq!(listed["total_count"], 1);
    assert_eq!(listed["limit"], 10);
    assert_eq!(listed["offset"], 0);

    // List with an IDs filter (valid UUID) → 200 and only that policy.
    let req = test::TestRequest::get()
        .uri(&format!("/rbs/v0/resource/policy?ids={policy_id}"))
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "policy list with ids must succeed");
    let filtered = body_json(resp).await;
    assert_eq!(filtered["total_count"], 1);
    assert_eq!(filtered["items"][0]["policy_id"], policy_id.as_str());

    // Update → 200 and the version increments.
    let update_body =
        json!({"name": "flow-policy-a2", "content_type": "base64", "content": b64("package rbs\n# v2\n")});
    let req = test::TestRequest::put()
        .uri(&format!("/rbs/v0/resource/policy/{policy_id}"))
        .insert_header(bearer("user-token"))
        .set_json(&update_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "policy update must succeed");
    let updated = body_json(resp).await;
    assert_eq!(updated["policy_name"], "flow-policy-a2");
    assert_eq!(updated["policy_version"], 2);

    // Delete → 204, then get → 404 (covers the handler's error mapping too).
    let req = test::TestRequest::delete()
        .uri(&format!("/rbs/v0/resource/policy/{policy_id}"))
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "policy delete must succeed");

    let req = test::TestRequest::get()
        .uri(&format!("/rbs/v0/resource/policy/{policy_id}"))
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "deleted policy must report 404");
    let err = body_json(resp).await;
    assert!(err["error"].as_str().expect("error message").contains("not found"));
}

/// Batch delete of two policies → 204, and a batch delete of an unknown policy
/// id → 404.
#[actix_web::test]
async fn policy_batch_delete_succeeds_and_reports_missing() {
    ensure_db();
    let upstream = start_mock_upstream().await;
    let core = build_core(&upstream);
    let app = build_app(core.clone(), bearer_auth("batch_policy_user")).await;

    let first = seed_policy(&core, "batch_policy_user", "batch-policy-1", "package rbs\n").await;
    let second = seed_policy(&core, "batch_policy_user", "batch-policy-2", "package rbs\n").await;

    let req = test::TestRequest::delete()
        .uri(&format!("/rbs/v0/resource/policy?ids={first},{second}"))
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "batch delete must succeed");

    let req = test::TestRequest::get().uri("/rbs/v0/resource/policy").insert_header(bearer("user-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["total_count"], 0, "batch delete must remove both policies");

    // Unknown (but well-formed) policy id → 404 from the service.
    let missing = uuid_like("batch_policy_user");
    let req = test::TestRequest::delete()
        .uri(&format!("/rbs/v0/resource/policy?ids={missing}"))
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "missing policy batch delete must report 404");
}

/// Deterministic, unique-enough UUID string for a test subject.
fn uuid_like(seed: &str) -> String {
    // Any syntactically valid UUID works: the handlers validate the shape, the
    // store then reports it as missing.
    let digest = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        hasher.finish()
    };
    format!("{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}", digest as u32, (digest >> 32) as u16, 0, 0, digest >> 16)
}

// ===========================================================================
// Policy routes — error mappings
// ===========================================================================

/// Duplicate name → 409, cross-user access → 403, unknown id → 404.
#[actix_web::test]
async fn policy_error_mappings() {
    ensure_db();
    let upstream = start_mock_upstream().await;
    let core = build_core(&upstream);

    let owner_app = build_app(core.clone(), bearer_auth("policy_owner")).await;
    let other_app = build_app(core.clone(), bearer_auth("policy_other")).await;

    // Owner creates a policy.
    let req = test::TestRequest::post()
        .uri("/rbs/v0/resource/policy")
        .insert_header(bearer("owner-token"))
        .set_json(json!({"name": "policy-dup", "content_type": "base64", "content": b64("package rbs\n")}))
        .to_request();
    let resp = test::call_service(&owner_app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Same name again for the same user → 409.
    let req = test::TestRequest::post()
        .uri("/rbs/v0/resource/policy")
        .insert_header(bearer("owner-token"))
        .set_json(json!({"name": "policy-dup", "content_type": "base64", "content": b64("package rbs\n")}))
        .to_request();
    let resp = test::call_service(&owner_app, req).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT, "duplicate policy name must conflict");

    let policy_id = seed_policy(&core, "policy_owner", "policy-owned-by-owner", "package rbs\n").await;

    // Another user's get / update / delete → 403 (user-scoped store).
    let req = test::TestRequest::get()
        .uri(&format!("/rbs/v0/resource/policy/{policy_id}"))
        .insert_header(bearer("other-token"))
        .to_request();
    let resp = test::call_service(&other_app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "cross-user policy get must be forbidden");

    let req = test::TestRequest::put()
        .uri(&format!("/rbs/v0/resource/policy/{policy_id}"))
        .insert_header(bearer("other-token"))
        .set_json(json!({"name": "stolen", "content_type": "base64", "content": b64("package rbs\n")}))
        .to_request();
    let resp = test::call_service(&other_app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "cross-user policy update must be forbidden");

    // Delete is resolved through a user-scoped lookup, so another user's policy
    // is indistinguishable from a missing one and collapses into 404.
    let req = test::TestRequest::delete()
        .uri(&format!("/rbs/v0/resource/policy/{policy_id}"))
        .insert_header(bearer("other-token"))
        .to_request();
    let resp = test::call_service(&other_app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "cross-user policy delete collapses into 404");

    // The owner can still see the policy afterwards.
    let req = test::TestRequest::get()
        .uri(&format!("/rbs/v0/resource/policy/{policy_id}"))
        .insert_header(bearer("owner-token"))
        .to_request();
    let resp = test::call_service(&owner_app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "failed cross-user delete must not touch the policy");

    // Unknown policy id → 404.
    let missing = uuid_like("policy-missing");
    let req = test::TestRequest::put()
        .uri(&format!("/rbs/v0/resource/policy/{missing}"))
        .insert_header(bearer("owner-token"))
        .set_json(json!({"name": "policy-dup-2", "content_type": "base64", "content": b64("package rbs\n")}))
        .to_request();
    let resp = test::call_service(&owner_app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "unknown policy update must report 404");

    let req = test::TestRequest::delete()
        .uri(&format!("/rbs/v0/resource/policy/{missing}"))
        .insert_header(bearer("owner-token"))
        .to_request();
    let resp = test::call_service(&owner_app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "unknown policy delete must report 404");
}

/// Request-level validation: query ranges, id shapes and the batch-delete cap
/// are all rejected with 400 before touching the store.
#[actix_web::test]
async fn policy_validation_errors_return_400() {
    ensure_db();
    let upstream = start_mock_upstream().await;
    let core = build_core(&upstream);
    let app = build_app(core.clone(), bearer_auth("policy_validation_user")).await;

    // Out-of-range pagination on the list query.
    let req = test::TestRequest::get()
        .uri("/rbs/v0/resource/policy?limit=0")
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "list limit=0 must be rejected");

    // Malformed policy id inside the `ids` filter.
    let req = test::TestRequest::get()
        .uri("/rbs/v0/resource/policy?ids=not-a-uuid")
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "non-UUID ids filter must be rejected");

    // Create body with a forbidden character in the name.
    let req = test::TestRequest::post()
        .uri("/rbs/v0/resource/policy")
        .insert_header(bearer("user-token"))
        .set_json(json!({"name": "bad<name", "content_type": "base64", "content": b64("package rbs\n")}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "forbidden policy name char must be rejected");

    // Update body with an unsupported content type.
    let policy_id = seed_policy(&core, "policy_validation_user", "policy-update-invalid", "package rbs\n").await;
    let req = test::TestRequest::put()
        .uri(&format!("/rbs/v0/resource/policy/{policy_id}"))
        .insert_header(bearer("user-token"))
        .set_json(json!({"name": "valid-name", "content_type": "hex", "content": b64("package rbs\n")}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "unsupported policy content_type must be rejected");

    // Batch delete above the id cap → 400.
    let ids = (0..11).map(|i| uuid_like(&format!("cap-{i}"))).collect::<Vec<_>>().join(",");
    let req = test::TestRequest::delete()
        .uri(&format!("/rbs/v0/resource/policy?ids={ids}"))
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "batch delete above the id cap must be rejected");
    let err = body_json(resp).await;
    assert!(err["error"].as_str().expect("error message").contains("exceeds maximum"));
}

// ===========================================================================
// Resource routes — success paths
// ===========================================================================

/// Full resource lifecycle through the HTTP layer against a Vault backend
/// served by the mock upstream: create → get (JWE content) → info → update →
/// upsert-create → list → delete.
#[actix_web::test]
async fn resource_crud_flow_succeeds() {
    ensure_db();
    let upstream = start_mock_upstream().await;
    let core = build_core(&upstream);
    seed_user("resource_flow_user").await;
    let claims = json!({"enc-pubkey": rsa_jwk()});
    let app = build_app(core.clone(), bearer_auth_with_claims("resource_flow_user", claims)).await;

    let policy_id = seed_policy(&core, "resource_flow_user", "resource-flow-policy", &allow_all_rego()).await;

    // Create → 201.
    let create_body = json!({
        "policy_id": policy_id,
        "content_type": "text",
        "content": b64("top-secret"),
        "additional_info": "flow resource",
    });
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/flow-repo/secret/flow-secret")
        .insert_header(bearer("user-token"))
        .set_json(&create_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    let created = body_json(resp).await;
    assert_eq!(status, StatusCode::CREATED, "resource create must succeed: {created}");
    assert_eq!(created["uri"], "/rbs/v0/vault/flow-repo/secret/flow-secret");
    assert_eq!(created["policy_id"], policy_id.as_str());
    assert_eq!(created["export_mode"], "jwe");

    // Get → 200 with JWE-encrypted content (compact serialization: 5 parts).
    let req = test::TestRequest::get()
        .uri("/rbs/v0/vault/flow-repo/secret/flow-secret")
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "resource get must succeed");
    let content = body_json(resp).await;
    let encoded = content["content"].as_str().unwrap_or_else(|| panic!("content string: {content}"));
    let jwe = base64::engine::general_purpose::STANDARD.decode(encoded).expect("content must be base64");
    let jwe = String::from_utf8(jwe).expect("JWE compact serialization must be ASCII");
    assert_eq!(jwe.split('.').count(), 5, "content must be a compact JWE");
    assert_ne!(jwe, "{\"secret\":\"mock-secret\"}", "content must not leak plaintext");

    // Info → 200 with metadata only.
    let req = test::TestRequest::get()
        .uri("/rbs/v0/vault/flow-repo/secret/flow-secret/info")
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "resource info must succeed");
    let info = body_json(resp).await;
    assert_eq!(info["content_type"], "text");
    assert_eq!(info["additional_info"], "flow resource");
    assert!(info.get("content").is_none(), "info must not expose content");

    // Update (existing resource) → 200 and the changed field is applied.
    let req = test::TestRequest::put()
        .uri("/rbs/v0/vault/flow-repo/secret/flow-secret")
        .insert_header(bearer("user-token"))
        .set_json(json!({"content_type": "json"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "resource update must succeed");
    assert_eq!(body_json(resp).await["content_type"], "json");

    // Upsert of a new URI (create through PUT) → 201.
    let req = test::TestRequest::put()
        .uri("/rbs/v0/vault/flow-repo/secret/flow-secret-2")
        .insert_header(bearer("user-token"))
        .set_json(json!({"policy_id": policy_id, "content_type": "binary"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED, "upsert of a new resource must report 201");
    assert_eq!(body_json(resp).await["content_type"], "binary");

    // List → both resources, newest first.
    let req = test::TestRequest::get()
        .uri("/rbs/v0/resource?limit=10&offset=0")
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "resource list must succeed");
    let listed = body_json(resp).await;
    assert_eq!(listed["total_count"], 2);
    assert_eq!(listed["items"][0]["resource_name"], "flow-secret-2");

    // Delete → 204, a second delete → 404.
    let req = test::TestRequest::delete()
        .uri("/rbs/v0/vault/flow-repo/secret/flow-secret")
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "resource delete must succeed");

    let req = test::TestRequest::delete()
        .uri("/rbs/v0/vault/flow-repo/secret/flow-secret")
        .insert_header(bearer("user-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "deleting a missing resource must report 404");
}

/// Body and URI validation on the resource routes: the handler-level
/// `validator` check, the wildcard provider check, the content-type whitelist
/// and the `jwe`-only export mode.
#[actix_web::test]
async fn resource_validation_errors_return_400() {
    ensure_db();
    let upstream = start_mock_upstream().await;
    let core = build_core(&upstream);
    seed_user("resource_validation_user").await;
    let app = build_app(core.clone(), bearer_auth("resource_validation_user")).await;
    let policy_id =
        seed_policy(&core, "resource_validation_user", "resource-validation-policy", &allow_all_rego()).await;

    // Handler-level validation: empty policy id fails `length(min = 1)`.
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/validation-repo/secret/validation-secret")
        .insert_header(bearer("user-token"))
        .set_json(json!({"policy_id": ""}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "empty policy id must be rejected");

    let req = test::TestRequest::put()
        .uri("/rbs/v0/vault/validation-repo/secret/validation-secret")
        .insert_header(bearer("user-token"))
        .set_json(json!({"policy_id": ""}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "empty policy id must be rejected on update");

    // Unconfigured (wildcard) provider.
    let req = test::TestRequest::post()
        .uri("/rbs/v0/unknown-provider/validation-repo/secret/validation-secret")
        .insert_header(bearer("user-token"))
        .set_json(json!({"policy_id": policy_id}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "unconfigured provider must be rejected");

    // Reserved provider name (the wildcard route must still validate it).
    let req = test::TestRequest::post()
        .uri("/rbs/v0/resource/validation-repo/secret/validation-secret")
        .insert_header(bearer("user-token"))
        .set_json(json!({"policy_id": policy_id}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "reserved provider name must be rejected");

    // Content type outside the whitelist.
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/validation-repo/secret/validation-secret")
        .insert_header(bearer("user-token"))
        .set_json(json!({"policy_id": policy_id, "content_type": "markdown"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "unsupported content_type must be rejected");

    // `export_mode: plain` is rejected: only JWE export is allowed.
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/validation-repo/secret/validation-secret")
        .insert_header(bearer("user-token"))
        .set_json(json!({"policy_id": policy_id, "export_mode": "plain"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "plaintext export must be rejected");
    let err = body_json(resp).await;
    assert!(err["error"].as_str().expect("error message").contains("export_mode"));

    // A policy that is not owned by the caller cannot be bound.
    let foreign_policy = seed_policy(&core, "resource_validation_other", "foreign-policy", &allow_all_rego()).await;
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/validation-repo/secret/validation-secret")
        .insert_header(bearer("user-token"))
        .set_json(json!({"policy_id": foreign_policy}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "a policy owned by another user cannot be bound");
}

// ===========================================================================
// Resource retrieve (`POST /rbs/v0/{uri}/retrieve`)
// ===========================================================================

/// Retrieve with attestation evidence: the GTA mock returns a token, the
/// authenticator resolves it to an attestation context, and the resource is
/// returned as a JWE encrypted to the token's `tee-pubkey`.
#[actix_web::test]
async fn resource_retrieve_succeeds() {
    ensure_db();
    let upstream = start_mock_upstream().await;
    let core = build_core(&upstream);
    let owner = "retrieve_flow_user";
    seed_user(owner).await;
    let policy_id = seed_policy(&core, owner, "retrieve-flow-policy", &allow_all_rego()).await;

    // Register the resource through the HTTP API as its owner.
    let owner_app = build_app(core.clone(), bearer_auth(owner)).await;
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/retrieve-repo/secret/retrieve-secret")
        .insert_header(bearer("user-token"))
        .set_json(json!({"policy_id": policy_id, "content_type": "text", "content": b64("retrieve-secret")}))
        .to_request();
    let resp = test::call_service(&owner_app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED, "resource create must succeed");

    // Retrieve: the attestation token carries the JWE recipient key.
    let attest_claims = json!({"attester_data": {"runtime_data": {"tee-pubkey": rsa_jwk()}}});
    let attest_app = build_app(core.clone(), auth_with_mode(AuthMode::Attest { claims: attest_claims })).await;
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/retrieve-repo/secret/retrieve-secret/retrieve")
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&attest_app, req).await;
    let retrieve_status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(retrieve_status, StatusCode::OK, "retrieve must succeed with attestation evidence: {body}");
    assert_eq!(body["uri"], "/rbs/v0/vault/retrieve-repo/secret/retrieve-secret");
    let encoded = body["content"].as_str().expect("content");
    let jwe = base64::engine::general_purpose::STANDARD.decode(encoded).expect("content must be base64");
    assert_eq!(String::from_utf8(jwe).expect("JWE must be ASCII").split('.').count(), 5);

    // Authenticator that resolves an attest token to a Bearer context → 500.
    let mismatched_app = build_app(core.clone(), auth_with_mode(AuthMode::AttestAsBearer)).await;
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/retrieve-repo/secret/retrieve-secret/retrieve")
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&mismatched_app, req).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR, "unexpected auth context must be a 500");
    let err = body_json(resp).await;
    assert!(err["error"].as_str().expect("error message").contains("unexpected auth context"));

    // Authenticator that rejects the token issued by the attestation backend → 500.
    let failing_app = build_app(core.clone(), auth_with_mode(AuthMode::AlwaysFail)).await;
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/retrieve-repo/secret/retrieve-secret/retrieve")
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&failing_app, req).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR, "rejected attest token must be a 500");

    // Retrieve of a resource that does not exist → 404.
    let req = test::TestRequest::post()
        .uri("/rbs/v0/vault/retrieve-repo/secret/missing-secret/retrieve")
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&attest_app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "missing resource must report 404");
}

// ===========================================================================
// Framework error helpers
// ===========================================================================

/// `RequestDeserializeError` renders a 400 `ErrorBody`, and the JSON/query
/// payload error handlers convert actix payload errors into it.
#[actix_web::test]
async fn deserialize_error_helpers_map_to_400() {
    async fn body_bytes(resp: HttpResponse) -> Value {
        let bytes = actix_web::body::to_bytes(resp.into_body()).await.expect("response body");
        serde_json::from_slice(&bytes).expect("body must be JSON")
    }

    let err = rbs_rest::routes::error::RequestDeserializeError::new("field `name` is invalid".to_string());
    assert_eq!(err.to_string(), "field `name` is invalid", "Display must expose the message");

    let resp = actix_web::ResponseError::error_response(&err);
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_bytes(resp).await["error"], "field `name` is invalid");

    let req = test::TestRequest::default().to_http_request();

    let json_err = actix_web::error::JsonPayloadError::Deserialize(
        serde_json::from_str::<Value>("{not json").expect_err("bad json"),
    );
    let converted = rbs_rest::routes::json_error_handler(json_err, &req);
    let resp = converted.as_response_error().error_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "json payload errors must map to 400");
    let json = body_bytes(resp).await;
    assert!(json["error"].as_str().expect("error message").contains("key must be a string"));

    let de_err = <serde::de::value::Error as serde::de::Error>::custom("bad query parameter");
    let converted =
        rbs_rest::routes::query_error_handler(actix_web::error::QueryPayloadError::Deserialize(de_err), &req);
    let resp = converted.as_response_error().error_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query payload errors must map to 400");
    assert!(body_bytes(resp).await["error"].as_str().expect("error message").contains("bad query parameter"));
}

// ===========================================================================
// Authentication middleware branches
// ===========================================================================

/// Attest tokens are only accepted on resource GET paths; a Bearer-only path,
/// a path outside `/rbs/v0` and the bare `/rbs/v0/` prefix all reject them.
#[actix_web::test]
async fn auth_middleware_attest_token_path_branches() {
    ensure_db();
    let upstream = start_mock_upstream().await;
    let core = build_core(&upstream);
    let app = build_app(core.clone(), auth_with_mode(AuthMode::Attest { claims: Value::Null })).await;

    // Bearer-only path: `/rbs/v0/users` is not a resource GET path.
    let req = test::TestRequest::get().uri("/rbs/v0/users").insert_header(attest("attest-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "attest token on an admin path must be rejected");

    // Path outside `/rbs/v0` with GET is never a resource GET path.
    let app_outside = test::init_service(
        App::new()
            .app_data(web::Data::new(core.clone()))
            .app_data(web::Data::new(auth_with_mode(AuthMode::Attest { claims: Value::Null })))
            .wrap(from_fn(auth_middleware))
            .route("/outside", web::get().to(|| async { HttpResponse::Ok().body("ok") })),
    )
    .await;
    let req = test::TestRequest::get().uri("/outside").insert_header(attest("attest-token")).to_request();
    let resp = test::call_service(&app_outside, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "attest token outside /rbs/v0 must be rejected");

    // Bare scope prefix (`/rbs/v0/`) has an empty relative path → not a resource GET.
    let req = test::TestRequest::get().uri("/rbs/v0/").insert_header(attest("attest-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "attest token on the bare scope root must be rejected");

    // Resource GET path: the attest token is accepted and reaches the handler.
    let req = test::TestRequest::get()
        .uri("/rbs/v0/vault/auth-repo/secret/auth-secret")
        .insert_header(attest("attest-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "attest token must be accepted on a resource GET path");
    assert!(
        resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").contains("application/json"),
        "the handler must produce a JSON error body"
    );
}

/// A Bearer request reaching the middleware without a registered authenticator
/// is a server-side misconfiguration → 500.
#[actix_web::test]
async fn auth_middleware_without_authenticator_returns_500() {
    ensure_db();
    let upstream = start_mock_upstream().await;
    let core = build_core(&upstream);

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(core))
            .wrap(from_fn(auth_middleware))
            .service(web::scope("/rbs").service(web::scope("/v0").configure(routes_config))),
    )
    .await;

    let req = test::TestRequest::get().uri("/rbs/v0/users").insert_header(bearer("user-token")).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR, "missing authenticator must be a 500");
    let json = body_json(resp).await;
    assert_eq!(json["error"], "Internal server error");
}

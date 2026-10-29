/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
 * PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Supplementary branch coverage for `AdminManager`.
//!
//! This is a dedicated test binary with its own file-backed SQLite database, so
//! it neither depends on nor disturbs the global pool used by
//! `tests/admin_tests.rs`. Tests share the pool within this binary, use unique
//! usernames, and never assert on the absolute store size.
//!
//! Targeted branches: `Debug`, JWK key material on create/update, `auth_type`
//! only updates, Attest-token rejection, callers whose Bearer token names no
//! stored user, list pagination boundaries, and the resource-dependent branch
//! of the delete guard.

use std::sync::Arc;

use base64::Engine as _;
use rbs_api_types::config::{AdminConfig, AdminKeyConfig, Database};
use rbs_api_types::{AuthType, Role, UserCreateRequest, UserListQuery, UserUpdateRequest};
use rbs_core::auth::authz::AuthzFacade;
use rbs_core::policy_engine::RealPolicyEngine;
use rbs_core::{AdminManager, AttestContext, AuthContext, BearerContext, RbsError, TokenType};

const ADMIN: &str = "Administrator";

// ---------------------------------------------------------------------------
// Pool and row helpers
// ---------------------------------------------------------------------------

/// Initialize the process-global pool once per binary and apply the core schema.
async fn ensure_db() {
    static INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    INIT.get_or_init(|| async {
        let path = std::env::temp_dir().join("rbs_core_admin_manager_branch.sqlite");
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path.to_string_lossy(), suffix));
        }
        let config = Database {
            db_type: "sqlite".to_string(),
            url: format!("sqlite:{}?mode=rwc", path.to_string_lossy()),
            max_connections: 1,
            timeout: 30,
            sql_file_path: String::new(),
        };
        let db = rbs_core::rdb::init_pool(&config).await.expect("init pool");
        rbs_core::rdb::migrate_core_tables(&db).await.expect("migrate core tables");
    })
    .await;
}

/// Insert (or refresh) a user row so `ensure_enabled` has a matching record.
async fn seed_user(username: &str, role: &str, status: i32) {
    use sea_orm::ConnectionTrait;
    ensure_db().await;
    let db = rbs_core::rdb::get_connection_from_pool().expect("db pool");
    let backend = db.get_database_backend();
    let escaped = username.replace('\'', "''");
    let sql = format!(
        "INSERT OR REPLACE INTO t_user_info (user_id, username, role, auth_type, auth_value, auth_alg, status, created_at, updated_at) \
         VALUES ('id-{escaped}', '{escaped}', '{role}', 'jwt', 'stub', 'RSA', {status}, 0, 0)"
    );
    db.execute(sea_orm::Statement::from_string(backend, sql)).await.expect("seed user row");
}

async fn seed_enabled_user(username: &str, role: &str) {
    seed_user(username, role, 1).await;
}

async fn ensure_admin() {
    seed_enabled_user(ADMIN, "admin").await;
}

// ---------------------------------------------------------------------------
// Manager, auth context and request helpers
// ---------------------------------------------------------------------------

fn make_manager(max_users: u32) -> AdminManager {
    // The admin key path is only read during bootstrap, which these tests never
    // trigger on an empty store.
    AdminManager::new(
        AdminConfig {
            max_users,
            admin_key: AdminKeyConfig {
                public_key_path: Some("/tmp/rbs_branch_admin.pem".to_string()),
                jwks_file: None,
            },
        },
        AuthzFacade::new(Arc::new(RealPolicyEngine)),
    )
}

fn bearer_ctx(sub: &str, role: &str) -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: sub.to_string(),
        role: role.to_string(),
        claims: serde_json::Value::Null,
        token_type: TokenType::Bearer,
    })
}

fn attest_ctx() -> AuthContext {
    AuthContext::Attest(AttestContext {
        claims: serde_json::json!({"attester": "test"}),
        token_type: TokenType::Attest,
    })
}

fn all_users_query() -> UserListQuery {
    UserListQuery { limit: Some(100), offset: Some(0), role: None, enabled: None }
}

fn update_req() -> UserUpdateRequest {
    UserUpdateRequest { role: None, enabled: None, auth_type: None, public_key: None, jwk: None }
}

fn update_req_with_enabled(enabled: bool) -> UserUpdateRequest {
    let mut req = update_req();
    req.enabled = Some(enabled);
    req
}

// ---------------------------------------------------------------------------
// Key material helpers
// ---------------------------------------------------------------------------

fn rsa_pem_b64() -> String {
    let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa key");
    let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("pkey");
    base64::engine::general_purpose::STANDARD.encode(pkey.public_key_to_pem().expect("public pem"))
}

fn rsa_jwk() -> serde_json::Value {
    let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa key");
    serde_json::json!({
        "kty": "RSA",
        "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
        "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
    })
}

fn ec_p256_jwk() -> serde_json::Value {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).expect("group");
    let key = openssl::ec::EcKey::generate(&group).expect("ec key");
    let mut ctx = openssl::bn::BigNumContext::new().expect("bn ctx");
    let mut x = openssl::bn::BigNum::new().expect("x");
    let mut y = openssl::bn::BigNum::new().expect("y");
    key.public_key().affine_coordinates(&group, &mut x, &mut y, &mut ctx).expect("coordinates");
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x.to_vec()),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y.to_vec()),
    })
}

fn ed25519_jwk() -> serde_json::Value {
    let key = openssl::pkey::PKey::generate_ed25519().expect("ed25519 key");
    serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.raw_public_key().expect("raw key")),
    })
}

fn oct_jwk() -> serde_json::Value {
    serde_json::json!({"kty": "oct", "k": "A228ztpSnwyxAQ"})
}

fn create_req_with_pk(username: &str, pk_b64: &str) -> UserCreateRequest {
    UserCreateRequest {
        username: username.to_string(),
        role: None,
        enabled: None,
        auth_type: AuthType::Jwt,
        public_key: Some(pk_b64.to_string()),
        jwk: None,
    }
}

fn create_req_with_jwk(username: &str, jwk: serde_json::Value) -> UserCreateRequest {
    UserCreateRequest {
        username: username.to_string(),
        role: None,
        enabled: None,
        auth_type: AuthType::Jwt,
        public_key: None,
        jwk: Some(jwk),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_manager_debug_renders_without_config_details() {
    ensure_db().await;
    // The hand-written `Debug` impl intentionally exposes nothing but the type
    // name so that key paths / limits never reach a log line.
    let rendered = format!("{:?}", make_manager(5));
    assert_eq!(rendered, "AdminManager");
    assert!(!rendered.contains("max_users"));
    assert!(!rendered.contains("admin_key"));
}

#[tokio::test]
async fn create_user_accepts_rsa_and_ec_jwk_key_material() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    // RSA JWK: converted to PEM inside `extract_auth_material`.
    manager
        .create_user(&create_req_with_jwk("branch_jwk_rsa", rsa_jwk()), &admin)
        .await
        .expect("create user from RSA JWK");

    // EC JWK: same path, different key type.
    manager
        .create_user(&create_req_with_jwk("branch_jwk_ec", ec_p256_jwk()), &admin)
        .await
        .expect("create user from EC JWK");

    // An empty `public_key` is treated as absent, so the JWK is used instead of
    // failing mutual-exclusion validation.
    let mut empty_pk_with_jwk = create_req_with_jwk("branch_jwk_empty_pk", rsa_jwk());
    empty_pk_with_jwk.public_key = Some(String::new());
    manager.create_user(&empty_pk_with_jwk, &admin).await.expect("empty public_key must fall back to the JWK");

    for username in ["branch_jwk_rsa", "branch_jwk_ec", "branch_jwk_empty_pk"] {
        let stored = manager.get_user(username, &admin).await.expect("get user").expect("user must exist");
        assert_eq!(stored.username, username);
        assert_eq!(stored.role, Role::User);
        assert!(stored.enabled);
    }
}

#[tokio::test]
async fn create_user_rejects_unsupported_jwk_key_types() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    // `oct` (symmetric) JWKs are not valid authentication public keys.
    let err = manager
        .create_user(&create_req_with_jwk("branch_jwk_oct", oct_jwk()), &admin)
        .await
        .expect_err("symmetric JWK must be rejected");
    assert!(
        matches!(&err, RbsError::InvalidParameter(msg) if msg.contains("Unsupported JWK key type")),
        "got: {err:?}"
    );

    // `OKP` JWKs are recognized by JOSE but unsupported here, which surfaces as
    // an unsupported key type rather than an invalid parameter shape.
    let err = manager
        .create_user(&create_req_with_jwk("branch_jwk_okp", ed25519_jwk()), &admin)
        .await
        .expect_err("OKP JWK must be rejected");
    assert!(matches!(err, RbsError::InvalidParameter(_)), "got: {err:?}");

    // Nothing was persisted for the rejected names.
    assert!(manager.get_user("branch_jwk_oct", &admin).await.expect("get user").is_none());
}

#[tokio::test]
async fn update_user_rotates_jwk_and_accepts_auth_type_only() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    manager.create_user(&create_req_with_pk("branch_update_jwk", &rsa_pem_b64()), &admin).await.expect("create user");

    // A JWK-only update rotates the stored key material.
    let mut rotate = update_req();
    rotate.jwk = Some(ec_p256_jwk());
    let updated = manager.update_user("branch_update_jwk", &rotate, &admin).await.expect("rotate with JWK");
    assert_eq!(updated.username, "branch_update_jwk");

    // An empty `public_key` alongside the JWK is treated as absent.
    let mut empty_pk_rotate = update_req();
    empty_pk_rotate.public_key = Some(String::new());
    empty_pk_rotate.jwk = Some(rsa_jwk());
    manager
        .update_user("branch_update_jwk", &empty_pk_rotate, &admin)
        .await
        .expect("empty public_key must fall back to the JWK");

    // `auth_type` alone is a valid update: it flips the stored auth method
    // without touching the key material.
    let mut auth_type_only = update_req();
    auth_type_only.auth_type = Some(AuthType::Jwt);
    let updated = manager.update_user("branch_update_jwk", &auth_type_only, &admin).await.expect("auth_type update");
    assert!(updated.enabled);

    // An unsupported JWK is rejected before the transaction opens.
    let mut bad_rotate = update_req();
    bad_rotate.jwk = Some(oct_jwk());
    let err = manager
        .update_user("branch_update_jwk", &bad_rotate, &admin)
        .await
        .expect_err("unsupported JWK must be rejected");
    assert!(matches!(err, RbsError::InvalidParameter(_)), "got: {err:?}");
}

#[tokio::test]
async fn user_operations_reject_attest_tokens() {
    ensure_admin().await;
    let manager = make_manager(20);
    let attest = attest_ctx();

    // Attest tokens carry no Bearer `sub`, so the admin policy cannot authorize
    // them; every user-management entry point must fail closed.
    let err = manager.list_users(&all_users_query(), &attest).await.expect_err("attest list must fail");
    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");

    let err = manager.get_user(ADMIN, &attest).await.expect_err("attest get must fail");
    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");

    let err =
        manager.update_user(ADMIN, &update_req_with_enabled(true), &attest).await.expect_err("attest update must fail");
    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");

    let err = manager
        .create_user(&create_req_with_pk("branch_attest_user", &rsa_pem_b64()), &attest)
        .await
        .expect_err("attest create must fail");
    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");

    let err = manager.delete_user("branch_attest_user", &attest).await.expect_err("attest delete must fail");
    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");

    assert!(manager.get_user("branch_attest_user", &bearer_ctx(ADMIN, "admin")).await.expect("get").is_none());
}

#[tokio::test]
async fn operations_reject_callers_without_a_stored_user_row() {
    ensure_admin().await;
    let manager = make_manager(20);

    // A structurally valid admin token whose `sub` was never provisioned must be
    // rejected by the enabled-check, not served.
    let ghost = bearer_ctx("branch_ghost_admin", "admin");
    let err = manager.list_users(&all_users_query(), &ghost).await.expect_err("ghost list must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");

    let err = manager.get_user(ADMIN, &ghost).await.expect_err("ghost get must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");

    let err = manager
        .create_user(&create_req_with_pk("branch_ghost_user", &rsa_pem_b64()), &ghost)
        .await
        .expect_err("ghost create must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");

    let err = manager.delete_user("branch_ghost_user", &ghost).await.expect_err("ghost delete must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");
}

#[tokio::test]
async fn list_users_pagination_boundaries() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    manager
        .create_user(&create_req_with_pk("branch_page_a", &rsa_pem_b64()), &admin)
        .await
        .expect("create page user a");
    manager
        .create_user(&create_req_with_pk("branch_page_b", &rsa_pem_b64()), &admin)
        .await
        .expect("create page user b");

    // An offset past the end of the result set yields an empty page while still
    // reporting the filtered total.
    let page = manager
        .list_users(&UserListQuery { limit: Some(10), offset: Some(100_000), role: None, enabled: None }, &admin)
        .await
        .expect("list offset page");
    assert!(page.users.is_empty());
    assert!(page.total_count >= 2, "total_count must ignore pagination: {}", page.total_count);
    assert_eq!(page.limit, 10);
    assert_eq!(page.offset, 100_000);

    // Offset 0 with limit at the upper boundary combined with both filters.
    let page = manager
        .list_users(
            &UserListQuery { limit: Some(100), offset: Some(0), role: Some(Role::Admin), enabled: Some(true) },
            &admin,
        )
        .await
        .expect("list filtered page");
    assert!(page.users.iter().all(|u| u.role == Role::Admin && u.enabled));
    assert!(page.users.iter().any(|u| u.username == ADMIN));
    assert_eq!(page.total_count, page.users.len() as i64);

    // A page that starts inside the result set returns fewer rows than the limit.
    let page = manager
        .list_users(&UserListQuery { limit: Some(1), offset: Some(1), role: None, enabled: None }, &admin)
        .await
        .expect("list middle page");
    assert_eq!(page.users.len(), 1);
    assert_eq!(page.offset, 1);

    // Default page size / offset are applied when the query omits them.
    let page = manager
        .list_users(&UserListQuery { limit: None, offset: None, role: None, enabled: None }, &admin)
        .await
        .expect("list default page");
    assert_eq!(page.limit, 10);
    assert_eq!(page.offset, 0);
    assert!(page.users.len() <= 10);
}

#[tokio::test]
async fn delete_user_reports_resource_dependents() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    manager
        .create_user(&create_req_with_pk("branch_delete_res_owner", &rsa_pem_b64()), &admin)
        .await
        .expect("create resource owner");
    insert_resource_owned_by("branch_delete_res_owner").await;

    // A surviving resource must block the delete and be reported separately
    // from policies so operators can see what has to be cleaned up first.
    let err = manager.delete_user("branch_delete_res_owner", &admin).await.expect_err("dependents must block");
    match err {
        RbsError::UserHasDependents { policies, resources } => {
            assert_eq!(policies, 0);
            assert_eq!(resources, 1);
        },
        other => panic!("expected UserHasDependents, got: {other:?}"),
    }

    // The user is still present after the refused delete.
    assert!(manager.get_user("branch_delete_res_owner", &admin).await.expect("get user").is_some());
}

async fn insert_resource_owned_by(username: &str) {
    use sea_orm::ConnectionTrait;
    let db = rbs_core::rdb::get_connection_from_pool().expect("db pool");
    let backend = db.get_database_backend();
    let escaped = username.replace('\'', "''");
    let sql = format!(
        "INSERT INTO t_res_info (username, provider_name, repo_name, res_type, res_name, res_info, created_at, updated_at, content_type, export_mode, policy_id) \
         VALUES ('{escaped}', 'branch_provider', 'branch_repo', 'secret', 'branch_res', NULL, 0, 0, NULL, 'jwe', 'branch-policy')"
    );
    db.execute(sea_orm::Statement::from_string(backend, sql)).await.expect("insert resource row");
}

#[tokio::test]
async fn bootstrap_admin_is_a_noop_when_users_already_exist() {
    ensure_admin().await;
    // This binary's pool always holds the seeded administrator, so bootstrap
    // must skip the key-material read entirely and leave the store untouched.
    make_manager(20).bootstrap_admin().await.expect("bootstrap must be a no-op");
    let admin = bearer_ctx(ADMIN, "admin");
    let page = make_manager(20)
        .list_users(
            &UserListQuery { limit: Some(100), offset: Some(0), role: Some(Role::Admin), enabled: None },
            &admin,
        )
        .await
        .expect("list admins");
    assert_eq!(page.users.iter().filter(|u| u.username == ADMIN).count(), 1);
}

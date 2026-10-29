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

//! Database-failure and admin-key-configuration error paths for `AdminManager`.
//!
//! This is a dedicated test binary: the scenarios below intentionally corrupt the
//! schema of the process-global pool (renamed tables/columns, `RAISE(ABORT)`
//! triggers, a cleared user table) and must therefore not share a binary with
//! tests that expect an intact schema. Everything runs inside a single
//! `#[tokio::test]` so the mutations are strictly sequential, and every mutation
//! is reverted before the next scenario starts.
//!
//! Covered paths:
//! - `bootstrap_admin` user-count failure,
//! - `create_user` insert failure (maps to `InternalUnexpected`, not a duplicate),
//! - `update_user` transaction failure (not the `not_found` mapping),
//! - `delete_user` dependent-count and delete failures,
//! - `ensure_enabled` / `lookup_user_auth` query failures,
//! - every `read_admin_key` configuration and file-format branch.
//!
//! Not reachable from an integration test: the pool-handle errors on
//! `list_users` / `get_user` / `create_user` / `update_user` / `delete_user`
//! (`get_connection_from_pool`), because `require_enabled_*` already needs the
//! pool and fails first through `ensure_enabled`.

use std::sync::Arc;

use rbs_api_types::config::{AdminConfig, AdminKeyConfig, Database};
use rbs_api_types::{AuthType, UserCreateRequest, UserListQuery, UserUpdateRequest};
use rbs_core::auth::authz::AuthzFacade;
use rbs_core::policy_engine::RealPolicyEngine;
use rbs_core::{AdminManager, AuthContext, BearerContext, RbsError, TokenType, UserAuthProvider};

const ADMIN: &str = "Administrator";

// ---------------------------------------------------------------------------
// Pool, schema and row helpers
// ---------------------------------------------------------------------------

async fn init_shared_pool() {
    let path = std::env::temp_dir().join("rbs_core_admin_error_paths.sqlite");
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
}

async fn exec(sql: &str) {
    use sea_orm::ConnectionTrait;
    let db = rbs_core::rdb::get_connection_from_pool().expect("db pool");
    let backend = db.get_database_backend();
    db.execute(sea_orm::Statement::from_string(backend, sql.to_string()))
        .await
        .unwrap_or_else(|e| panic!("statement failed: {sql}: {e}"));
}

async fn seed_user(username: &str, role: &str, status: i32) {
    let escaped = username.replace('\'', "''");
    exec(&format!(
        "INSERT OR REPLACE INTO t_user_info (user_id, username, role, auth_type, auth_value, auth_alg, status, created_at, updated_at) \
         VALUES ('id-{escaped}', '{escaped}', '{role}', 'jwt', 'stub', 'RSA', {status}, 0, 0)"
    ))
    .await;
}

async fn clear_users() {
    exec("DELETE FROM t_user_info").await;
}

// ---------------------------------------------------------------------------
// Manager builders
// ---------------------------------------------------------------------------

fn manager_with_key(admin_key: AdminKeyConfig, max_users: u32) -> AdminManager {
    AdminManager::new(AdminConfig { max_users, admin_key }, AuthzFacade::new(Arc::new(RealPolicyEngine)))
}

fn manager(pem_path: &str) -> AdminManager {
    manager_with_key(AdminKeyConfig { public_key_path: Some(pem_path.to_string()), jwks_file: None }, 20)
}

fn admin_ctx() -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: ADMIN.to_string(),
        role: "admin".to_string(),
        claims: serde_json::Value::Null,
        token_type: TokenType::Bearer,
    })
}

fn all_users_query() -> UserListQuery {
    UserListQuery { limit: Some(100), offset: Some(0), role: None, enabled: None }
}

fn create_req(username: &str) -> UserCreateRequest {
    use base64::Engine as _;
    let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa key");
    let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("pkey");
    let pem = pkey.public_key_to_pem().expect("public pem");
    UserCreateRequest {
        username: username.to_string(),
        role: None,
        enabled: None,
        auth_type: AuthType::Jwt,
        public_key: Some(base64::engine::general_purpose::STANDARD.encode(pem)),
        jwk: None,
    }
}

// ---------------------------------------------------------------------------
// Key material files used by the `read_admin_key` scenarios
// ---------------------------------------------------------------------------

struct KeyFiles {
    _dir: tempfile::TempDir,
    pem: String,
    jwk: String,
    bad_pem: String,
    bad_json: String,
    unsupported_jwk: String,
    missing: String,
}

fn key_files() -> KeyFiles {
    use base64::Engine as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa key");
    let pkey = openssl::pkey::PKey::from_rsa(rsa.clone()).expect("pkey");

    let pem_path = dir.path().join("admin_pub.pem");
    std::fs::write(&pem_path, pkey.public_key_to_pem().expect("public pem")).expect("write pem");

    let jwk_path = dir.path().join("admin_jwk.json");
    let jwk = serde_json::json!({
        "kty": "RSA",
        "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
        "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
    });
    std::fs::write(&jwk_path, serde_json::to_vec(&jwk).expect("serialize jwk")).expect("write jwk");

    let bad_pem_path = dir.path().join("bad_pub.pem");
    std::fs::write(&bad_pem_path, b"not a pem document").expect("write bad pem");

    let bad_json_path = dir.path().join("bad_jwk.json");
    std::fs::write(&bad_json_path, b"{ this is not json").expect("write bad json");

    let unsupported_jwk_path = dir.path().join("oct_jwk.json");
    std::fs::write(&unsupported_jwk_path, br#"{"kty":"oct","k":"c2VjcmV0"}"#).expect("write oct jwk");

    KeyFiles {
        _dir: dir,
        pem: pem_path.to_string_lossy().to_string(),
        jwk: jwk_path.to_string_lossy().to_string(),
        bad_pem: bad_pem_path.to_string_lossy().to_string(),
        bad_json: bad_json_path.to_string_lossy().to_string(),
        unsupported_jwk: unsupported_jwk_path.to_string_lossy().to_string(),
        missing: std::env::temp_dir().join("rbs_missing_admin_key_material").to_string_lossy().to_string(),
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// `bootstrap_admin` must report the user-count failure instead of panicking.
async fn bootstrap_count_failure(pem: &str) {
    exec("ALTER TABLE t_user_info RENAME TO t_user_info_bak").await;
    let err = manager(pem).bootstrap_admin().await.expect_err("count against a missing table must fail");
    exec("ALTER TABLE t_user_info_bak RENAME TO t_user_info").await;

    match err {
        RbsError::InternalUnexpected { context } => {
            assert!(context.contains("no such table"), "unexpected context: {context}");
        },
        other => panic!("expected InternalUnexpected, got: {other:?}"),
    }
}

/// A failed INSERT (here: a `BEFORE INSERT` trigger) is not a duplicate, so it
/// must map to `InternalUnexpected` rather than `ResourceConflict`.
async fn create_user_insert_failure(pem: &str) {
    seed_user(ADMIN, "admin", 1).await;
    exec(
        "CREATE TRIGGER fail_user_insert BEFORE INSERT ON t_user_info \
         BEGIN SELECT RAISE(ABORT, 'insert blocked by test'); END",
    )
    .await;

    let err = manager(pem)
        .create_user(&create_req("err_paths_create"), &admin_ctx())
        .await
        .expect_err("insert failure must surface");
    exec("DROP TRIGGER fail_user_insert").await;

    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");
}

/// A failed UPDATE inside the transaction keeps the generic internal error and
/// must not be mistaken for the `not_found` mapping.
async fn update_user_transaction_failure(pem: &str) {
    seed_user("err_paths_update", "user", 1).await;
    exec(
        "CREATE TRIGGER fail_user_update BEFORE UPDATE ON t_user_info \
         BEGIN SELECT RAISE(ABORT, 'update blocked by test'); END",
    )
    .await;

    let req = UserUpdateRequest {
        role: None,
        enabled: Some(false),
        auth_type: Some(AuthType::Jwt),
        public_key: None,
        jwk: None,
    };
    let err = manager(pem)
        .update_user("err_paths_update", &req, &admin_ctx())
        .await
        .expect_err("update failure must surface");
    exec("DROP TRIGGER fail_user_update").await;

    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");
}

/// The dependent counts read the policy and resource tables separately, so a
/// failure in either table must abort the delete with an internal error.
async fn delete_user_dependent_count_failures(pem: &str) {
    seed_user(ADMIN, "admin", 1).await;
    seed_user("err_paths_delete", "user", 1).await;

    exec("ALTER TABLE t_res_policy RENAME TO t_res_policy_bak").await;
    let err = manager(pem)
        .delete_user("err_paths_delete", &admin_ctx())
        .await
        .expect_err("policy count failure must surface");
    exec("ALTER TABLE t_res_policy_bak RENAME TO t_res_policy").await;
    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");

    exec("ALTER TABLE t_res_info RENAME TO t_res_info_bak").await;
    let err = manager(pem)
        .delete_user("err_paths_delete", &admin_ctx())
        .await
        .expect_err("resource count failure must surface");
    exec("ALTER TABLE t_res_info_bak RENAME TO t_res_info").await;
    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");
}

/// Once both dependent counts are zero, a failing DELETE must still be reported
/// as an internal error (not as "not found", which is reserved for 0 rows).
async fn delete_user_delete_failure(pem: &str) {
    exec(
        "CREATE TRIGGER fail_user_delete BEFORE DELETE ON t_user_info \
         BEGIN SELECT RAISE(ABORT, 'delete blocked by test'); END",
    )
    .await;
    let err =
        manager(pem).delete_user("err_paths_delete", &admin_ctx()).await.expect_err("delete failure must surface");
    exec("DROP TRIGGER fail_user_delete").await;

    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");
    // The row survived the failed delete.
    let err = manager(pem).delete_user("err_paths_delete", &admin_ctx()).await;
    assert!(err.is_ok(), "delete should succeed once the trigger is gone: {err:?}");
}

/// `ensure_enabled` and the authentication lookup both hit the user table
/// directly, so a schema fault there is reported as an internal error /
/// `TokenInvalid` respectively.
async fn user_lookup_failures(pem: &str) {
    exec("ALTER TABLE t_user_info RENAME TO t_user_info_bak").await;

    let err = manager(pem)
        .list_users(&all_users_query(), &admin_ctx())
        .await
        .expect_err("enabled check against a missing table must fail");
    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");

    let err = manager(pem).get_user_auth(ADMIN).await.expect_err("auth lookup against a missing table must fail");
    exec("ALTER TABLE t_user_info_bak RENAME TO t_user_info").await;

    assert!(matches!(err, rbs_core::AuthError::TokenInvalid { .. }), "got: {err:?}");
}

/// Every `read_admin_key` branch: configuration exclusivity, missing/invalid
/// files, unsupported JWK types, and the two success paths.
async fn admin_key_config_paths(files: &KeyFiles) {
    // Both sources configured: mutually exclusive.
    clear_users().await;
    let both = AdminKeyConfig { public_key_path: Some(files.pem.clone()), jwks_file: Some(files.jwk.clone()) };
    let err = manager_with_key(both, 20).bootstrap_admin().await.expect_err("both sources must be rejected");
    assert!(
        matches!(&err, RbsError::InternalUnexpected { context } if context.contains("mutually exclusive")),
        "got: {err:?}"
    );

    // Neither source configured...
    clear_users().await;
    let none = AdminKeyConfig { public_key_path: None, jwks_file: None };
    let err = manager_with_key(none, 20).bootstrap_admin().await.expect_err("missing source must be rejected");
    assert!(
        matches!(&err, RbsError::InternalUnexpected { context } if context.contains("either public_key_path or jwks_file")),
        "got: {err:?}"
    );

    // ...and empty strings count as "not configured".
    clear_users().await;
    let empty = AdminKeyConfig { public_key_path: Some(String::new()), jwks_file: Some(String::new()) };
    let err = manager_with_key(empty, 20).bootstrap_admin().await.expect_err("empty paths must be rejected");
    assert!(matches!(err, RbsError::InternalUnexpected { .. }), "got: {err:?}");

    // PEM source that does not exist on disk.
    clear_users().await;
    let err = manager(&files.missing).bootstrap_admin().await.expect_err("missing PEM file must be rejected");
    assert!(
        matches!(&err, RbsError::InternalUnexpected { context } if context.contains("Failed to read public key file")),
        "got: {err:?}"
    );

    // PEM source with unparsable content.
    clear_users().await;
    let err = manager(&files.bad_pem).bootstrap_admin().await.expect_err("invalid PEM must be rejected");
    assert!(matches!(err, RbsError::InvalidParameter(_)), "got: {err:?}");

    // JWK file that does not exist on disk.
    clear_users().await;
    let missing_jwk = AdminKeyConfig { public_key_path: None, jwks_file: Some(files.missing.clone()) };
    let err = manager_with_key(missing_jwk, 20).bootstrap_admin().await.expect_err("missing JWK file rejected");
    assert!(
        matches!(&err, RbsError::InternalUnexpected { context } if context.contains("Failed to read JWK file")),
        "got: {err:?}"
    );

    // JWK file with malformed JSON.
    clear_users().await;
    let bad_json = AdminKeyConfig { public_key_path: None, jwks_file: Some(files.bad_json.clone()) };
    let err = manager_with_key(bad_json, 20).bootstrap_admin().await.expect_err("malformed JWK json rejected");
    assert!(
        matches!(&err, RbsError::InternalUnexpected { context } if context.contains("Failed to parse JWK file")),
        "got: {err:?}"
    );

    // JWK file holding a syntactically valid but unsupported key.
    clear_users().await;
    let unsupported = AdminKeyConfig { public_key_path: None, jwks_file: Some(files.unsupported_jwk.clone()) };
    let err = manager_with_key(unsupported, 20).bootstrap_admin().await.expect_err("unsupported JWK rejected");
    assert!(
        matches!(&err, RbsError::InvalidParameter(msg) if msg.contains("Unsupported JWK key type")),
        "got: {err:?}"
    );

    // Success path: PEM file.
    clear_users().await;
    manager(&files.pem).bootstrap_admin().await.expect("bootstrap from a PEM file");

    // Success path: JWK file (the JWK is converted to PEM and its algorithm is
    // derived before the administrator row is written).
    clear_users().await;
    let jwk_cfg = AdminKeyConfig { public_key_path: None, jwks_file: Some(files.jwk.clone()) };
    manager_with_key(jwk_cfg, 20).bootstrap_admin().await.expect("bootstrap from a JWK file");
    let page = manager(&files.pem).list_users(&all_users_query(), &admin_ctx()).await.expect("list users");
    assert_eq!(page.total_count, 1);
    assert_eq!(page.users[0].username, ADMIN);
}

#[tokio::test]
async fn admin_manager_maps_database_and_admin_key_failures() {
    init_shared_pool().await;

    // The key files must outlive the scenarios, so the owning `KeyFiles` handle
    // is bound here instead of being dropped with a temporary.
    let files = key_files();
    let pem = files.pem.clone();

    bootstrap_count_failure(&pem).await;
    create_user_insert_failure(&pem).await;
    update_user_transaction_failure(&pem).await;
    delete_user_dependent_count_failures(&pem).await;
    delete_user_delete_failure(&pem).await;
    user_lookup_failures(&pem).await;
    admin_key_config_paths(&files).await;
}

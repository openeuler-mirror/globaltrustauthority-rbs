/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 */

//! Integration tests for `SeaOrmResourceRepository` — real SQLite in-memory.

use std::sync::Arc;

use rbs_core::rdb::execute_sql_file_path;
use rbs_core::resource::error::ResourceError;
use rbs_core::resource::repository::{ResourceEntity, ResourceRepository, SeaOrmResourceRepository};
use sea_orm::{Database, DatabaseConnection};

async fn setup() -> (SeaOrmResourceRepository, Arc<DatabaseConnection>) {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("sqlite connect");
    execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql")
        .await
        .expect("migrate tables");
    let db = Arc::new(db);
    (SeaOrmResourceRepository::new(db.clone()), db)
}

fn make_entity(uri: &str, user: &str, policy_id: &str) -> ResourceEntity {
    let (prov, repo, rtype, rname) = parse_test_uri(uri);
    ResourceEntity {
        username: user.into(), provider_name: prov, repo_name: repo,
        res_type: rtype, res_name: rname, res_info: None,
        created_at: 1000, updated_at: 1000,
        content_type: None, export_mode: "jwe".into(), policy_id: policy_id.into(),
    }
}

fn parse_test_uri(uri: &str) -> (String, String, String, String) {
    let segments: Vec<&str> = uri.trim_start_matches("/rbs/v0/").split('/').collect();
    (segments[0].into(), segments[1].into(), segments[2].into(), segments[3].into())
}

// ── SQL-09: INSERT ────────────────────────────────────────────────────

#[tokio::test]
async fn insert_resource_success_then_find() {
    let (repo, _db) = setup().await;
    let entity = make_entity("/rbs/v0/vault/default/secret/mykey", "user1", "pol-1");
    repo.insert(&entity).await.expect("insert");
    let found = repo.find_by_uri("/rbs/v0/vault/default/secret/mykey").await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().policy_id, "pol-1");
}

#[tokio::test]
async fn insert_resource_duplicate_returns_error() {
    let (repo, _db) = setup().await;
    let entity = make_entity("/rbs/v0/vault/default/secret/mykey", "user1", "pol-1");
    repo.insert(&entity).await.unwrap();
    let result = repo.insert(&entity).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(&err, ResourceError::BackendError { .. }),
        "expected BackendError, got {:?}", err
    );
}

// ── SQL-10: find_by_uri ───────────────────────────────────────────────

#[tokio::test]
async fn find_resource_by_uri_not_found_returns_none() {
    let (repo, _db) = setup().await;
    let found = repo.find_by_uri("/rbs/v0/vault/default/secret/nonexistent").await.unwrap();
    assert!(found.is_none());
}

// ── SQL-11: list_by_user ──────────────────────────────────────────────

#[tokio::test]
async fn list_by_user_empty() {
    let (repo, _db) = setup().await;
    let items = repo.list_by_user("user1").await.unwrap();
    assert!(items.is_empty());
}

#[tokio::test]
async fn list_by_user_filters_by_user() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/a", "u1", "p1")).await.unwrap();
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/b", "u1", "p2")).await.unwrap();
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/c", "u2", "p3")).await.unwrap();
    let items = repo.list_by_user("u1").await.unwrap();
    assert_eq!(items.len(), 2);
    let items2 = repo.list_by_user("u3").await.unwrap();
    assert!(items2.is_empty());
}

// ── SQL-12: find_by_policy_id ─────────────────────────────────────────

#[tokio::test]
async fn count_by_user_returns_count() {
    let (repo, _db) = setup().await;
    assert_eq!(repo.count_by_user("u1").await.unwrap(), 0);
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/a", "u1", "p1")).await.unwrap();
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/b", "u1", "p2")).await.unwrap();
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/c", "u2", "p3")).await.unwrap();
    assert_eq!(repo.count_by_user("u1").await.unwrap(), 2);
    assert_eq!(repo.count_by_user("u2").await.unwrap(), 1);
    assert_eq!(repo.count_by_user("u3").await.unwrap(), 0);
}

#[tokio::test]
async fn find_by_policy_id_returns_matching() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/x", "u1", "pol-a")).await.unwrap();
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/y", "u1", "pol-a")).await.unwrap();
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/z", "u2", "pol-b")).await.unwrap();
    let r = repo.find_by_policy_id("pol-a").await.unwrap();
    assert_eq!(r.len(), 2);
    let r2 = repo.find_by_policy_id("pol-c").await.unwrap();
    assert!(r2.is_empty());
}

// ── update ────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_resource_success() {
    let (repo, _db) = setup().await;
    let entity = make_entity("/rbs/v0/vault/default/secret/mykey", "user1", "pol-1");
    repo.insert(&entity).await.unwrap();
    let mut updated = entity.clone();
    updated.export_mode = "jwe".to_string();
    updated.content_type = Some("json".to_string());
    let old_time = entity.updated_at;
    let affected = repo.update("/rbs/v0/vault/default/secret/mykey", &updated, old_time).await.unwrap();
    assert_eq!(affected, 1);
    let row = repo.find_by_uri("/rbs/v0/vault/default/secret/mykey").await.unwrap().unwrap();
    assert_eq!(row.export_mode, "jwe");
    assert_eq!(row.content_type, Some("json".to_string()));
}

#[tokio::test]
async fn update_resource_not_found() {
    let (repo, _db) = setup().await;
    let entity = make_entity("/rbs/v0/vault/default/secret/nonexistent", "user1", "pol-1");
    let affected = repo.update("/rbs/v0/vault/default/secret/nonexistent", &entity, entity.updated_at).await.unwrap();
    assert_eq!(affected, 0);
}

// ── delete ────────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_resource_success() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("/rbs/v0/vault/default/secret/mykey", "user1", "pol-1")).await.unwrap();
    let affected = repo.delete("/rbs/v0/vault/default/secret/mykey", "user1").await.unwrap();
    assert_eq!(affected, 1);
    assert!(repo.find_by_uri("/rbs/v0/vault/default/secret/mykey").await.unwrap().is_none());
}

#[tokio::test]
async fn delete_resource_not_found() {
    let (repo, _db) = setup().await;
    let affected = repo.delete("/rbs/v0/vault/default/secret/nonexistent", "user1").await.unwrap();
    assert_eq!(affected, 0);
}

// ── concurrency: per-user limit precision ──────────────────────────────
//
// Verifies that `create_with_user_limit_check` holds an exclusive per-user lock
// across the count+insert, so concurrent same-user creates cannot exceed the
// limit (the TOCTOU race fixed by the transactional lock). Uses an in-memory
// SQLite DB (the test sandbox cannot open file-backed DBs) with a multi-
// connection pool and busy_timeout so contended writers wait rather than fail.

async fn setup_concurrency() -> (SeaOrmResourceRepository, Arc<DatabaseConnection>) {
    use sea_orm::{ConnectOptions, ConnectionTrait, Database as Db, Statement};

    let mut opt = ConnectOptions::new("sqlite::memory:".to_string());
    opt.max_connections(8)
        .map_sqlx_sqlite_opts(|o| {
            // WAL is unavailable for :memory: (silently ignored); busy_timeout
            // is what matters — it makes a contended writer wait instead of
            // returning SQLITE_BUSY immediately.
            o.busy_timeout(std::time::Duration::from_secs(5))
                .synchronous(sea_orm::sqlx::sqlite::SqliteSynchronous::Normal)
        });
    let db = Db::connect(opt).await.expect("sqlite connect");
    execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql")
        .await
        .expect("migrate tables");

    // The owning user must exist for the per-user row-lock UPDATE to match.
    let backend = db.get_database_backend();
    db.execute(Statement::from_sql_and_values(
        backend,
        "INSERT INTO t_user_info (user_id, username, role, auth_type, auth_value, auth_alg, status, created_at, updated_at) \
         VALUES (?, ?, 'user', 'jwt', 'pubkey', 'EdDSA', 1, 1, 1)",
        ["uid-concurrency".into(), "concurrent-user".into()],
    ))
    .await
    .expect("insert user");

    let db = Arc::new(db);
    (SeaOrmResourceRepository::new(db.clone()), db)
}

/// SQL-CC-01: 20 concurrent creates for the same user with max_per_user=2 must
/// result in exactly 2 successes and 18 CountExceed errors — never more than 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn create_with_user_limit_check_concurrent_precision() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    let (repo, _db) = setup_concurrency().await;
    let repo = StdArc::new(repo);
    let max_per_user: usize = 2;
    let total: usize = 20;
    let success = StdArc::new(AtomicUsize::new(0));
    let rejected = StdArc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for i in 0..total {
        let repo = repo.clone();
        let success = success.clone();
        let rejected = rejected.clone();
        handles.push(tokio::spawn(async move {
            let uri = format!("/rbs/v0/vault/repo1/secret/concurrent{}", i);
            let entity = make_entity(&uri, "concurrent-user", "pol-1");
            match repo.create_with_user_limit_check(&uri, &entity, max_per_user).await {
                Ok(()) => { success.fetch_add(1, Ordering::SeqCst); }
                Err(ResourceError::CountExceed { .. }) => { rejected.fetch_add(1, Ordering::SeqCst); }
                Err(e) => panic!("unexpected error: {:?}", e),
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let s = success.load(Ordering::SeqCst);
    let r = rejected.load(Ordering::SeqCst);
    assert_eq!(s, max_per_user, "expected exactly {} successes, got {}", max_per_user, s);
    assert_eq!(r, total - max_per_user, "expected {} rejections, got {}", total - max_per_user, r);
    // Final persisted count must equal the limit (no over-insert under concurrency).
    assert_eq!(
        repo.count_by_user("concurrent-user").await.unwrap(),
        max_per_user,
    );
}

/// SQL-CC-02: a single successful create under the limit (sanity for the txn path).
#[tokio::test]
async fn create_with_user_limit_check_single_success() {
    let (repo, _db) = setup_concurrency().await;
    let entity = make_entity("/rbs/v0/vault/repo1/secret/single", "concurrent-user", "pol-1");
    repo.create_with_user_limit_check("/rbs/v0/vault/repo1/secret/single", &entity, 10)
        .await
        .expect("create under limit");
    assert_eq!(repo.count_by_user("concurrent-user").await.unwrap(), 1);
}

/// SQL-CC-03: duplicate uri is rejected as AlreadyExists (dup-check inside txn).
#[tokio::test]
async fn create_with_user_limit_check_duplicate_rejected() {
    let (repo, _db) = setup_concurrency().await;
    let uri = "/rbs/v0/vault/repo1/secret/dup";
    let entity = make_entity(uri, "concurrent-user", "pol-1");
    repo.create_with_user_limit_check(uri, &entity, 10).await.unwrap();
    let result = repo.create_with_user_limit_check(uri, &entity, 10).await;
    assert!(matches!(result, Err(ResourceError::AlreadyExists { .. })), "got {:?}", result);
}

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

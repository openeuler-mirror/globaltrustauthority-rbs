/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 */

//! Integration tests for `SeaOrmPolicyRepository` — real SQLite in-memory.

use std::sync::Arc;

use rbs_core::policy::error::PolicyError;
use rbs_core::policy::repository::{PolicyEntity, PolicyRepository, SeaOrmPolicyRepository};
use rbs_core::rdb::execute_sql_file_path;
use sea_orm::{Database, DatabaseConnection, TransactionTrait};

async fn setup() -> (SeaOrmPolicyRepository, Arc<DatabaseConnection>) {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("sqlite connect");
    execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql")
        .await
        .expect("migrate tables");
    let db = Arc::new(db);
    (SeaOrmPolicyRepository::new(db.clone()), db)
}

fn make_entity(id: &str, user: &str, name: &str) -> PolicyEntity {
    PolicyEntity {
        policy_id: id.into(), username: user.into(), policy_name: name.into(),
        policy_version: 1, policy_content: "base64content".into(),
        content_type: "base64".into(), created_at: 1000, updated_at: 1000,
    }
}

// ── SQL-01: INSERT ────────────────────────────────────────────────────

#[tokio::test]
async fn insert_success_then_find_by_id() {
    let (repo, _db) = setup().await;
    let entity = make_entity("p1", "user1", "policy-one");

    repo.insert(&entity).await.expect("insert should succeed");

    let found = repo.find_by_id("p1").await.expect("find_by_id");
    assert!(found.is_some());
    let row = found.unwrap();
    assert_eq!(row.policy_name, "policy-one");
    assert_eq!(row.username, "user1");
    assert_eq!(row.policy_version, 1);
}

#[tokio::test]
async fn insert_duplicate_primary_key_returns_error() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("dup", "user1", "first")).await.unwrap();

    let result = repo.insert(&make_entity("dup", "user1", "second")).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PolicyError::BackendError { .. }));
}

// ── SQL-02: find_by_id ────────────────────────────────────────────────

#[tokio::test]
async fn find_by_id_not_found_returns_none() {
    let (repo, _db) = setup().await;
    let result = repo.find_by_id("no-such-id").await.expect("find_by_id");
    assert!(result.is_none());
}

// ── SQL-03: find_by_name_and_user ─────────────────────────────────────

#[tokio::test]
async fn find_by_name_and_user_found() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "my-policy")).await.unwrap();

    let found = repo.find_by_name_and_user("my-policy", "user1").await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().policy_id, "p1");
}

#[tokio::test]
async fn find_by_name_and_user_not_found_wrong_name() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "my-policy")).await.unwrap();

    let found = repo.find_by_name_and_user("wrong-name", "user1").await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn find_by_name_and_user_not_found_wrong_user() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "my-policy")).await.unwrap();

    let found = repo.find_by_name_and_user("my-policy", "other-user").await.unwrap();
    assert!(found.is_none());
}

// ── SQL-04: find_by_ids_and_user ───────────────────────────────────────

#[tokio::test]
async fn find_by_ids_empty_returns_empty() {
    let (repo, _db) = setup().await;
    let result = repo.find_by_ids_and_user(&[], "user1").await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_ids_single_match() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "a")).await.unwrap();
    let result = repo.find_by_ids_and_user(&["p1".into()], "user1").await.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].policy_id, "p1");
}

#[tokio::test]
async fn find_by_ids_multiple_match() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "a")).await.unwrap();
    repo.insert(&make_entity("p2", "user1", "b")).await.unwrap();
    let result = repo.find_by_ids_and_user(&["p1".into(), "p2".into()], "user1").await.unwrap();
    assert_eq!(result.len(), 2);
}

#[tokio::test]
async fn find_by_ids_wrong_user_filters_out() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "a")).await.unwrap();
    let result = repo.find_by_ids_and_user(&["p1".into()], "other-user").await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_ids_mixed_match_and_missing() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "a")).await.unwrap();
    // p2 never inserted
    let result = repo.find_by_ids_and_user(&["p1".into(), "p2".into()], "user1").await.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].policy_id, "p1");
}

// ── SQL-05: count_by_user ─────────────────────────────────────────────

#[tokio::test]
async fn count_by_user_zero_when_none() {
    let (repo, _db) = setup().await;
    let count = repo.count_by_user("user1").await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn count_by_user_counts_only_own_policies() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "a")).await.unwrap();
    repo.insert(&make_entity("p2", "user1", "b")).await.unwrap();
    repo.insert(&make_entity("p3", "user2", "c")).await.unwrap();

    assert_eq!(repo.count_by_user("user1").await.unwrap(), 2);
    assert_eq!(repo.count_by_user("user3").await.unwrap(), 0);
}

// ── SQL-06: list_by_user ───────────────────────────────────────────────

#[tokio::test]
async fn list_by_user_empty_returns_zero() {
    let (repo, _db) = setup().await;
    let (items, total) = repo.list_by_user("user1", 0, 10).await.unwrap();
    assert!(items.is_empty());
    assert_eq!(total, 0);
}

#[tokio::test]
async fn list_by_user_returns_all_for_user() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "u1", "a")).await.unwrap();
    repo.insert(&make_entity("p2", "u1", "b")).await.unwrap();
    repo.insert(&make_entity("p3", "u2", "c")).await.unwrap();

    let (items, total) = repo.list_by_user("u1", 0, 10).await.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(total, 2);
}

#[tokio::test]
async fn list_by_user_pagination_offset() {
    let (repo, _db) = setup().await;
    for i in 1..=5 {
        repo.insert(&make_entity(&format!("p{}", i), "user1", &format!("n{}", i))).await.unwrap();
    }
    let (items, total) = repo.list_by_user("user1", 2, 10).await.unwrap();
    assert_eq!(items.len(), 3); // 5 total, offset 2 → 3 remaining
    assert_eq!(total, 5);
}

#[tokio::test]
async fn list_by_user_pagination_limit() {
    let (repo, _db) = setup().await;
    for i in 1..=5 {
        repo.insert(&make_entity(&format!("p{}", i), "user1", &format!("n{}", i))).await.unwrap();
    }
    let (items, total) = repo.list_by_user("user1", 0, 2).await.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(total, 5);
}

// ── SQL-08: delete ─────────────────────────────────────────────────────

#[tokio::test]
async fn delete_existing_removes_row() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "a")).await.unwrap();
    repo.delete("p1").await.unwrap();
    let found = repo.find_by_id("p1").await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn delete_non_existing_does_not_error() {
    let (repo, _db) = setup().await;
    let result = repo.delete("no-such-id").await;
    assert!(result.is_ok());
}

// ── update_with_version ───────────────────────────────────────────────

#[tokio::test]
async fn update_with_version_success() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "old-name")).await.unwrap();
    let updated = make_entity("p1", "user1", "new-name");
    let affected = repo.update_with_version("p1", 1, updated).await.unwrap();
    assert_eq!(affected, 1);
    let row = repo.find_by_id("p1").await.unwrap().unwrap();
    assert_eq!(row.policy_name, "new-name");
    assert_eq!(row.policy_version, 2); // auto-incremented
}

#[tokio::test]
async fn update_with_version_conflict_returns_zero() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "v1")).await.unwrap();
    // expected_version = 999 does not match current version = 1
    let affected = repo.update_with_version("p1", 999, make_entity("p1", "user1", "v2")).await.unwrap();
    assert_eq!(affected, 0);
}

// ── delete_by_ids_txn ─────────────────────────────────────────────────

#[tokio::test]
async fn delete_by_ids_txn_single() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "a")).await.unwrap();
    let txn = _db.begin().await.unwrap();
    let affected = repo.delete_by_ids_txn(&txn, &["p1".into()], "user1").await.unwrap();
    assert_eq!(affected, 1);
    txn.commit().await.unwrap();
    assert!(repo.find_by_id("p1").await.unwrap().is_none());
}

#[tokio::test]
async fn delete_by_ids_txn_multiple() {
    let (repo, _db) = setup().await;
    repo.insert(&make_entity("p1", "user1", "a")).await.unwrap();
    repo.insert(&make_entity("p2", "user1", "b")).await.unwrap();
    repo.insert(&make_entity("p3", "user2", "c")).await.unwrap();
    let txn = _db.begin().await.unwrap();
    let affected = repo.delete_by_ids_txn(&txn, &["p1".into(), "p2".into(), "p3".into()], "user1").await.unwrap();
    assert_eq!(affected, 2); // only p1, p2 belong to user1
    txn.commit().await.unwrap();
}

#[tokio::test]
async fn delete_by_ids_txn_empty_ids() {
    let (repo, _db) = setup().await;
    let txn = _db.begin().await.unwrap();
    let affected = repo.delete_by_ids_txn(&txn, &[], "user1").await.unwrap();
    assert_eq!(affected, 0);
    txn.commit().await.unwrap();
}

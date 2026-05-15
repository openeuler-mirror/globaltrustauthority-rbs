/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 */

//! Integration tests for `DbPolicyClient` — real SQLite in-memory.

use std::sync::Arc;

use rbs_core::policy::repository::{PolicyEntity, PolicyRepository, SeaOrmPolicyRepository};
use rbs_core::rdb::execute_sql_file_path;
use rbs_core::resource::adapter::{DbPolicyClient, PolicyClient};
use rbs_core::resource::repository::{ResourceEntity, ResourceRepository, SeaOrmResourceRepository};
use sea_orm::Database;

async fn setup() -> (DbPolicyClient, SeaOrmPolicyRepository, SeaOrmResourceRepository) {
    let db = Arc::new(Database::connect("sqlite::memory:").await.expect("sqlite connect"));
    execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql").await.expect("migrate");
    (DbPolicyClient::new(db.clone()), SeaOrmPolicyRepository::new(db.clone()), SeaOrmResourceRepository::new(db))
}

fn make_resource(uri: &str, user: &str, pid: &str) -> ResourceEntity {
    let s: Vec<&str> = uri.trim_start_matches("/rbs/v0/").split('/').collect();
    ResourceEntity {
        user_id: user.into(), provider_name: s[0].into(), repo_name: s[1].into(),
        res_type: s[2].into(), res_name: s[3].into(), res_info: None,
        create_time: 1000, update_time: 1000, content_type: None,
        export_mode: "jwe".into(), policy_id: pid.into(),
    }
}

fn make_entity(id: &str, user: &str, name: &str) -> PolicyEntity {
    PolicyEntity {
        policy_id: id.into(), user_id: user.into(), policy_name: name.into(),
        policy_version: 1, policy_content: "cGFja2FnZSB4Cg==".into(), // "package x\n" base64
        content_type: "base64".into(), created_at: 1000, updated_at: 1000,
    }
}

// ── SQL-13: validate_policy ───────────────────────────────────────────

#[tokio::test]
async fn validate_policy_true_when_exists() {
    let (client, repo, _res_repo) = setup().await;
    repo.insert(make_entity("p1", "user1", "a")).await.unwrap();
    let valid = client.validate_policy("p1", "user1").await.unwrap();
    assert!(valid);
}

#[tokio::test]
async fn validate_policy_false_when_wrong_user() {
    let (client, repo, _res_repo) = setup().await;
    repo.insert(make_entity("p1", "user1", "a")).await.unwrap();
    let valid = client.validate_policy("p1", "other").await.unwrap();
    assert!(!valid);
}

#[tokio::test]
async fn validate_policy_false_when_not_exists() {
    let (client, _repo, _res_repo) = setup().await;
    let valid = client.validate_policy("no-such", "user1").await.unwrap();
    assert!(!valid);
}

// ── SQL-14: get_policy_content ────────────────────────────────────────

#[tokio::test]
async fn get_policy_content_decodes_base64() {
    let (client, repo, _res_repo) = setup().await;
    repo.insert(make_entity("p1", "user1", "a")).await.unwrap();
    let content = client.get_policy_content("p1").await.unwrap();
    assert_eq!(content, "package x\n");
}

#[tokio::test]
async fn get_policy_content_not_found_returns_error() {
    let (client, _repo, _res_repo) = setup().await;
    let result = client.get_policy_content("no-such").await;
    assert!(result.is_err());
}

// ── relation_res_ids ──────────────────────────────────────────────────

#[tokio::test]
async fn relation_res_ids_returns_uris() {
    let (client, repo, res_repo) = setup().await;
    repo.insert(make_entity("p1", "user1", "a")).await.unwrap();
    res_repo.insert(&make_resource("/rbs/v0/vault/default/secret/x", "u1", "p1")).await.unwrap();
    res_repo.insert(&make_resource("/rbs/v0/vault/default/cert/y", "u1", "p1")).await.unwrap();

    let uris = client.relation_res_ids("p1", "u1").await.unwrap();
    assert_eq!(uris.len(), 2);
    assert!(uris.contains(&"/rbs/v0/vault/default/secret/x".to_string()));
    assert!(uris.contains(&"/rbs/v0/vault/default/cert/y".to_string()));
}

#[tokio::test]
async fn relation_res_ids_empty_when_no_match() {
    let (client, _repo, _res_repo) = setup().await;
    let uris = client.relation_res_ids("no-such", "u1").await.unwrap();
    assert!(uris.is_empty());
}

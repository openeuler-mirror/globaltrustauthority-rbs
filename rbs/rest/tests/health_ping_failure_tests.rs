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

//! Readiness probe failure-path test: the global pool is initialized against a
//! SQLite file, the file is then overwritten with garbage and the connection's
//! page cache is dropped, so the probe's read query fails with a non-config
//! error. The endpoint must answer 503 with the fixed `ping failed` reason and
//! must not leak any driver detail (paths, SQL, error text).
//!
//! This lives in its own test binary because the DB pool is process-global and
//! must stay broken for the whole test.

use actix_web::{http::StatusCode, test, App};
use rbs_api_types::config::Database;
use rbs_core::rdb;
use rbs_rest::server::health::configure_health_routes;
use sea_orm::ConnectionTrait;
use serde_json::{json, Value};

/// Overwrite `path` with bytes that are not a SQLite database and force the
/// pooled connection to re-read from disk (`PRAGMA shrink_memory` drops the
/// page cache; without it the cached pages would mask the corruption).
async fn corrupt_database_file(path: &std::path::Path) {
    std::fs::write(path, vec![0xFFu8; 8192]).expect("overwrite database file");
    let db = rdb::get_connection_from_pool().expect("pool");
    let backend = db.get_database_backend();
    db.execute(sea_orm::Statement::from_string(backend, "PRAGMA shrink_memory")).await.expect("drop page cache");
}

#[actix_web::test]
async fn readyz_reports_ping_failure_without_leaking_details() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("rbs-health-unreadable.sqlite");
    let config = Database {
        db_type: "sqlite".to_string(),
        max_connections: 1,
        timeout: 5,
        url: format!("sqlite:{}?mode=rwc", db_path.to_string_lossy()),
        sql_file_path: String::new(),
    };
    rdb::init_database(&config).await.expect("init database");
    assert!(rdb::ping().await.is_ok(), "the freshly created pool must answer the probe");

    corrupt_database_file(&db_path).await;
    assert!(rdb::ping().await.is_err(), "the corrupted file must make the probe query fail");

    let app = test::init_service(App::new().configure(configure_health_routes)).await;
    let resp = test::call_service(&app, test::TestRequest::get().uri("/readyz").to_request()).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body: Value = test::read_body_json(resp).await;
    // Fixed reason string only: the driver error text is logged, never returned.
    assert_eq!(body, json!({"status": "error", "reason": "sqlite: ping failed"}));
    let rendered = body.to_string();
    for leaked in [db_path.to_string_lossy().as_ref(), "shrink_memory", "sqlite_master", "code: 26"] {
        assert!(!rendered.contains(leaked), "probe body must not leak '{leaked}': {rendered}");
    }

    // Liveness stays independent of the dependency state.
    let resp = test::call_service(&app, test::TestRequest::get().uri("/livez").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

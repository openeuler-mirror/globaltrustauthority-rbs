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

//! Readiness probe timeout test via pool saturation: the pool is initialized with
//! `max_connections = 1` and the single connection is held by an open transaction
//! (started through the test-only sea-orm dev-dependency), so `/readyz`'s pooled query
//! queues behind it and the 2s probe timeout must fire — returning 503 with the
//! timeout reason instead of hanging until the sqlx acquire timeout (30s).

use std::time::Instant;

use actix_web::{http::StatusCode, test, App};
use rbs_api_types::config::Database;
use rbs_core::rdb;
use rbs_rest::server::health::configure_health_routes;
use sea_orm::TransactionTrait;
use serde_json::{json, Value};
use tokio::sync::oneshot;

fn single_connection_pool_config() -> Database {
    Database {
        db_type: "sqlite".to_string(),
        max_connections: 1,
        timeout: 30,
        url: "sqlite::memory:".to_string(),
        sql_file_path: String::new(),
    }
}

#[actix_web::test]
async fn readyz_probe_times_out_when_pool_saturated() {
    rdb::init_database(&single_connection_pool_config()).await.expect("init database");
    let conn = rdb::get_connection_from_pool().expect("get connection");

    let (tx, rx) = oneshot::channel::<()>();
    // Hold the only pooled connection with an open transaction until the probe finishes.
    let holder = tokio::spawn(async move {
        let _txn = conn.begin().await.expect("begin transaction");
        let _ = tx.send(());
        // Keep the transaction (and thus the connection) checked out.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });
    rx.await.expect("transaction started");

    let app = test::init_service(App::new().configure(configure_health_routes)).await;
    let start = Instant::now();
    let req = test::TestRequest::get().uri("/readyz").to_request();
    let resp = test::call_service(&app, req).await;
    let elapsed = start.elapsed().as_secs_f64();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body, json!({"status": "error", "reason": "sqlite: probe timeout"}));
    // The 2s timeout must fire (not hang): allow scheduling slack around 2s.
    assert!(elapsed >= 1.8, "probe returned too early: {elapsed}s");
    assert!(elapsed < 4.0, "probe hung beyond timeout: {elapsed}s");

    holder.abort();
}

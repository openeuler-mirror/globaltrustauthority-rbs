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

//! Health endpoint tests with the global DB pool initialized: `/readyz` returns 200 and
//! is idempotently repeatable. This binary owns its own pool state (separate test
//! executable), initialized once via a shared async guard.

use actix_web::{http::StatusCode, test, App};
use rbs_api_types::config::Database;
use rbs_core::rdb;
use rbs_rest::server::health::configure_health_routes;
use serde_json::{json, Value};
use tokio::sync::OnceCell;

static POOL_INIT: OnceCell<()> = OnceCell::const_new();

async fn ensure_pool() {
    POOL_INIT
        .get_or_init(|| async {
            let db = Database {
                db_type: "sqlite".to_string(),
                max_connections: 5,
                timeout: 30,
                url: "sqlite::memory:".to_string(),
                sql_file_path: String::new(),
            };
            rdb::init_database(&db).await.expect("init database");
        })
        .await;
}

#[actix_web::test]
async fn readyz_pool_ready_returns_200_and_is_idempotent() {
    ensure_pool().await;
    let app = test::init_service(App::new().configure(configure_health_routes)).await;
    for i in 0..5 {
        let req = test::TestRequest::get().uri("/readyz").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK, "iteration {i}");
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body, json!({"status": "ok"}), "iteration {i}");
    }
}

#[actix_web::test]
async fn livez_unaffected_by_pool_state() {
    ensure_pool().await;
    let app = test::init_service(App::new().configure(configure_health_routes)).await;
    let req = test::TestRequest::get().uri("/livez").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body, json!({"status": "ok"}));
}

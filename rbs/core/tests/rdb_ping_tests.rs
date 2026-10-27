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

//! Tests for `rdb::ping()` — the readiness probe primitive backed by the global connection
//! pool. This file is intentionally the only rbs-core test binary that touches the global
//! `DB_CONN` static, so the "pool not initialized" state is deterministic in a fresh process.

use rbs_api_types::config::Database;
use rbs_core::rdb::{self, DbError};

fn sqlite_memory_config(max_connections: u32) -> Database {
    Database {
        db_type: "sqlite".to_string(),
        max_connections,
        timeout: 30,
        url: "sqlite::memory:".to_string(),
        sql_file_path: String::new(),
    }
}

#[tokio::test]
async fn ping_pool_not_initialized_then_ok_after_init() {
    // Step 1: without init_database the global pool is unset -> ConfigError with a
    // "not initialized" message (the readiness path maps this to a dedicated reason).
    let err = rdb::ping().await.expect_err("ping must fail before init_database");
    assert!(
        matches!(err, DbError::ConfigError(_)),
        "expected DbError::ConfigError, got: {err:?}"
    );
    assert!(err.to_string().contains("not initialized"), "got: {err}");

    // Step 2: after initializing the pool the probe succeeds (single sequential test to
    // avoid racing parallel tests over the process-global OnceCell).
    rdb::init_database(&sqlite_memory_config(5)).await.expect("init database");
    rdb::ping().await.expect("ping must succeed after init");
}

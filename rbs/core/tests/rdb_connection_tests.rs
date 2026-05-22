/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Tests for infra/rdb/connection.rs — SQLite connection creation.

use rbs_core::rdb::connection::{create_sqlite_connection, create_sqlite_file_connection};

#[tokio::test]
async fn test_create_sqlite_connection_in_memory() {
    let result = create_sqlite_connection().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_sqlite_file_connection_nonexistent_directory() {
    let result = create_sqlite_file_connection("/nonexistent/path/to/db.sqlite").await;
    assert!(result.is_err());
}
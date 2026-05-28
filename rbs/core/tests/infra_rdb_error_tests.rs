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

//! Unit tests for `DbError` — all variants and From<sea_orm::DbErr>.

use rbs_core::rdb::DbError;

// ===========================================================================
// Variant construction and Display
// ===========================================================================

#[test]
fn test_invalid_database_type_message() {
    let err = DbError::InvalidDatabaseType("mysql".to_string());
    assert_eq!(err.to_string(), "Invalid database type: mysql");
}

#[test]
fn test_connection_error_message() {
    let err = DbError::ConnectionError("refused".to_string());
    assert_eq!(err.to_string(), "Failed to connect to database: refused");
}

#[test]
fn test_pool_error_message() {
    let err = DbError::PoolError("timeout".to_string());
    assert_eq!(err.to_string(), "Failed to initialize connection pool: timeout");
}

#[test]
fn test_config_error_message() {
    let err = DbError::ConfigError("missing host".to_string());
    assert_eq!(err.to_string(), "Database configuration error: missing host");
}

#[test]
fn test_other_error_message() {
    let err = DbError::Other("query failed".to_string());
    assert_eq!(err.to_string(), "Database error: query failed");
}

// ===========================================================================
// Clone and Debug
// ===========================================================================

#[test]
fn test_clone() {
    let err = DbError::ConnectionError("refused".to_string());
    let cloned = err.clone();
    assert_eq!(cloned.to_string(), err.to_string());
}

#[test]
fn test_debug() {
    let err = DbError::PoolError("timeout".to_string());
    let debug = format!("{:?}", err);
    assert!(debug.contains("PoolError"));
}

// ===========================================================================
// From<sea_orm::DbErr>
// ===========================================================================

#[test]
fn test_from_sea_orm_db_err_custom() {
    let db_err = sea_orm::DbErr::Custom("test custom error".to_string());
    let err: DbError = DbError::from(db_err);
    match err {
        DbError::Other(msg) => {
            assert!(msg.contains("test custom error"));
        }
        other => panic!("Expected DbError::Other, got {:?}", other),
    }
}
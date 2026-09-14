/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Database error handling module
//! Define custom error types for database operations

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum DbError {
    #[error("Invalid database type: {0}")]
    InvalidDatabaseType(String),

    #[error("Failed to connect to database: {0}")]
    ConnectionError(String),

    #[error("Failed to initialize connection pool: {0}")]
    PoolError(String),

    #[error("Database configuration error: {0}")]
    ConfigError(String),

    #[error("Database error: {0}")]
    Other(String),
}

impl From<sea_orm::DbErr> for DbError {
    fn from(err: sea_orm::DbErr) -> Self {
        DbError::Other(err.to_string())
    }
}

/// Detect whether a `sea_orm::DbErr` is a unique-constraint violation
/// (SQLite UNIQUE, sqlx code 2067). INSERT path collisions arrive as
/// `DbErr::Exec`; the `Query` branch is kept for safety.
///
/// Shared by repositories that rely on a UNIQUE constraint as the
/// authoritative duplicate guard (policy name per user, bootstrap admin
/// username) and map the collision to a domain-specific "already exists"
/// error instead of a generic internal failure.
pub fn is_unique_violation(e: &sea_orm::DbErr) -> bool {
    use sea_orm::RuntimeErr;
    let db_err = match e {
        sea_orm::DbErr::Exec(RuntimeErr::SqlxError(sea_orm::sqlx::Error::Database(db)))
        | sea_orm::DbErr::Query(RuntimeErr::SqlxError(sea_orm::sqlx::Error::Database(db))) => db,
        _ => return false,
    };
    db_err.is_unique_violation()
}
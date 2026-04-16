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
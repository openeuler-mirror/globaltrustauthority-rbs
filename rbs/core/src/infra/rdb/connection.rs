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

//! Database Connection Management Module
//! Provides unified database connection pool management functionality

use std::error::Error;
use sea_orm::{ConnectionTrait, DatabaseConnection, ConnectOptions, Database as Db,TransactionTrait};
use std::sync::Arc;
use tokio::sync::OnceCell;
use log::{info, error};
use rbs_api_types::config::Database;
use super::error::DbError;

static DB_CONN: OnceCell<Arc<DatabaseConnection>> = OnceCell::const_new();

/// Create a database connection
pub async fn create_connection(config: &Database) -> Result<DatabaseConnection, DbError> {
    let mut opt = ConnectOptions::new(config.url.clone());
    opt.max_connections(config.max_connections)
       .connect_timeout(std::time::Duration::from_secs(config.timeout))
       .sqlx_logging(false);

    Db::connect(opt)
        .await
        .map_err(|e| DbError::ConnectionError(e.to_string()))
}

/// Initialize the database connection pool
pub async fn init_database(database: &Database) -> Result<(), DbError> {
    let _conn = init_pool(database).await?;
    Ok(())
}

/// Get the database connection pool from the global pool
pub fn get_connection_from_pool() -> Result<Arc<DatabaseConnection>, DbError> {
    DB_CONN.get().cloned().ok_or_else(|| {
        DbError::ConfigError("Database connection not initialized".to_string())
    })
}

/// Initialize and get the database connection pool
pub async fn init_pool(config: &Database) -> Result<Arc<DatabaseConnection>, DbError> {
    let conn = DB_CONN
        .get_or_try_init(|| async {
            info!("Initializing {} database connection...", config.db_type);

            let conn = create_connection(config).await.map_err(|e| {
                error!("Failed to create {} connection pool: {}", config.db_type, e);
                DbError::ConnectionError(format!("Failed to create {} connection: {}", config.db_type, e))
            })?;

            info!("{} database connection pool created successfully", config.db_type);
            Ok::<Arc<DatabaseConnection>, DbError>(Arc::new(conn))
        })
        .await?;

    Ok(conn.clone())
}

/// Execute SQL file path on the database connection pool
pub async fn execute_sql_file_path(db: &DatabaseConnection, sql_file_path: &str) -> Result<(), Box<dyn Error>> {
    let sql_content = std::fs::read_to_string(sql_file_path)?;
    let db_backend = db.get_database_backend();
    let statements = sql_content
        .split(';')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim());
    let txn = db.begin().await?;
    for stmt in statements {
        let statement = sea_orm::Statement::from_string(db_backend, stmt.to_owned());
        if let Err(e) = txn.execute(statement).await {
            txn.rollback().await?;
            return Err(e.into());
        }
    }
    txn.commit().await?;
    Ok(())
}
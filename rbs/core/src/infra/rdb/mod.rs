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

//! Database connection management module
//! Provides unified connection pool management for MySQL and PostgreSQL

pub mod connection;
pub mod error;

pub use connection::create_connection;
pub use connection::get_connection_from_pool;
pub use connection::init_database;
pub use connection::init_pool;
pub use connection::execute_sql_file_path;
pub use error::DbError;
pub use rbs_api_types::config::Database;

#[deprecated(since = "0.1.0", note = "please use `get_connection_from_pool` instead")]
pub use connection::get_connection_from_pool as get_db_connection;

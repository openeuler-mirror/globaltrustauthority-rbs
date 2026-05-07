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

//! Sea-orm Entity definition for the `users` table.

use sea_orm::entity::prelude::*;

/// Users table entity.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "t_user_info")]
pub struct Model {
    /// Internal UUID (not exposed via API).
    pub user_id: String,
    /// Login name — external unique identifier, primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub username: String,
    /// User role.
    pub role: String,
    /// Authentication type (always "jwt").
    pub auth_type: String,
    /// Public key in PEM format (JWK input converted to PEM before storage).
    pub auth_value: String,
    /// Signature algorithm derived from the public key.
    pub auth_alg: String,
    /// 0 = disabled, 1 = enabled.
    pub status: i32,
    /// Creation timestamp.
    pub created_at: String,
    /// Last modification timestamp.
    pub updated_at: String,
}

/// Relationships (none for users table).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

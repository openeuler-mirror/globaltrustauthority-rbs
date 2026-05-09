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

//! Sea-orm Entity definition for the `t_user_info` table.

use rbs_api_types::{AuthType, Role};
use sea_orm::entity::prelude::*;

/// User role — persisted as a string in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum DbRole {
    #[sea_orm(string_value = "admin")]
    Admin,
    #[sea_orm(string_value = "user")]
    User,
}

/// User status — persisted as an integer in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum UserStatus {
    #[sea_orm(num_value = 0)]
    Disabled = 0,
    #[sea_orm(num_value = 1)]
    Enabled = 1,
}

/// Authentication type — persisted as a string in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum DbAuthType {
    #[sea_orm(string_value = "jwt")]
    Jwt,
}

impl From<Role> for DbRole {
    fn from(r: Role) -> Self {
        match r {
            Role::Admin => DbRole::Admin,
            Role::User => DbRole::User,
        }
    }
}

impl From<DbRole> for Role {
    fn from(r: DbRole) -> Self {
        match r {
            DbRole::Admin => Role::Admin,
            DbRole::User => Role::User,
        }
    }
}

impl From<AuthType> for DbAuthType {
    fn from(a: AuthType) -> Self {
        match a {
            AuthType::Jwt => DbAuthType::Jwt,
        }
    }
}

impl From<DbAuthType> for AuthType {
    fn from(_: DbAuthType) -> Self {
        AuthType::Jwt
    }
}

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
    pub role: DbRole,
    /// Authentication type.
    pub auth_type: DbAuthType,
    /// Public key in PEM format (JWK input converted to PEM before storage).
    pub auth_value: String,
    /// Signature algorithm derived from the public key.
    pub auth_alg: String,
    /// Account status.
    pub status: UserStatus,
    /// Creation timestamp (UTC).
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last modification timestamp (UTC).
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Relationships (none for users table).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

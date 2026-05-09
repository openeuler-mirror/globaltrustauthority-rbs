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

//! Authorization module.

mod builder;
mod error;
mod facade;

pub use error::AuthzError;
pub use facade::AuthzFacade;

/// CRUD operation types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Create,
    Get,
    Update,
    Delete,
    List,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Create => "Create",
            Action::Get => "Get",
            Action::Update => "Update",
            Action::Delete => "Delete",
            Action::List => "List",
        }
    }
}

/// Role requirement level
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiredRole {
    /// Regular user can execute (requires owner match)
    UserScoped,
    /// Admin only
    AdminOnly,
}

impl RequiredRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            RequiredRole::UserScoped => "UserScoped",
            RequiredRole::AdminOnly => "AdminOnly",
        }
    }
}

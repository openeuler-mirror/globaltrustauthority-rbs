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

pub use error::{AuthzDecision, AuthzError};
pub use facade::AuthzFacade;

/// Management operation types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAction {
    Create,
    Get,
    Update,
    Delete,
    List,
}

impl AdminAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AdminAction::Create => "Create",
            AdminAction::Get => "Get",
            AdminAction::Update => "Update",
            AdminAction::Delete => "Delete",
            AdminAction::List => "List",
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

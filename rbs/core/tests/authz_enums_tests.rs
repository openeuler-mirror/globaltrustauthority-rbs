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

//! Tests for auth/authz/mod.rs — Action and RequiredRole enum variants.

use rbs_core::auth::authz::{Action, RequiredRole};

#[test]
fn test_action_as_str_create() {
    assert_eq!(Action::Create.as_str(), "Create");
}

#[test]
fn test_action_as_str_get() {
    assert_eq!(Action::Get.as_str(), "Get");
}

#[test]
fn test_action_as_str_update() {
    assert_eq!(Action::Update.as_str(), "Update");
}

#[test]
fn test_action_as_str_delete() {
    assert_eq!(Action::Delete.as_str(), "Delete");
}

#[test]
fn test_action_as_str_list() {
    assert_eq!(Action::List.as_str(), "List");
}

#[test]
fn test_required_role_as_str_user_scoped() {
    assert_eq!(RequiredRole::UserScoped.as_str(), "UserScoped");
}

#[test]
fn test_required_role_as_str_admin_only() {
    assert_eq!(RequiredRole::AdminOnly.as_str(), "AdminOnly");
}

#[test]
fn test_action_debug() {
    let action = Action::Create;
    let debug_str = format!("{:?}", action);
    assert_eq!(debug_str, "Create");
}

#[test]
fn test_action_eq() {
    assert_eq!(Action::Create, Action::Create);
    assert_ne!(Action::Create, Action::Delete);
}

#[test]
fn test_required_role_debug() {
    let role = RequiredRole::AdminOnly;
    let debug_str = format!("{:?}", role);
    assert_eq!(debug_str, "AdminOnly");
}

#[test]
fn test_required_role_eq() {
    assert_eq!(RequiredRole::UserScoped, RequiredRole::UserScoped);
    assert_ne!(RequiredRole::UserScoped, RequiredRole::AdminOnly);
}

#[test]
fn test_action_clone() {
    let action = Action::Get;
    let cloned = action.clone();
    assert_eq!(cloned, action);
}

#[test]
fn test_required_role_clone() {
    let role = RequiredRole::UserScoped;
    let cloned = role.clone();
    assert_eq!(cloned, role);
}
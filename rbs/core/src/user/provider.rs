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

//! User Provider trait definition.

use async_trait::async_trait;
use rbs_api_types::error::RbsError;
use rbs_api_types::{UserCreateRequest, UserListResponse, UserResponse, UserUpdateRequest};

/// Result type alias using RbsError.
type Result<T> = std::result::Result<T, RbsError>;

/// User provider trait.
///
/// Implementors handle user CRUD operations.
#[async_trait]
pub trait UserProvider: Send + Sync {
    /// Create a new user.
    async fn create(&self, req: &UserCreateRequest) -> Result<UserResponse>;

    /// Get user by id.
    async fn get(&self, user_id: &str) -> Result<Option<UserResponse>>;

    /// Update user by id.
    async fn update(&self, user_id: &str, req: &UserUpdateRequest) -> Result<Option<UserResponse>>;

    /// Delete user by id.
    async fn delete(&self, user_id: &str) -> Result<()>;

    /// List users with pagination.
    async fn list(&self, limit: i64, offset: i64) -> Result<UserListResponse>;
}

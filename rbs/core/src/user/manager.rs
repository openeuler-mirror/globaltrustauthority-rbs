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

//! User Manager implementation.

use std::sync::Arc;

use rbs_api_types::error::RbsError;
use rbs_api_types::{UserCreateRequest, UserListResponse, UserResponse, UserUpdateRequest};

use super::provider::UserProvider;

/// Result type alias using RbsError.
type Result<T> = std::result::Result<T, RbsError>;

/// User manager.
///
/// Routes user requests to the configured provider.
pub struct UserManager {
    backend: Option<Arc<dyn UserProvider>>,
}

impl std::fmt::Debug for UserManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserManager").finish()
    }
}

impl UserManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self { backend: None }
    }

    /// Create a new manager with the given provider.
    pub fn with_provider(backend: Arc<dyn UserProvider>) -> Self {
        Self { backend: Some(backend) }
    }

    /// Set the provider.
    pub fn set_provider(&mut self, backend: Arc<dyn UserProvider>) {
        self.backend = Some(backend);
    }

    /// Create a new user.
    pub async fn create(&self, req: &UserCreateRequest) -> Result<UserResponse> {
        match &self.backend {
            Some(backend) => backend.create(req).await,
            None => Err(RbsError::ProviderNotFound("user provider not configured".into())),
        }
    }

    /// Get user by id.
    pub async fn get(&self, user_id: &str) -> Result<Option<UserResponse>> {
        match &self.backend {
            Some(backend) => backend.get(user_id).await,
            None => Err(RbsError::ProviderNotFound("user provider not configured".into())),
        }
    }

    /// Update user by id.
    pub async fn update(&self, user_id: &str, req: &UserUpdateRequest) -> Result<Option<UserResponse>> {
        match &self.backend {
            Some(backend) => backend.update(user_id, req).await,
            None => Err(RbsError::ProviderNotFound("user provider not configured".into())),
        }
    }

    /// Delete user by id.
    pub async fn delete(&self, user_id: &str) -> Result<()> {
        match &self.backend {
            Some(backend) => backend.delete(user_id).await,
            None => Err(RbsError::ProviderNotFound("user provider not configured".into())),
        }
    }

    /// List users with pagination.
    pub async fn list(&self, limit: i64, offset: i64) -> Result<UserListResponse> {
        match &self.backend {
            Some(backend) => backend.list(limit, offset).await,
            None => Err(RbsError::ProviderNotFound("user provider not configured".into())),
        }
    }
}

impl Default for UserManager {
    fn default() -> Self {
        Self::new()
    }
}

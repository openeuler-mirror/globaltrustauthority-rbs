/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Authorization module.

use crate::auth::AuthContext;
use async_trait::async_trait;

/// Authorization errors
#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("forbidden: {reason}")]
    Forbidden { reason: String },

    #[error("resource not found: {uri}")]
    ResourceNotFound { uri: String },

    #[error("policy evaluation failed: {reason}")]
    PolicyEvaluationFailed { reason: String },

    #[error("invalid context: {reason}")]
    InvalidContext { reason: String },
}

/// Authorization decision
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny { reason: String },
}

/// Resource URI components
#[derive(Debug, Clone)]
pub struct ResourceUri {
    pub res_provider: String,
    pub repository_name: String,
    pub resource_type: String,
    pub resource_name: String,
}

/// Administration operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminOperation {
    CreateUser,
    DeleteUser,
    UpdateUser,
    GetUser,
    ListUsers,
}

/// Policy operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyOperation {
    CreatePolicy,
    DeletePolicy,
    UpdatePolicy,
    GetPolicy,
    ListPolicies,
}

/// Authorization trait
#[async_trait]
pub trait Authz: Send + Sync {
    /// Authorize resource GET operation
    async fn authorize_resource_get(
        &self,
        ctx: &AuthContext,
        resource_uri: &ResourceUri,
    ) -> Result<AuthzDecision, AuthzError>;

    /// Authorize administration operation
    async fn authorize_admin(
        &self,
        ctx: &AuthContext,
        operation: AdminOperation,
        target: &str,
    ) -> Result<AuthzDecision, AuthzError>;

    /// Authorize policy operation
    async fn authorize_policy(
        &self,
        ctx: &AuthContext,
        operation: PolicyOperation,
        target: &str,
    ) -> Result<AuthzDecision, AuthzError>;
}

/// Authorization facade implementation
#[derive(Debug, Clone)]
pub struct AuthzFacade {
    // TODO: Add policy engine and other dependencies
}

impl AuthzFacade {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Authz for AuthzFacade {
    async fn authorize_resource_get(
        &self,
        _ctx: &AuthContext,
        _resource_uri: &ResourceUri,
    ) -> Result<AuthzDecision, AuthzError> {
        // TODO: Implement resource authorization
        // Depends on: policy_engine, resource_policy resolution
        todo!("authorize_resource_get: policy acquisition mechanism not yet defined")
    }

    async fn authorize_admin(
        &self,
        _ctx: &AuthContext,
        _operation: AdminOperation,
        _target: &str,
    ) -> Result<AuthzDecision, AuthzError> {
        // TODO: Implement admin authorization
        // Depends on: policy_engine, admin_policy resolution
        todo!("authorize_admin: admin policy resolution not yet defined")
    }

    async fn authorize_policy(
        &self,
        _ctx: &AuthContext,
        _operation: PolicyOperation,
        _target: &str,
    ) -> Result<AuthzDecision, AuthzError> {
        // TODO: Implement policy management authorization
        todo!("authorize_policy: policy management authorization not yet defined")
    }
}

impl Default for AuthzFacade {
    fn default() -> Self {
        Self::new()
    }
}

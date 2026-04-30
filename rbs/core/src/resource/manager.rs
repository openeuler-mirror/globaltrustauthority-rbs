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

//! Resource Manager implementation.

use std::collections::HashMap;
use std::sync::Arc;

use rbs_api_types::error::RbsError;
use rbs_api_types::{
    ResourceContentResponse, ResourceInfoResponse, ResourceMetadataResponse, ResourceUpsertRequest,
};

use crate::auth::AuthContext;
use super::provider::ResourceProvider;

/// Result type alias using RbsError.
type Result<T> = std::result::Result<T, RbsError>;

/// Resource manager.
///
/// Routes resource requests to the appropriate provider based on `res_provider` in URI.
pub struct ResourceManager {
    backends: HashMap<String, Arc<dyn ResourceProvider>>,
}

impl std::fmt::Debug for ResourceManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceManager")
            .field("backends", &self.backends.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ResourceManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
        }
    }

    /// Register a provider with the given res_provider name.
    pub fn register(&mut self, res_provider: &str, provider: Arc<dyn ResourceProvider>) {
        self.backends.insert(res_provider.to_string(), provider);
    }

    /// Parse res_provider from URI.
    /// URI format: {res_provider}/{repository_name}/{resource_type}/{resource_name}
    fn parse_res_provider(uri: &str) -> Option<&str> {
        let first = uri.split('/').next()?;
        if first.is_empty() {
            None
        } else {
            Some(first)
        }
    }

    /// Get resource content.
    pub async fn get(&self, uri: &str, auth_ctx: Option<AuthContext>) -> Result<Option<ResourceContentResponse>> {
        let res_provider = Self::parse_res_provider(uri)
            .ok_or_else(|| RbsError::InvalidParameter("uri".into()))?;
        let provider = self
            .backends
            .get(res_provider)
            .ok_or_else(|| RbsError::ProviderNotFound(format!("resource provider '{}' not found", res_provider)))?;
        provider.get(uri, auth_ctx).await
    }

    /// Create or update resource.
    pub async fn upsert(&self, uri: &str, req: &ResourceUpsertRequest, auth_ctx: Option<AuthContext>) -> Result<ResourceMetadataResponse> {
        let res_provider = Self::parse_res_provider(uri)
            .ok_or_else(|| RbsError::InvalidParameter("uri".into()))?;
        let provider = self
            .backends
            .get(res_provider)
            .ok_or_else(|| RbsError::ProviderNotFound(format!("resource provider '{}' not found", res_provider)))?;
        provider.upsert(uri, req, auth_ctx).await
    }

    /// Delete resource.
    pub async fn delete(&self, uri: &str, auth_ctx: Option<AuthContext>) -> Result<()> {
        let res_provider = Self::parse_res_provider(uri)
            .ok_or_else(|| RbsError::InvalidParameter("uri".into()))?;
        let provider = self
            .backends
            .get(res_provider)
            .ok_or_else(|| RbsError::ProviderNotFound(format!("resource provider '{}' not found", res_provider)))?;
        provider.delete(uri, auth_ctx).await
    }

    /// Get resource metadata.
    pub async fn info(&self, uri: &str, auth_ctx: Option<AuthContext>) -> Result<Option<ResourceInfoResponse>> {
        let res_provider = Self::parse_res_provider(uri)
            .ok_or_else(|| RbsError::InvalidParameter("uri".into()))?;
        let provider = self
            .backends
            .get(res_provider)
            .ok_or_else(|| RbsError::ProviderNotFound(format!("resource provider '{}' not found", res_provider)))?;
        provider.info(uri, auth_ctx).await
    }

    /// List resources.
    pub async fn list(
        &self,
        res_provider: &str,
        repository_name: Option<&str>,
        resource_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<ResourceMetadataResponse> {
        let provider = self
            .backends
            .get(res_provider)
            .ok_or_else(|| RbsError::ProviderNotFound(format!("resource provider '{}' not found", res_provider)))?;
        provider.list(res_provider, repository_name, resource_type, limit, offset).await
    }
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self::new()
    }
}

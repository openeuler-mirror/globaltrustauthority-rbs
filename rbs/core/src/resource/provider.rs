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

//! Resource Provider trait definition.

use async_trait::async_trait;
use rbs_api_types::error::RbsError;
use rbs_api_types::{
    ResourceContentResponse, ResourceInfoResponse, ResourceMetadataResponse, ResourceUpsertRequest,
};

/// Result type alias using RbsError.
type Result<T> = std::result::Result<T, RbsError>;

/// Resource provider trait.
///
/// Implementors handle resource CRUD operations.
#[async_trait]
pub trait ResourceProvider: Send + Sync {
    /// Get resource content.
    async fn get(&self, uri: &str) -> Result<Option<ResourceContentResponse>>;

    /// Create or update resource.
    async fn upsert(&self, uri: &str, req: &ResourceUpsertRequest) -> Result<ResourceMetadataResponse>;

    /// Delete resource.
    async fn delete(&self, uri: &str) -> Result<()>;

    /// Get resource metadata (no content).
    async fn info(&self, uri: &str) -> Result<Option<ResourceInfoResponse>>;

    /// List resources (optional, default returns 501).
    async fn list(
        &self,
        res_provider: &str,
        repository_name: Option<&str>,
        resource_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<ResourceMetadataResponse> {
        let _ = (res_provider, repository_name, resource_type, limit, offset);
        Err(RbsError::NotImplemented)
    }
}

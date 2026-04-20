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

//! Attestation Provider trait definition.

use async_trait::async_trait;
use rbs_api_types::error::RbsError;
use rbs_api_types::{AttestRequest, AttestResponse, AuthChallengeResponse};

/// Result type alias using RbsError.
type Result<T> = std::result::Result<T, RbsError>;

/// Attestation provider trait.
///
/// Implementors handle nonce generation and attestation validation.
/// RBS does NOT implement verify_token; token verification is done internally.
#[async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Get authentication challenge (nonce).
    async fn get_auth_challenge(&self, as_provider: Option<&str>) -> Result<AuthChallengeResponse>;

    /// Submit attestation evidence and obtain AttestToken.
    async fn attest(&self, req: AttestRequest, user_id: &str) -> Result<AttestResponse>;
}

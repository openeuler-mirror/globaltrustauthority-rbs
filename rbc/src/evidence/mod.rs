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

//! Evidence Provider trait and implementations.

mod native_evidence;

pub use native_evidence::NativeEvidenceProvider;

use crate::error::RbcError;
use rbs_api_types::api::{AttesterData, AuthChallengeResponse};
use serde_json::Value;

/// Evidence collection trait.
///
/// Uses `AuthChallengeResponse` from `rbs_api_types` directly (avoids duplicating the nonce wrapper).
/// Uses `AttesterData` from `rbs_api_types`; the ephemeral RSA public key is carried inside
/// `runtime_data["tee_pubkey"]` as a JWK string (per OpenAPI `AttesterData` description).
pub trait EvidenceProvider: Send + Sync {
    fn collect_evidence(
        &self,
        challenge: &AuthChallengeResponse,
        attester_data: Option<&AttesterData>,
    ) -> Result<Value, RbcError>;
}

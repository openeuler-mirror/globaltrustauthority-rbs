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

//! Token Provider trait and implementations.

mod native_token;
mod rbs_token;

pub use native_token::NativeTokenProvider;
pub use rbs_token::RbsAttestTokenProvider;

use crate::error::RbcError;
use async_trait::async_trait;
use rbs_api_types::AttesterData;
use serde_json::Value;

/// Token acquisition trait.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn get_token(
        &self,
        evidence: Option<&Value>,
        attester_data: Option<&AttesterData>,
    ) -> Result<String, RbcError>;
}

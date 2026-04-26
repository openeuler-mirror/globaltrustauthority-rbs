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

//! Authentication errors.

use thiserror::Error;

/// Authentication error types
#[derive(Debug, Clone, Error)]
pub enum AuthError {
    #[error("token is missing")]
    TokenMissing,

    #[error("token is invalid: {reason}")]
    TokenInvalid { reason: String },

    #[error("token has expired")]
    TokenExpired,

    #[error("token issuer is unknown")]
    TokenUnknown,

    #[error("user is disabled")]
    UserDisabled,

    #[error("provider not found: {provider}")]
    ProviderNotFound { provider: String },
}

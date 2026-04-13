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

//! RBC error types (aligned with `docs/api/rbs_rbc_interface.md` §2.4).

use thiserror::Error;

/// Unified error type for the RBC library.
#[derive(Debug, Error)]
pub enum RbcError {
    /// Configuration file load failure (path not found, format error, etc.).
    #[error("config error: {0}")]
    ConfigError(String),

    /// TLS certificate load or handshake failure.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// Provider instantiation failure.
    #[error("provider error: {0}")]
    ProviderError(String),

    /// RSA key-pair generation failure.
    #[error("key generation error: {0}")]
    KeyGenError(String),

    /// Invalid input argument.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Evidence collection failure.
    #[error("evidence error: {0}")]
    EvidenceError(String),

    /// Network / connection / transport failure communicating with RBS.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Attestation flow failure (RBS attest returned an error).
    #[error("attest error: {0}")]
    AttestError(String),

    /// RBS server internal error (5xx).
    #[error("server error: {0}")]
    ServerError(String),

    /// Request timeout.
    #[error("timeout: {0}")]
    TimeoutError(String),

    /// Token invalid or expired (401/403).
    #[error("auth error: {0}")]
    AuthError(String),

    /// Resource not found (404).
    #[error("resource not found: {0}")]
    ResourceNotFound(String),

    /// Request rejected by policy (403 + policy denial).
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    /// JWE / content encryption failure.
    #[error("encrypt error: {0}")]
    EncryptError(String),

    /// JWE / content decryption failure.
    #[error("decrypt error: {0}")]
    DecryptError(String),

    /// JSON serialization / deserialization error.
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// HTTP transport error.
    #[error("http transport: {0}")]
    HttpTransport(#[from] reqwest::Error),
}

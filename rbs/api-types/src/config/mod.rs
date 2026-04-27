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

//! YAML run configuration types (`RbsConfig` and nested structs; default file `rbs.yaml`).
//!
//! The `rbs` binary loads them via `rbs::load_config`, which requires a non-null `rest` section.
//! `logging` initializes `rbs_core`; `rest` configures `rbs_rest` when the binary is built with the
//! `rest` feature.

mod validation;

use std::collections::HashMap;
use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Serialize};

/// Wrapper for sensitive config values (e.g. keys, tokens). Serializes/deserializes as normal
/// but `Debug` and `Display` show a redacted placeholder so logs never expose the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Sensitive<T>(T);

impl<T: Serialize> Serialize for Sensitive<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Sensitive<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Sensitive)
    }
}

impl<T: fmt::Debug> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl<T> Sensitive<T> {
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn get(&self) -> &T {
        &self.0
    }
}

impl<T: Default> Default for Sensitive<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

fn default_rest_option() -> Option<RestConfig> {
    None
}

fn default_db_type() -> String {
    "mysql".to_string()
}

fn default_max_connections() -> u32 {
    20
}

fn default_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Database {
    #[serde(default = "default_db_type")]
    pub db_type: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    pub url: String,
    pub sql_file_path: String,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            db_type: default_db_type(),
            max_connections: default_max_connections(),
            timeout: default_timeout(),
            url: String::new(),
            sql_file_path: String::new(),
        }
    }
}

/// Top-level run configuration (`rbs.yaml`). Only **`rest`**, **`logging`**, **`storage`**, **`attestation`**, and **`auth`** are deserialized;
/// any other top-level key is rejected (`deny_unknown_fields`).
///
/// In YAML, `rest` may be omitted or null (deserializes as `None`). The `rbs` binary's `load_config`
/// requires `rest` to be present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RbsConfig {
    #[serde(default = "default_rest_option")]
    pub rest: Option<RestConfig>,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub storage: Option<Database>,
    #[serde(default)]
    pub attestation: AttestationConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

/// For programmatic use; YAML omitting `rest` deserializes to `None` via `default_rest_option`.
impl Default for RbsConfig {
    fn default() -> Self {
        Self {
            rest: Some(RestConfig::default()),
            logging: LoggingConfig::default(),
            storage: None,
            attestation: AttestationConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "text".to_string(),
            file_path: None,
            enable_rotation: false,
            rotation: LogRotationConfig::default(),
            file_mode: 0o640,
        }
    }
}

/// Config slice for core (logging and future core-only options).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
    pub logging: LoggingConfig,
    #[serde(default)]
    pub attestation: AttestationConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            logging: LoggingConfig::default(),
            attestation: AttestationConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

/// Attestation provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestationConfig {
    /// Default attestation provider name.
    #[serde(default = "default_attestation_provider")]
    pub default_as_provider: String,
    /// Backend providers indexed by name.
    #[serde(default)]
    pub backends: HashMap<String, AttestationBackendConfig>,
}

fn default_attestation_provider() -> String {
    "gta".to_string()
}

/// Mode of attestation backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationBackendMode {
    Rest,
    Builtin,
}

impl Default for AttestationBackendMode {
    fn default() -> Self {
        Self::Rest
    }
}

/// Configuration for a single attestation backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestationBackendConfig {
    /// Backend mode (rest or builtin).
    #[serde(default)]
    pub mode: AttestationBackendMode,
    /// REST backend configuration.
    pub rest: AttestationRestConfig,
    /// Builtin backend configuration (placeholder for future use).
    pub builtin: AttestationBuiltinConfig,
}

impl Default for AttestationBackendConfig {
    fn default() -> Self {
        Self {
            mode: AttestationBackendMode::Rest,
            rest: AttestationRestConfig::default(),
            builtin: AttestationBuiltinConfig::default(),
        }
    }
}

/// REST backend configuration for attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestationRestConfig {
    pub base_url: String,
    #[serde(default)]
    pub timeout_secs: u32,
    #[serde(default)]
    pub retries: u32,
    #[serde(default)]
    pub tls_verify: bool,
    /// Custom CA certificate file for TLS verification.
    /// If empty, uses system default CA bundle.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ca_file: String,
    /// REST backend credentials (user_id, api_key).
    #[serde(default)]
    pub credentials: AttestationCredentials,
}

impl Default for AttestationRestConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            timeout_secs: 30,
            retries: 3,
            tls_verify: true,
            ca_file: String::new(),
            credentials: AttestationCredentials::default(),
        }
    }
}

/// Builtin backend configuration (placeholder).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestationBuiltinConfig {}

/// GTA REST API credentials for attestation requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestationCredentials {
    /// User identifier for attestation requests.
    pub user_id: String,
    /// Main API key for primary authentication.
    pub main_api_key: Sensitive<String>,
    /// Sub API key for secondary authentication (used in attest requests).
    pub sub_api_key: Sensitive<String>,
}

impl Default for AttestationCredentials {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            main_api_key: Sensitive::new(String::new()),
            sub_api_key: Sensitive::new(String::new()),
        }
    }
}

/// Per-IP rate limit configuration. Effective only when the `per-ip-rate-limit` feature is enabled in rbs-rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PerIpRateLimitConfig {
    pub enabled: bool,
    /// Max requests per second per client IP (token bucket refill rate).
    pub requests_per_sec: u32,
    /// Burst size (bucket capacity). Defaults to `requests_per_sec` when unset or zero.
    pub burst: Option<u32>,
}

impl Default for PerIpRateLimitConfig {
    fn default() -> Self {
        Self { enabled: false, requests_per_sec: 60, burst: None }
    }
}

/// Trusted proxy addresses. When the direct peer is in this set, client IP for rate limiting and
/// audit is taken from Forwarded / X-Forwarded-For (realip); otherwise peer address is used.
/// Empty = do not trust any proxy (prevents X-Forwarded-For spoofing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TrustedProxyConfig {
    /// List of proxy peer IPs (e.g. "127.0.0.1", "`::1`", "10.0.0.1"). Peer must match for forwarded headers to be used.
    pub addrs: Vec<String>,
}

/// REST server configuration: listen address, worker count, body limit, timeouts, and optional HTTPS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RestConfig {
    pub listen_addr: String,
    pub workers: u32,
    pub body_limit_bytes: u64,
    pub listen_backlog: u32,
    pub request_timeout_secs: u32,
    pub shutdown_timeout_secs: u32,
    pub https: RestHttpsConfig,
    pub rate_limit: PerIpRateLimitConfig,
    /// Trusted reverse proxies for client IP resolution. See [`TrustedProxyConfig`].
    pub trusted_proxy: TrustedProxyConfig,
}

impl Default for RestConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:6666".to_string(),
            workers: 4,
            body_limit_bytes: 10 * 1024 * 1024,
            listen_backlog: 128,
            request_timeout_secs: 60,
            shutdown_timeout_secs: 30,
            https: RestHttpsConfig::default(),
            rate_limit: PerIpRateLimitConfig::default(),
            trusted_proxy: TrustedProxyConfig::default(),
        }
    }
}

/// HTTPS configuration for the REST server. Certificate and key files are PEM format by default.
/// Key file path is treated as sensitive and will not appear in Debug/logs.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RestHttpsConfig {
    pub enabled: bool,
    pub cert_file: String,
    #[serde(deserialize_with = "deserialize_sensitive_key_file")]
    pub key_file: Sensitive<String>,
}

fn deserialize_sensitive_key_file<'de, D>(d: D) -> Result<Sensitive<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    Ok(Sensitive::new(s))
}

impl fmt::Debug for RestHttpsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestHttpsConfig")
            .field("enabled", &self.enabled)
            .field("cert_file", &self.cert_file)
            .field("key_file", &"[redacted]")
            .finish()
    }
}

/// Compression for rotated log files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationCompression {
    #[default]
    None,
    Gzip,
}

/// Rotation policy for log files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogRotationConfig {
    pub max_file_size_bytes: u64,
    pub max_files: u32,
    pub compression: RotationCompression,
    #[serde(default = "default_rotation_file_mode", deserialize_with = "deserialize_octal_mode")]
    pub file_mode: u32,
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 10 * 1024 * 1024,
            max_files: 6,
            compression: RotationCompression::None,
            file_mode: 0o440,
        }
    }
}

/// Logging configuration: level, format, file path, rotation, permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub file_path: Option<String>,
    pub enable_rotation: bool,
    pub rotation: LogRotationConfig,
    #[serde(default = "default_file_mode", deserialize_with = "deserialize_octal_mode")]
    pub file_mode: u32,
}

fn default_file_mode() -> u32 {
    0o640
}
fn default_rotation_file_mode() -> u32 {
    0o440
}

fn deserialize_octal_mode<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OctalModeVisitor;
    impl<'de> Visitor<'de> for OctalModeVisitor {
        type Value = u32;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("octal mode as number (e.g. 640, 750) or string")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u32, E> {
            validation::parse_octal_str(&v.to_string()).map_err(E::custom)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u32, E> {
            validation::parse_octal_str(v).map_err(E::custom)
        }
    }
    deserializer.deserialize_any(OctalModeVisitor)
}

/// Bearer JWT verification configuration
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JwtVerificationConfig {
    /// Path to local JWKS file (mutually exclusive with public_key_path)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_file: Option<String>,
    /// Path to PEM-encoded public key file (mutually exclusive with jwks_file)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_path: Option<String>,
    /// Expected issuer (token.iss claim, required)
    pub issuer: String,
}

/// AttestToken verification configuration
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestTokenVerificationConfig {
    /// Path to local JWKS file (mutually exclusive with public_key_path)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_file: Option<String>,
    /// Path to PEM-encoded public key file (mutually exclusive with jwks_file)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_path: Option<String>,
    /// Expected issuer (token.iss claim, required)
    pub issuer: String,
    /// Expected audience (token.aud claim, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

/// Authentication configuration (top-level)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Bearer JWT verification configuration
    #[serde(default)]
    pub bearer_token: JwtVerificationConfig,
    /// AttestToken verification configuration
    #[serde(default)]
    pub attest_token: AttestTokenVerificationConfig,
}

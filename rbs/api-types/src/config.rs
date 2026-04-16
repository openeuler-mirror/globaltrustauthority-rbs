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

/// Top-level run configuration (`rbs.yaml`). Only **`rest`**, **`logging`**, and **`database`** are deserialized;
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
}

/// For programmatic use; YAML omitting `rest` deserializes to `None` via `default_rest_option`.
impl Default for RbsConfig {
    fn default() -> Self {
        Self { rest: Some(RestConfig::default()), logging: LoggingConfig::default(), storage: None }
    }
}

/// Config slice for core (logging and future core-only options).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
    pub logging: LoggingConfig,
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
            parse_octal_str(&v.to_string()).map_err(E::custom)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u32, E> {
            parse_octal_str(v).map_err(E::custom)
        }
    }
    deserializer.deserialize_any(OctalModeVisitor)
}

const MAX_FILE_MODE: u32 = 0o7777;

fn parse_octal_str(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty mode".to_string());
    }
    let mut mode: u32 = 0;
    for c in s.chars() {
        let d = c.to_digit(8).ok_or_else(|| format!("invalid octal digit: {}", c))?;
        mode = mode * 8 + d;
    }
    if mode > MAX_FILE_MODE {
        return Err(format!("file mode {} exceeds maximum {}", mode, MAX_FILE_MODE));
    }
    Ok(mode)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let rbs = RbsConfig::default();
        let rest = rbs.rest.as_ref().unwrap();
        assert_eq!(rest.listen_addr, "127.0.0.1:6666");
        assert_eq!(rest.workers, 4);
        assert!(!rest.https.enabled);
        assert_eq!(rbs.logging.level, "info");
        assert_eq!(rbs.logging.file_mode, 0o640);
        assert_eq!(rbs.logging.rotation.file_mode, 0o440);
        assert_eq!(rbs.logging.rotation.compression, RotationCompression::None);

        let rest = RestConfig::default();
        assert_eq!(rest.listen_addr, "127.0.0.1:6666");
        assert!(!rest.https.enabled);

        assert!(!RestHttpsConfig::default().enabled);
        assert_eq!(RotationCompression::default(), RotationCompression::None);

        let rl = PerIpRateLimitConfig::default();
        assert!(!rl.enabled);
        assert_eq!(rl.requests_per_sec, 60);
        assert_eq!(rl.burst, None);

        let s = Sensitive::new("secret".to_string());
        assert_eq!(s.get(), "secret");
        assert_eq!(format!("{:?}", s), "[redacted]");
    }

    #[test]
    fn config_deserialize_yaml_partial() {
        let yaml = r#"
rest:
  listen_addr: "127.0.0.1:9000"
logging:
  level: debug
  file_mode: 600
  rotation:
    file_mode: "440"
"#;
        let config: RbsConfig = serde_yaml::from_str(yaml).unwrap();
        let rest = config.rest.as_ref().unwrap();
        assert_eq!(rest.listen_addr, "127.0.0.1:9000");
        assert_eq!(rest.workers, 4);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.file_mode, 0o600);
        assert_eq!(config.logging.rotation.file_mode, 0o440);
    }

    #[test]
    fn config_deserialize_yaml_octal_string() {
        let yaml = r#"
logging:
  file_mode: "750"
  rotation:
    file_mode: "640"
"#;
        let config: RbsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.logging.file_mode, 0o750);
        assert_eq!(config.logging.rotation.file_mode, 0o640);
    }

    #[test]
    fn config_deserialize_invalid_octal_fails() {
        let yaml = r#"
logging:
  file_mode: "649"
"#;
        let result: Result<RbsConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "invalid octal digit 9 must yield error");
    }

    #[test]
    fn config_deserialize_invalid_octal_digit_fails() {
        let yaml = r#"
logging:
  rotation:
    file_mode: "889"
"#;
        let result: Result<RbsConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "invalid octal digit 8 must yield error");
    }

    #[test]
    fn config_deserialize_octal_exceeds_max_fails() {
        let yaml = r#"
logging:
  file_mode: "10000"
"#;
        let result: Result<RbsConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "file_mode > 0o7777 must yield error");
    }

    #[test]
    fn sensitive_round_trip_and_redaction() {
        let original = Sensitive::new("super-secret".to_string());
        // Use YAML here to avoid pulling in an additional JSON dependency just for tests.
        let yaml = serde_yaml::to_string(&original).unwrap();
        let deserialized: Sensitive<String> = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.get(), original.get());
        assert_eq!(format!("{:?}", deserialized), "[redacted]");
        assert_eq!(deserialized.to_string(), "[redacted]");
    }

    #[test]
    fn rest_https_config_debug_redacts_key_file() {
        let cfg = RestHttpsConfig {
            enabled: true,
            cert_file: "/path/to/cert.pem".to_string(),
            key_file: Sensitive::new("/path/to/key.pem".to_string()),
        };
        let debug = format!("{:?}", cfg);
        assert!(debug.contains("RestHttpsConfig"));
        assert!(debug.contains("cert_file"));
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("key.pem"));
    }

    #[test]
    fn octal_mode_deserialize_numeric_and_string() {
        let yaml = r#"
logging:
  file_mode: 750
  rotation:
    file_mode: " 640 "
"#;
        let config: RbsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.logging.file_mode, 0o750);
        assert_eq!(config.logging.rotation.file_mode, 0o640);
    }

    #[test]
    fn octal_mode_allows_maximum() {
        let yaml = r#"
logging:
  file_mode: "7777"
"#;
        let config: RbsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.logging.file_mode, 0o7777);
    }

    #[test]
    fn core_and_trusted_proxy_defaults() {
        let core = CoreConfig::default();
        assert_eq!(core.logging, LoggingConfig::default());

        let proxies = TrustedProxyConfig::default();
        assert!(proxies.addrs.is_empty());
    }

    #[test]
    fn deserialize_rbs_yaml_sample() {
        let yaml = include_str!("../../conf/rbs.yaml");
        let config: RbsConfig = serde_yaml::from_str(yaml).expect("repo rbs/conf/rbs.yaml must parse");
        let rest = config.rest.as_ref().expect("sample config must include `rest`");
        assert_eq!(rest.listen_addr, "127.0.0.1:6666");
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "text");
    }

    #[test]
    fn deserialize_rejects_unknown_top_level_keys() {
        let yaml = r#"
rest: {}
logging:
  level: info
auth:
  bearer: {}
"#;
        let result: Result<RbsConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "top-level keys other than rest/logging must be rejected");
    }
}

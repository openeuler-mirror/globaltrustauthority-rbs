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

//! Configuration validation for RBS.

use super::{
    AttestationBackendConfig, AttestationBackendMode, AttestationConfig, AttestationCredentials,
    AttestationRestConfig, Database, LogRotationConfig, LoggingConfig, PerIpRateLimitConfig,
    RestConfig, RbsConfig,
};

/// Maximum allowed file mode (octal). Files cannot have permissions beyond 0o7777
/// (owner/read/write/execute + group/read/write/execute + others/read/write/execute).
const MAX_FILE_MODE: u32 = 0o7777;

// =============================================================================
// RestConfig limits
// =============================================================================

/// Minimum number of REST server worker threads. At least 1 is required.
const REST_WORKERS_MIN: u32 = 1;

/// Maximum number of REST server worker threads. A single process should not need more than 256.
const REST_WORKERS_MAX: u32 = 256;

/// Minimum HTTP request body size limit in bytes. Smallest allowed is 1KB.
const REST_BODY_LIMIT_MIN: u64 = 1024;

/// Maximum HTTP request body size limit in bytes. Largest allowed is 100MB to prevent memory exhaustion.
const REST_BODY_LIMIT_MAX: u64 = 104857600; // 100MB

/// Maximum allowed request timeout in seconds. Requests cannot exceed 1 hour.
const REST_REQUEST_TIMEOUT_MAX: u32 = 3600;

/// Minimum allowed graceful shutdown timeout in seconds. Must be at least 1 second.
const REST_SHUTDOWN_TIMEOUT_MIN: u32 = 1;

/// Maximum allowed graceful shutdown timeout in seconds. Must not exceed 5 minutes.
const REST_SHUTDOWN_TIMEOUT_MAX: u32 = 300;

/// Maximum length of a listen address string (e.g., "127.0.0.1:6666"). Prevents excessively long addresses.
const REST_LISTEN_ADDR_MAX_LEN: usize = 128;

/// Maximum value for the listen backlog (connection queue size). Linux caps this at 65535.
const REST_BACKLOG_MAX: u32 = 65535;

// =============================================================================
// PerIpRateLimit limits
// =============================================================================

/// Minimum requests per second per IP address. Must be at least 1.
const RATE_LIMIT_REQ_PER_SEC_MIN: u32 = 1;

/// Maximum requests per second per IP address. Set to 1M to prevent integer overflow in token bucket math.
const RATE_LIMIT_REQ_PER_SEC_MAX: u32 = 1000000;

/// Minimum burst size for token bucket. Burst must be at least 1 request.
const RATE_LIMIT_BURST_MIN: u32 = 1;

/// Maximum burst size for token bucket. Set to 1M to match requests_per_sec upper bound.
const RATE_LIMIT_BURST_MAX: u32 = 1000000;

// =============================================================================
// Logging limits
// =============================================================================

/// Valid log level values: trace, debug, info, warn, error, off.
/// Off disables all logging; trace enables the most verbose output.
const LOG_LEVEL_VALID: [&str; 6] = ["trace", "debug", "info", "warn", "error", "off"];

/// Valid log format values: text (human-readable), json (machine-readable structured logs).
const LOG_FORMAT_VALID: [&str; 2] = ["text", "json"];

/// Maximum length of a log file path string. Paths longer than 4096 chars are rejected.
const LOG_FILE_PATH_MAX_LEN: usize = 4096;

/// Minimum rotated log file size before triggering a rotation. Must be at least 1KB.
const LOG_ROTATION_MAX_FILE_SIZE_MIN: u64 = 1024;

/// Maximum rotated log file size before triggering a rotation. Capped at 100MB to manage disk usage.
const LOG_ROTATION_MAX_FILE_SIZE_MAX: u64 = 104857600; // 100MB

/// Minimum number of rotated log files to retain. Must keep at least 1 file.
const LOG_ROTATION_MAX_FILES_MIN: u32 = 1;

/// Maximum number of rotated log files to retain. Set to 100 to prevent unbounded disk usage.
const LOG_ROTATION_MAX_FILES_MAX: u32 = 100;

// =============================================================================
// File path limits
// =============================================================================

/// Maximum length of any file path string in configuration (cert files, key files, CA bundles, etc.).
const FILE_PATH_MAX_LEN: usize = 4096;

// =============================================================================
// Database limits
// =============================================================================

/// Minimum database connection pool size. At least 1 connection is required.
const DB_MAX_CONNECTIONS_MIN: u32 = 1;

/// Maximum database connection pool size. Set to 10000 to prevent resource exhaustion.
const DB_MAX_CONNECTIONS_MAX: u32 = 10000;

/// Maximum database operation timeout in seconds. Queries exceeding 5 minutes are likely stuck.
const DB_TIMEOUT_MAX: u64 = 300;

/// Maximum length of a database connection URL string (e.g., mysql://user:pass@host:port/db).
const DB_URL_MAX_LEN: usize = 2048;

// =============================================================================
// AttestationRestConfig limits
// =============================================================================

/// Maximum length of the attestation backend base URL string.
const ATTEST_BASE_URL_MAX_LEN: usize = 2048;

/// Maximum attestation REST API call timeout in seconds. Set to 1 hour for long-running attestations.
const ATTEST_TIMEOUT_SECS_MAX: u32 = 3600;

/// Maximum number of attestation REST API retry attempts on failure.
const ATTEST_RETRIES_MAX: u32 = 100;

// =============================================================================
// AttestationCredentials limits
// =============================================================================

/// User-Id maximum length (36 chars, matching GTA expectation).
const ATTEST_USER_ID_MAX_LEN: usize = 36;

/// API key total length: prefix (2 chars) + 32 alphanumeric chars = 34.
const ATTEST_API_KEY_LENGTH: usize = 34;

/// Main API key prefix.
const ATTEST_API_KEY_PREFIX_MAIN: &str = "m.";

/// Sub API key prefix.
const ATTEST_API_KEY_PREFIX_SUB: &str = "s.";

pub fn parse_octal_str(s: &str) -> Result<u32, String> {
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

impl LoggingConfig {
    fn validate(&self) {
        // level: must be one of valid values
        if !LOG_LEVEL_VALID.contains(&self.level.as_str()) {
            panic!(
                "logging.level = '{}' is invalid; must be one of {:?}",
                self.level, LOG_LEVEL_VALID
            );
        }

        // format: must be one of valid values
        if !LOG_FORMAT_VALID.contains(&self.format.as_str()) {
            panic!(
                "logging.format = '{}' is invalid; must be one of {:?}",
                self.format, LOG_FORMAT_VALID
            );
        }

        // file_path: length limit
        if let Some(ref path) = self.file_path {
            if path.len() > LOG_FILE_PATH_MAX_LEN {
                panic!(
                    "logging.file_path length {} exceeds maximum {}",
                    path.len(), LOG_FILE_PATH_MAX_LEN
                );
            }
        }

        // file_mode: octal range
        if self.file_mode > MAX_FILE_MODE {
            panic!(
                "logging.file_mode = {:o} exceeds maximum {:o}",
                self.file_mode, MAX_FILE_MODE
            );
        }

        // rotation validation
        self.rotation.validate();
    }
}

impl LogRotationConfig {
    fn validate(&self) {
        if self.max_file_size_bytes < LOG_ROTATION_MAX_FILE_SIZE_MIN
            || self.max_file_size_bytes > LOG_ROTATION_MAX_FILE_SIZE_MAX
        {
            panic!(
                "logging.rotation.max_file_size_bytes = {} is out of range [{}, {}]",
                self.max_file_size_bytes, LOG_ROTATION_MAX_FILE_SIZE_MIN, LOG_ROTATION_MAX_FILE_SIZE_MAX
            );
        }

        if self.max_files < LOG_ROTATION_MAX_FILES_MIN || self.max_files > LOG_ROTATION_MAX_FILES_MAX {
            panic!(
                "logging.rotation.max_files = {} is out of range [{}, {}]",
                self.max_files, LOG_ROTATION_MAX_FILES_MIN, LOG_ROTATION_MAX_FILES_MAX
            );
        }

        if self.file_mode > MAX_FILE_MODE {
            panic!(
                "logging.rotation.file_mode = {:o} exceeds maximum {:o}",
                self.file_mode, MAX_FILE_MODE
            );
        }
    }
}

impl PerIpRateLimitConfig {
    fn validate(&self) {
        if self.enabled {
            if self.requests_per_sec < RATE_LIMIT_REQ_PER_SEC_MIN || self.requests_per_sec > RATE_LIMIT_REQ_PER_SEC_MAX {
                panic!(
                    "rest.rate_limit.requests_per_sec = {} is out of range [{}, {}]",
                    self.requests_per_sec, RATE_LIMIT_REQ_PER_SEC_MIN, RATE_LIMIT_REQ_PER_SEC_MAX
                );
            }
            if let Some(burst) = self.burst {
                if burst < RATE_LIMIT_BURST_MIN || burst > RATE_LIMIT_BURST_MAX {
                    panic!(
                        "rest.rate_limit.burst = {} is out of range [{}, {}]",
                        burst, RATE_LIMIT_BURST_MIN, RATE_LIMIT_BURST_MAX
                    );
                }
            }
        }
    }
}

impl RestConfig {
    fn validate(&self) {
        // listen_addr: non-empty, length limit
        if self.listen_addr.is_empty() {
            panic!("rest.listen_addr must not be empty");
        }
        if self.listen_addr.len() > REST_LISTEN_ADDR_MAX_LEN {
            panic!(
                "rest.listen_addr length {} exceeds maximum {}",
                self.listen_addr.len(),
                REST_LISTEN_ADDR_MAX_LEN
            );
        }
        if !self.listen_addr.contains(':') {
            panic!("rest.listen_addr must be in host:port format, got '{}'", self.listen_addr);
        }

        // workers
        if self.workers < REST_WORKERS_MIN || self.workers > REST_WORKERS_MAX {
            panic!(
                "rest.workers = {} is out of range [{}, {}]",
                self.workers, REST_WORKERS_MIN, REST_WORKERS_MAX
            );
        }

        // body_limit_bytes
        if self.body_limit_bytes < REST_BODY_LIMIT_MIN || self.body_limit_bytes > REST_BODY_LIMIT_MAX {
            panic!(
                "rest.body_limit_bytes = {} is out of range [{}, {}]",
                self.body_limit_bytes, REST_BODY_LIMIT_MIN, REST_BODY_LIMIT_MAX
            );
        }

        // request_timeout_secs
        if self.request_timeout_secs > REST_REQUEST_TIMEOUT_MAX {
            panic!(
                "rest.request_timeout_secs = {} exceeds maximum {}",
                self.request_timeout_secs, REST_REQUEST_TIMEOUT_MAX
            );
        }

        // shutdown_timeout_secs
        if self.shutdown_timeout_secs < REST_SHUTDOWN_TIMEOUT_MIN || self.shutdown_timeout_secs > REST_SHUTDOWN_TIMEOUT_MAX {
            panic!(
                "rest.shutdown_timeout_secs = {} is out of range [{}, {}]",
                self.shutdown_timeout_secs, REST_SHUTDOWN_TIMEOUT_MIN, REST_SHUTDOWN_TIMEOUT_MAX
            );
        }

        // listen_backlog
        if self.listen_backlog > REST_BACKLOG_MAX {
            panic!(
                "rest.listen_backlog = {} exceeds maximum {}",
                self.listen_backlog, REST_BACKLOG_MAX
            );
        }

        // https validation
        if self.https.enabled {
            if self.https.cert_file.is_empty() {
                panic!("rest.https.enabled is true but rest.https.cert_file is empty");
            }
            if self.https.key_file.get().is_empty() {
                panic!("rest.https.enabled is true but rest.https.key_file is empty");
            }
            if self.https.cert_file.len() > FILE_PATH_MAX_LEN {
                panic!(
                    "rest.https.cert_file length {} exceeds maximum {}",
                    self.https.cert_file.len(), FILE_PATH_MAX_LEN
                );
            }
            if self.https.key_file.get().len() > FILE_PATH_MAX_LEN {
                panic!(
                    "rest.https.key_file length {} exceeds maximum {}",
                    self.https.key_file.get().len(), FILE_PATH_MAX_LEN
                );
            }
        }

        // rate_limit validation
        self.rate_limit.validate();
    }
}

impl AttestationRestConfig {
    fn validate(&self) {
        // base_url: length limit
        if self.base_url.len() > ATTEST_BASE_URL_MAX_LEN {
            panic!(
                "attestation.backends.*.rest.base_url length {} exceeds maximum {}",
                self.base_url.len(), ATTEST_BASE_URL_MAX_LEN
            );
        }

        // timeout_secs
        if self.timeout_secs > ATTEST_TIMEOUT_SECS_MAX {
            panic!(
                "attestation.backends.*.rest.timeout_secs = {} exceeds maximum {}",
                self.timeout_secs, ATTEST_TIMEOUT_SECS_MAX
            );
        }

        // retries
        if self.retries > ATTEST_RETRIES_MAX {
            panic!(
                "attestation.backends.*.rest.retries = {} exceeds maximum {}",
                self.retries, ATTEST_RETRIES_MAX
            );
        }

        // ca_file: length limit
        if !self.ca_file.is_empty() && self.ca_file.len() > FILE_PATH_MAX_LEN {
            panic!(
                "attestation.backends.*.rest.ca_file length {} exceeds maximum {}",
                self.ca_file.len(), FILE_PATH_MAX_LEN
            );
        }

        // warn if tls_verify is disabled
        if !self.tls_verify {
            eprintln!(
                "WARNING: attestation.backends.*.rest.tls_verify is false; TLS verification is disabled"
            );
        }

        // credentials validation
        self.credentials.validate();
    }
}

impl AttestationConfig {
    fn validate(&self) {
        // backends must not be empty
        if self.backends.is_empty() {
            panic!("attestation.backends must have at least one backend");
        }

        // default_as_provider must exist in backends
        if !self.backends.contains_key(&self.default_as_provider) {
            panic!(
                "attestation.default_as_provider = '{}' is not found in attestation.backends",
                self.default_as_provider
            );
        }

        // validate each backend
        for (name, backend) in &self.backends {
            backend.validate(name);
        }
    }
}

impl AttestationBackendConfig {
    fn validate(&self, name: &str) {
        match self.mode {
            AttestationBackendMode::Rest => {
                if self.rest.base_url.is_empty() {
                    panic!(
                        "attestation.backends['{}'].mode = 'rest' but base_url is not configured",
                        name
                    );
                }
                self.rest.validate();
            }
            AttestationBackendMode::Builtin => {
                // builtin is placeholder, no further validation needed
            }
        }
    }
}

impl AttestationCredentials {
    fn validate(&self) {
        // user_id validation (required)
        if self.user_id.is_empty() {
            panic!("attestation backends rest.credentials.user_id must not be empty");
        }
        if self.user_id.len() > ATTEST_USER_ID_MAX_LEN {
            panic!(
                "attestation backends rest.credentials.user_id length {} exceeds maximum {}",
                self.user_id.len(),
                ATTEST_USER_ID_MAX_LEN
            );
        }
        if !self.user_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            panic!(
                "attestation backends rest.credentials.user_id contains invalid characters (only alphanumeric, '-', '_' allowed)"
            );
        }

        // main_api_key validation (optional)
        Self::validate_api_key_if_present("main_api_key", &self.main_api_key, ATTEST_API_KEY_PREFIX_MAIN);
        // sub_api_key validation (optional)
        Self::validate_api_key_if_present("sub_api_key", &self.sub_api_key, ATTEST_API_KEY_PREFIX_SUB);
    }

    fn validate_api_key_if_present(field: &str, key: &super::Sensitive<String>, expected_prefix: &str) {
        let key_str = key.get();
        if key_str.is_empty() {
            return;
        }
        if key_str.len() != ATTEST_API_KEY_LENGTH {
            panic!(
                "attestation backends rest.credentials.{} length {} != {}",
                field, key_str.len(), ATTEST_API_KEY_LENGTH
            );
        }
        if !key_str.starts_with(expected_prefix) {
            panic!(
                "attestation backends rest.credentials.{} must start with '{}'",
                field, expected_prefix
            );
        }
        let suffix = &key_str[expected_prefix.len()..];
        if !suffix.chars().all(|c| c.is_ascii_alphanumeric()) {
            panic!(
                "attestation backends rest.credentials.{} suffix must be 32 alphanumeric characters",
                field
            );
        }
    }
}

impl Database {
    fn validate(&self) {
        const DB_TYPES_VALID: [&str; 4] = ["sqlite", "memory", "mysql", "postgres"];

        if !DB_TYPES_VALID.contains(&self.db_type.as_str()) {
            panic!(
                "storage.db_type = '{}' is invalid; must be one of {:?}",
                self.db_type, DB_TYPES_VALID
            );
        }

        if self.max_connections < DB_MAX_CONNECTIONS_MIN || self.max_connections > DB_MAX_CONNECTIONS_MAX {
            panic!(
                "storage.max_connections = {} is out of range [{}, {}]",
                self.max_connections, DB_MAX_CONNECTIONS_MIN, DB_MAX_CONNECTIONS_MAX
            );
        }

        if self.timeout > DB_TIMEOUT_MAX {
            panic!(
                "storage.timeout = {} exceeds maximum {}",
                self.timeout, DB_TIMEOUT_MAX
            );
        }

        if self.db_type != "memory" {
            if self.sql_file_path.is_empty() {
                panic!("storage.db_type = '{}' requires non-empty storage.sql_file_path", self.db_type);
            }
            if self.sql_file_path.len() > FILE_PATH_MAX_LEN {
                panic!(
                    "storage.sql_file_path length {} exceeds maximum {}",
                    self.sql_file_path.len(), FILE_PATH_MAX_LEN
                );
            }
        }

        if self.db_type == "mysql" || self.db_type == "postgres" {
            if self.url.is_empty() {
                panic!("storage.db_type = '{}' requires non-empty storage.url", self.db_type);
            }
            if self.url.len() > DB_URL_MAX_LEN {
                panic!(
                    "storage.url length {} exceeds maximum {}",
                    self.url.len(), DB_URL_MAX_LEN
                );
            }
        }
    }
}

impl RbsConfig {
    /// Validates all configuration fields and panics if any constraint is violated.
    /// Called at startup before building the core to fail-fast on bad configuration.
    pub fn validate(&self) {
        if let Some(ref rest) = self.rest {
            rest.validate();
        }
        self.logging.validate();
        self.attestation.validate();
        if let Some(ref storage) = self.storage {
            storage.validate();
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
        assert_eq!(rbs.logging.rotation.compression, super::super::RotationCompression::None);

        let rest = RestConfig::default();
        assert_eq!(rest.listen_addr, "127.0.0.1:6666");
        assert!(!rest.https.enabled);

        assert!(!super::super::RestHttpsConfig::default().enabled);
        assert_eq!(super::super::RotationCompression::default(), super::super::RotationCompression::None);

        let rl = PerIpRateLimitConfig::default();
        assert!(!rl.enabled);
        assert_eq!(rl.requests_per_sec, 60);
        assert_eq!(rl.burst, None);

        let s = super::super::Sensitive::new("secret".to_string());
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
        let original = super::super::Sensitive::new("super-secret".to_string());
        let yaml = serde_yaml::to_string(&original).unwrap();
        let deserialized: super::super::Sensitive<String> = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.get(), original.get());
        assert_eq!(format!("{:?}", deserialized), "[redacted]");
        assert_eq!(deserialized.to_string(), "[redacted]");
    }

    #[test]
    fn rest_https_config_debug_redacts_key_file() {
        let cfg = super::super::RestHttpsConfig {
            enabled: true,
            cert_file: "/path/to/cert.pem".to_string(),
            key_file: super::super::Sensitive::new("/path/to/key.pem".to_string()),
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
        let core = super::super::CoreConfig::default();
        assert_eq!(core.logging, LoggingConfig::default());

        let proxies = super::super::TrustedProxyConfig::default();
        assert!(proxies.addrs.is_empty());
    }

    #[test]
    fn deserialize_rbs_yaml_sample() {
        let yaml = include_str!("../../../conf/rbs.yaml");
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

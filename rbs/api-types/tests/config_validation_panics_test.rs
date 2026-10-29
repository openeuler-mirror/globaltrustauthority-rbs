/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Startup validation tests for configuration constraints that are not exercised
//! by the happy-path suites: length caps, mutually-exclusive mTLS settings, and
//! the storage/resource backend ranges. `RbsConfig::validate` panics on failure,
//! so each case asserts the panic message that identifies the offending field.

use std::collections::HashMap;

use rbs_api_types::config::{
    AttestationBackendMode, CaConfig, CredentialsConfig, Database, HsmConfig, IdempotencyConfig, LogRotationConfig,
    RbsConfig, ResourceProviderConfig, ResourceProvidersConfig, Sensitive, SlotConfig, VaultConfig,
};

const BASE_YAML: &str = r#"
rest:
  listen_addr: "127.0.0.1:6666"
attestation:
  default_as_provider: gta
  backends:
    gta:
      mode: builtin
auth:
  attest_token:
    public_key_path: "/tmp/attest_pub.pem"
    issuer: "Global Trust Authority"
  bearer_token:
    issuer: "rbs-cli"
    audience: "globaltrustauthority-rbs"
admin:
  admin_key:
    public_key_path: "/tmp/admin_pub.pem"
"#;

fn base() -> RbsConfig {
    serde_yaml::from_str(BASE_YAML).expect("parse base config")
}

fn rest_backend(config: &mut RbsConfig) {
    let backend = config.attestation.backends.get_mut("gta").expect("gta backend");
    backend.mode = AttestationBackendMode::Rest;
    backend.rest.base_url = "https://gta.example.com".to_string();
    backend.rest.credentials.user_id = "valid-user".to_string();
}

fn long_path() -> String {
    "/".to_string() + &"a".repeat(4100)
}

fn vault(mut f: impl FnMut(&mut VaultConfig)) -> ResourceProviderConfig {
    let mut cfg = VaultConfig {
        url: "http://localhost:8200".to_string(),
        token: Sensitive::new("token".to_string()),
        mount_path: "secret".to_string(),
        kv_version: "v2".to_string(),
        verify_ssl: true,
        timeout: 30,
        max_connections: 10,
        max_retries: 2,
        max_response_body_bytes: 1024 * 1024,
        allowed_resource_types: vec!["secret".to_string()],
    };
    f(&mut cfg);
    ResourceProviderConfig::Vault(cfg)
}

fn ca(mut f: impl FnMut(&mut CaConfig)) -> ResourceProviderConfig {
    let mut cfg = CaConfig {
        url: "https://ca.example.com".to_string(),
        https: Default::default(),
        message_protection_cert_file: "/tmp/cert.pem".to_string(),
        message_protection_key_file: "/tmp/key.pem".to_string(),
        response_protection_trust_anchors_file: "/tmp/anchors.pem".to_string(),
        cert_profile: String::new(),
        allowed_resource_types: vec!["cert".to_string()],
        max_response_bytes: 1024 * 1024,
        timeout: 30,
        idempotency: IdempotencyConfig::default(),
    };
    f(&mut cfg);
    ResourceProviderConfig::Ca(cfg)
}

fn hsm(mut f: impl FnMut(&mut HsmConfig)) -> ResourceProviderConfig {
    let mut cfg = HsmConfig {
        module_path: "/usr/lib/pkcs11.so".to_string(),
        slot: SlotConfig { label: "token".to_string() },
        credentials: CredentialsConfig { pin_env: "RBS_HSM_PIN".to_string() },
        allowed_resource_types: vec!["key".to_string()],
        max_key_bytes: 1024 * 1024,
        timeout: 30,
    };
    f(&mut cfg);
    ResourceProviderConfig::Hsm(cfg)
}

fn with_backend(config: &mut RbsConfig, name: &str, backend: ResourceProviderConfig) {
    let mut backends = HashMap::new();
    backends.insert(name.to_string(), backend);
    config.resource = Some(ResourceProvidersConfig { max_per_user: 10, backends });
}

// ── Logging ────────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "logging.level")]
fn logging_invalid_level_panics() {
    let mut config = base();
    config.logging.level = "verbose".to_string();
    config.validate();
}

#[test]
#[should_panic(expected = "logging.format")]
fn logging_invalid_format_panics() {
    let mut config = base();
    config.logging.format = "xml".to_string();
    config.validate();
}

#[test]
#[should_panic(expected = "logging.file_path length")]
fn logging_file_path_too_long_panics() {
    let mut config = base();
    config.logging.file_path = Some(long_path());
    config.validate();
}

#[test]
#[should_panic(expected = "logging.file_mode")]
fn logging_file_mode_too_large_panics() {
    let mut config = base();
    config.logging.file_mode = 0o10000;
    config.validate();
}

#[test]
#[should_panic(expected = "logging.rotation.file_mode")]
fn logging_rotation_file_mode_too_large_panics() {
    let mut config = base();
    config.logging.rotation = LogRotationConfig { file_mode: 0o10000, ..config.logging.rotation.clone() };
    config.validate();
}

// ── REST / HTTPS ───────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "rest.listen_addr length")]
fn rest_listen_addr_too_long_panics() {
    let mut config = base();
    config.rest.as_mut().expect("rest").listen_addr = format!("127.0.0.1:{}", "1".repeat(200));
    config.validate();
}

#[test]
#[should_panic(expected = "key_file is empty")]
fn rest_https_empty_key_file_panics() {
    let mut config = base();
    let rest = config.rest.as_mut().expect("rest");
    rest.https.enabled = true;
    rest.https.cert_file = "/tmp/cert.pem".to_string();
    rest.https.key_file = Sensitive::new(String::new());
    config.validate();
}

#[test]
#[should_panic(expected = "cert_file length")]
fn rest_https_cert_file_too_long_panics() {
    let mut config = base();
    let rest = config.rest.as_mut().expect("rest");
    rest.https.enabled = true;
    rest.https.cert_file = long_path();
    rest.https.key_file = Sensitive::new("/tmp/key.pem".to_string());
    config.validate();
}

#[test]
#[should_panic(expected = "key_file length")]
fn rest_https_key_file_too_long_panics() {
    let mut config = base();
    let rest = config.rest.as_mut().expect("rest");
    rest.https.enabled = true;
    rest.https.cert_file = "/tmp/cert.pem".to_string();
    rest.https.key_file = Sensitive::new(long_path());
    config.validate();
}

// ── Attestation REST ───────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "ca_file length")]
fn attestation_ca_file_too_long_panics() {
    let mut config = base();
    rest_backend(&mut config);
    config.attestation.backends.get_mut("gta").expect("gta").rest.ca_file = long_path();
    config.validate();
}

#[test]
#[should_panic(expected = "client_cert_path length")]
fn attestation_client_cert_path_too_long_panics() {
    let mut config = base();
    rest_backend(&mut config);
    let rest = &mut config.attestation.backends.get_mut("gta").expect("gta").rest;
    rest.client_cert_path = long_path();
    rest.client_key_path = "/tmp/key.pem".to_string();
    config.validate();
}

#[test]
#[should_panic(expected = "client_key_path length")]
fn attestation_client_key_path_too_long_panics() {
    let mut config = base();
    rest_backend(&mut config);
    let rest = &mut config.attestation.backends.get_mut("gta").expect("gta").rest;
    rest.client_cert_path = "/tmp/cert.pem".to_string();
    rest.client_key_path = long_path();
    config.validate();
}

#[test]
#[should_panic(expected = "must be provided together")]
fn attestation_mtls_pair_mismatch_panics() {
    let mut config = base();
    rest_backend(&mut config);
    config.attestation.backends.get_mut("gta").expect("gta").rest.client_cert_path = "/tmp/cert.pem".to_string();
    config.validate();
}

#[test]
#[should_panic(expected = "sub_api_key must not be empty")]
fn attestation_empty_sub_api_key_panics() {
    let mut config = base();
    rest_backend(&mut config);
    let creds = &mut config.attestation.backends.get_mut("gta").expect("gta").rest.credentials;
    creds.api_key_auth = true;
    creds.main_api_key = Sensitive::new(format!("m.{}", "a".repeat(32)));
    creds.sub_api_key = Sensitive::new(String::new());
    config.validate();
}

// ── Storage ────────────────────────────────────────────────────────────────

fn storage(db_type: &str, sql_file_path: &str, url: &str) -> Database {
    Database {
        db_type: db_type.to_string(),
        max_connections: 10,
        timeout: 30,
        url: url.to_string(),
        sql_file_path: sql_file_path.to_string(),
    }
}

#[test]
#[should_panic(expected = "requires non-empty storage.sql_file_path")]
fn storage_sqlite_requires_sql_file_path() {
    let mut config = base();
    config.storage = Some(storage("sqlite", "", ""));
    config.validate();
}

#[test]
#[should_panic(expected = "storage.sql_file_path length")]
fn storage_sql_file_path_too_long_panics() {
    let mut config = base();
    config.storage = Some(storage("sqlite", &long_path(), ""));
    config.validate();
}

#[test]
#[should_panic(expected = "requires non-empty storage.url")]
fn storage_mysql_requires_url() {
    let mut config = base();
    config.storage = Some(storage("mysql", "/tmp/schema.sql", ""));
    config.validate();
}

#[test]
#[should_panic(expected = "storage.url length")]
fn storage_url_too_long_panics() {
    let mut config = base();
    config.storage = Some(storage("postgres", "/tmp/schema.sql", &format!("postgres://{}", "a".repeat(2100))));
    config.validate();
}

// ── Resource backends ──────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "resource.max_per_user")]
fn resource_max_per_user_out_of_range_panics() {
    let mut config = base();
    let mut backends = HashMap::new();
    backends.insert("v".to_string(), vault(|_| {}));
    config.resource = Some(ResourceProvidersConfig { max_per_user: 0, backends });
    config.validate();
}

#[test]
#[should_panic(expected = "must have at least one backend")]
fn resource_empty_backends_panics() {
    let mut config = base();
    config.resource = Some(ResourceProvidersConfig { max_per_user: 10, backends: HashMap::new() });
    config.validate();
}

#[test]
#[should_panic(expected = "url must not be empty")]
fn vault_empty_url_panics() {
    let mut config = base();
    with_backend(&mut config, "v", vault(|cfg| cfg.url = String::new()));
    config.validate();
}

#[test]
#[should_panic(expected = "url length")]
fn vault_url_too_long_panics() {
    let mut config = base();
    with_backend(&mut config, "v", vault(|cfg| cfg.url = format!("http://{}", "a".repeat(2100))));
    config.validate();
}

#[test]
#[should_panic(expected = "mount_path length")]
fn vault_mount_path_invalid_panics() {
    let mut config = base();
    with_backend(&mut config, "v", vault(|cfg| cfg.mount_path = String::new()));
    config.validate();
}

#[test]
#[should_panic(expected = "max_connections")]
fn vault_max_connections_out_of_range_panics() {
    let mut config = base();
    with_backend(&mut config, "v", vault(|cfg| cfg.max_connections = 0));
    config.validate();
}

#[test]
#[should_panic(expected = "max_retries")]
fn vault_max_retries_out_of_range_panics() {
    let mut config = base();
    with_backend(&mut config, "v", vault(|cfg| cfg.max_retries = 1000));
    config.validate();
}

#[test]
#[should_panic(expected = "message_protection_cert_file must not be empty")]
fn ca_empty_message_protection_cert_panics() {
    let mut config = base();
    with_backend(&mut config, "c", ca(|cfg| cfg.message_protection_cert_file = String::new()));
    config.validate();
}

#[test]
#[should_panic(expected = "message_protection_key_file must not be empty")]
fn ca_empty_message_protection_key_panics() {
    let mut config = base();
    with_backend(&mut config, "c", ca(|cfg| cfg.message_protection_key_file = String::new()));
    config.validate();
}

#[test]
#[should_panic(expected = "response_protection_trust_anchors_file must not be empty")]
fn ca_empty_trust_anchors_panics() {
    let mut config = base();
    with_backend(&mut config, "c", ca(|cfg| cfg.response_protection_trust_anchors_file = String::new()));
    config.validate();
}

#[test]
#[should_panic(expected = "allowed_resource_types must not be empty")]
fn ca_empty_allowed_types_panics() {
    let mut config = base();
    with_backend(&mut config, "c", ca(|cfg| cfg.allowed_resource_types.clear()));
    config.validate();
}

#[test]
#[should_panic(expected = "max_response_bytes must be > 0")]
fn ca_zero_max_response_bytes_panics() {
    let mut config = base();
    with_backend(&mut config, "c", ca(|cfg| cfg.max_response_bytes = 0));
    config.validate();
}

#[test]
#[should_panic(expected = "timeout = 0 is out of range")]
fn ca_timeout_out_of_range_panics() {
    let mut config = base();
    with_backend(&mut config, "c", ca(|cfg| cfg.timeout = 0));
    config.validate();
}

#[test]
#[should_panic(expected = "idempotency.max_entries must be > 0")]
fn ca_zero_idempotency_entries_panics() {
    let mut config = base();
    with_backend(&mut config, "c", ca(|cfg| cfg.idempotency.max_entries = 0));
    config.validate();
}

#[test]
#[should_panic(expected = "idempotency.ttl_seconds must be > 0")]
fn ca_zero_idempotency_ttl_panics() {
    let mut config = base();
    with_backend(&mut config, "c", ca(|cfg| cfg.idempotency.ttl_seconds = 0));
    config.validate();
}

#[test]
#[should_panic(expected = "module_path must not be empty")]
fn hsm_empty_module_path_panics() {
    let mut config = base();
    with_backend(&mut config, "h", hsm(|cfg| cfg.module_path = String::new()));
    config.validate();
}

#[test]
#[should_panic(expected = "slot.label must not be empty")]
fn hsm_empty_slot_label_panics() {
    let mut config = base();
    with_backend(&mut config, "h", hsm(|cfg| cfg.slot.label = String::new()));
    config.validate();
}

#[test]
#[should_panic(expected = "credentials.pin_env must not be empty")]
fn hsm_empty_pin_env_panics() {
    let mut config = base();
    with_backend(&mut config, "h", hsm(|cfg| cfg.credentials.pin_env = String::new()));
    config.validate();
}

#[test]
#[should_panic(expected = "allowed_resource_types must not be empty")]
fn hsm_empty_allowed_types_panics() {
    let mut config = base();
    with_backend(&mut config, "h", hsm(|cfg| cfg.allowed_resource_types.clear()));
    config.validate();
}

#[test]
#[should_panic(expected = "max_key_bytes must be > 0")]
fn hsm_zero_max_key_bytes_panics() {
    let mut config = base();
    with_backend(&mut config, "h", hsm(|cfg| cfg.max_key_bytes = 0));
    config.validate();
}

#[test]
#[should_panic(expected = "timeout = 0 is out of range")]
fn hsm_timeout_out_of_range_panics() {
    let mut config = base();
    with_backend(&mut config, "h", hsm(|cfg| cfg.timeout = 0));
    config.validate();
}

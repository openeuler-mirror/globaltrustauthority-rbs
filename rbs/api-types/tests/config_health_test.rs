/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
 * PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Integration tests for the optional top-level `health` config section (`HealthConfig`):
//! serde semantics (absent -> None, present -> exact value, section strictness) and startup
//! validation behavior (format checks, rest/health address conflict, deny_unknown_fields).

use rbs_api_types::config::{HealthConfig, RbsConfig};

/// Minimal YAML that passes `RbsConfig::validate()`: builtin attestation backend, auth and
/// admin pointing at placeholder key paths (validation checks presence only; the files are
/// read at startup, not during validate).
const VALID_BASE_YAML: &str = r#"
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

fn base_config() -> RbsConfig {
    serde_yaml::from_str(VALID_BASE_YAML).expect("parse base config")
}

fn with_health(mut config: RbsConfig, listen_addr: &str) -> RbsConfig {
    config.health = Some(HealthConfig { listen_addr: listen_addr.to_string() });
    config
}

// TC1: no `health` section -> None (absent = disabled, old-config compatibility).
#[test]
fn health_section_absent_defaults_to_none() {
    let config: RbsConfig = serde_yaml::from_str(VALID_BASE_YAML).expect("parse config");
    assert!(config.health.is_none());
}

// TC2: `health` section present -> Some(HealthConfig) with the exact field value.
#[test]
fn health_section_parses_listen_addr() {
    let yaml = format!("{VALID_BASE_YAML}health:\n  listen_addr: \"0.0.0.0:6667\"\n");
    let config: RbsConfig = serde_yaml::from_str(&yaml).expect("parse config");
    assert_eq!(
        config.health,
        Some(HealthConfig { listen_addr: "0.0.0.0:6667".to_string() })
    );
}

// TC3a: unknown key inside `health` -> deserialization error (deny_unknown_fields).
#[test]
fn health_section_rejects_unknown_key() {
    let yaml = "health:\n  listen_addr2: \"0.0.0.0:6667\"\n";
    let result = serde_yaml::from_str::<RbsConfig>(yaml);
    assert!(result.is_err(), "unknown key inside health must be rejected");
}

// TC3b: missing `listen_addr` -> deserialization error mentioning the field.
#[test]
fn health_section_requires_listen_addr() {
    let yaml = "health: {}";
    let err = serde_yaml::from_str::<RbsConfig>(yaml).unwrap_err();
    assert!(
        err.to_string().contains("listen_addr"),
        "error should mention listen_addr, got: {err}"
    );
}

// TC4a: empty listen_addr -> panic.
#[test]
#[should_panic(expected = "health.listen_addr must not be empty")]
fn health_validate_rejects_empty_addr() {
    with_health(base_config(), "").validate();
}

// TC4b: listen_addr longer than 128 chars -> panic.
#[test]
#[should_panic(expected = "health.listen_addr length 129 exceeds maximum 128")]
fn health_validate_rejects_overlong_addr() {
    with_health(base_config(), &"a".repeat(129)).validate();
}

// TC4c: listen_addr without ':' -> panic.
#[test]
#[should_panic(expected = "health.listen_addr must be in host:port format")]
fn health_validate_rejects_addr_without_port() {
    with_health(base_config(), "0.0.0.0-6667").validate();
}

// TC5: health.listen_addr equal to rest.listen_addr -> panic (conflict detection).
#[test]
#[should_panic(expected = "health.listen_addr must differ from rest.listen_addr")]
fn health_validate_rejects_same_addr_as_rest() {
    with_health(base_config(), "127.0.0.1:6666").validate();
}

// TC6a: valid health address alongside rest -> validate passes.
#[test]
fn health_validate_accepts_valid_addr_with_rest() {
    with_health(base_config(), "0.0.0.0:6667").validate();
}

// TC6b: health present with rest absent -> validate passes (no conflict possible).
#[test]
fn health_validate_accepts_health_without_rest() {
    let mut config = base_config();
    config.rest = None;
    with_health(config, "0.0.0.0:6667").validate();
}

// TC13: unknown top-level key -> rejected (deny_unknown_fields mechanism; this is the path an
// older binary takes when it encounters the new `health` key — upgrade-order documentation).
#[test]
fn unknown_top_level_key_rejected() {
    let yaml = "healthz:\n  listen_addr: \"0.0.0.0:6667\"\n";
    let result = serde_yaml::from_str::<RbsConfig>(yaml);
    assert!(result.is_err(), "unknown top-level key must be rejected");
}

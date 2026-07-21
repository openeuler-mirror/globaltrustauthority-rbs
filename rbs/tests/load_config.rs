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

//! Integration tests for `rbs::load_config`.

use std::fs;
use std::path::Path;

use tempfile::tempdir;

#[test]
fn load_config_reads_valid_yaml_file() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("rbs.yaml");
    fs::write(
        &path,
        r#"
rest:
  listen_addr: "127.0.0.1:19999"
logging:
  level: info
  format: text
"#,
    )
    .expect("write config");

    let cfg = rbs::load_config(&path).expect("load_config must succeed");
    let rest = cfg.rest.as_ref().expect("rest must be present");
    assert_eq!(rest.listen_addr, "127.0.0.1:19999");
    assert_eq!(cfg.logging.level, "info");
}

#[test]
fn load_config_fails_when_rest_is_null() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("rbs.yaml");
    fs::write(
        &path,
        r#"
rest: null
logging:
  level: info
"#,
    )
    .expect("write config");

    let err = rbs::load_config(&path).expect_err("null rest must be rejected");
    let msg = err.to_string();
    assert!(msg.contains("rest") && msg.contains("non-null"), "expected rest error, got: {msg}");
}

#[test]
fn load_config_fails_when_file_missing() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("nonexistent.yaml");
    assert!(!path.exists());

    let err = rbs::load_config(&path).expect_err("missing file must error");
    let msg = err.to_string();
    assert!(msg.contains("read config file") || msg.contains("No such file"), "expected read error, got: {msg}");
}

#[test]
fn load_config_error_includes_path() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("bad.yaml");
    fs::write(&path, "not: yaml: [[[").expect("write invalid yaml");

    let err = rbs::load_config(&path).expect_err("invalid yaml must error");
    let chain = format!("{err:#}");
    let path_str = Path::new(&path).display().to_string();
    assert!(
        chain.contains("parse YAML") && chain.contains(&path_str),
        "error chain should mention parse and path; got: {chain}"
    );
}

#[test]
fn load_config_reads_policy_max_per_user() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("rbs.yaml");
    fs::write(
        &path,
        r#"
rest:
  listen_addr: "127.0.0.1:19999"
logging:
  level: info
policy:
  max_per_user: 25
"#,
    )
    .expect("write config");

    let cfg = rbs::load_config(&path).expect("load_config must succeed");
    assert_eq!(cfg.policy.max_per_user, 25);
}

#[test]
fn load_config_defaults_policy_when_omitted() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("rbs.yaml");
    fs::write(
        &path,
        r#"
rest:
  listen_addr: "127.0.0.1:19999"
logging:
  level: info
"#,
    )
    .expect("write config");

    let cfg = rbs::load_config(&path).expect("load_config must succeed");
    assert_eq!(cfg.policy.max_per_user, 10);
}

#[test]
fn load_config_validates_resource_and_bearer() {
    // Full config with legal resource backend + bearer_token + the sibling sections
    // (attestation, attest_token) that `validate()` checks earlier in the chain.
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("rbs.yaml");
    fs::write(
        &path,
        r#"
rest:
  listen_addr: "127.0.0.1:19999"
logging:
  level: info
auth:
  attest_token:
    jwks_file: "/etc/rbs/attest.jwk"
    issuer: "GTA"
  bearer_token:
    issuer: "rbs-cli"
    audience: "globaltrustauthority-rbs"
admin:
  max_users: 10
  admin_key:
    public_key_path: "/etc/rbs/admin_pub.pem"
attestation:
  default_as_provider: gta
  backends:
    gta:
      mode: rest
      rest:
        base_url: "https://127.0.0.1:8080"
        credentials:
          user_id: "rbs-service"
resource:
  backends:
    vault:
      type: vault
      url: "https://vault:8200"
      token: "s.x"
      mount_path: secret
      kv_version: v2
      verify_ssl: true
      timeout: 30
      max_connections: 100
      max_retries: 2
"#,
    )
    .expect("write config");

    let cfg = rbs::load_config(&path).expect("load_config must succeed");
    // validate() panics on bad config; legal values here must not panic.
    cfg.validate();
    assert_eq!(cfg.auth.bearer_token.issuer, "rbs-cli");
    assert_eq!(cfg.resource.as_ref().unwrap().backends.len(), 1);
}

#[test]
#[should_panic(expected = "kv_version")]
fn load_config_validate_rejects_bad_resource_kv_version() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("rbs.yaml");
    fs::write(
        &path,
        r#"
rest:
  listen_addr: "127.0.0.1:19999"
logging:
  level: info
auth:
  attest_token:
    jwks_file: "/etc/rbs/attest.jwk"
    issuer: "GTA"
  bearer_token:
    issuer: "rbs-cli"
    audience: "globaltrustauthority-rbs"
admin:
  max_users: 10
  admin_key:
    public_key_path: "/etc/rbs/admin_pub.pem"
attestation:
  default_as_provider: gta
  backends:
    gta:
      mode: rest
      rest:
        base_url: "https://127.0.0.1:8080"
        credentials:
          user_id: "rbs-service"
resource:
  backends:
    vault:
      type: vault
      url: "https://vault:8200"
      token: "s.x"
      mount_path: secret
      kv_version: v9
"#,
    )
    .expect("write config");

    let cfg = rbs::load_config(&path).expect("load_config must succeed");
    cfg.validate();
}

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

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

//! Integration test: init_logging must fail when log directory does not exist.

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig};
use tempfile::tempdir;

/// `init_logging` fails when the configured log directory does not exist.
#[test]
fn init_logging_fails_when_log_directory_does_not_exist() {
    let dir = tempdir().expect("create temp dir");
    let nonexistent_sub = dir.path().join("nonexistent_subdir");
    assert!(!nonexistent_sub.exists());
    let log_file = nonexistent_sub.join("rbs.log");

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: false,
        rotation: LogRotationConfig::default(),
        file_mode: 0o600,
    };

    let err = init_logging(&config).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("does not exist") || msg.contains("log directory"),
        "error should mention missing directory: {}",
        msg
    );
}

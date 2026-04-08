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

//! Integration test (Unix-only): log file respects configured file_mode when not rotating.

#![cfg(unix)]

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

/// When configured without rotation, the created log file must respect the configured
/// file mode on Unix platforms.
#[test]
fn init_logging_sets_file_mode_0600() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("rbs-permissions.log");

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: false,
        rotation: LogRotationConfig::default(),
        file_mode: 0o600,
    };

    init_logging(&config).expect("init_logging should succeed");
    log::info!("permissions test line");
    log::logger().flush();

    let metadata = fs::metadata(&log_file).expect("log file should exist");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "log file should have mode 0o600, got {mode:o}");
}

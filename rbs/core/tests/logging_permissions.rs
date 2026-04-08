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

//! Integration test (Unix-only): rotated archives honour rotation file_mode.

#![cfg(unix)]

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig, RotationCompression};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

/// Rotated archives must honour the configured rotation file mode on Unix platforms.
#[test]
fn rotation_archives_use_0440_mode() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("rbs-rotation-permissions.log");

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: true,
        rotation: LogRotationConfig {
            max_file_size_bytes: 50,
            max_files: 2,
            compression: RotationCompression::None,
            file_mode: 0o440,
        },
        file_mode: 0o600,
    };

    init_logging(&config).expect("init_logging should succeed");

    for i in 0..10 {
        log::info!("rotation permissions test line {}", i);
    }
    log::logger().flush();

    let archived = dir.path().join("rbs-rotation-permissions.log.1");
    assert!(archived.exists(), "rotation should create first archive: {:?}", archived);

    let metadata = fs::metadata(&archived).expect("archived file should exist");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o440, "archived log should have mode 0o440, got {mode:o}",);
}

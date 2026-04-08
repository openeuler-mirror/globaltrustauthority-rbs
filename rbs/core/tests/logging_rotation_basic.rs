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

//! Integration test: basic size-based rotation creates an archived file with content.

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig, RotationCompression};
use std::fs;
use tempfile::tempdir;

/// Basic rotation: size-based rolling creates `rbs.log.1` with rotated content.
#[test]
fn init_logging_with_rotation_creates_archived_file() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("rbs.log");

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

    init_logging(&config).expect("init_logging should succeed in isolation");

    for i in 0..10 {
        log::info!("rotation test line {}", i);
    }
    log::logger().flush();

    let archived = dir.path().join("rbs.log.1");
    assert!(archived.exists(), "rotation should create rbs.log.1");

    // Basic sanity check that the archived file actually contains rolled log content.
    let archived_content = fs::read_to_string(&archived).unwrap_or_default();
    assert!(archived_content.contains("rotation test line"), "archived log should contain rotated test lines");
}

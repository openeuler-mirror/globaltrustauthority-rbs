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

//! Integration tests: rotation with gzip compression.

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig, RotationCompression};
use std::fs;
use tempfile::tempdir;

/// After gzip rotation, new logs must continue to be written only to the active log file,
/// not appended to the archived gzip.
#[test]
fn init_logging_with_rotation_gzip_keeps_writing_to_active_log() {
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
            compression: RotationCompression::Gzip,
            file_mode: 0o440,
        },
        file_mode: 0o600,
    };

    init_logging(&config).expect("init_logging should succeed in isolation");

    // First batch of logs to trigger rotation and create rbs.log.1.gz.
    for i in 0..10 {
        log::info!("rotation gzip first batch {}", i);
    }
    log::logger().flush();

    let archived_gz = dir.path().join("rbs.log.1.gz");
    assert!(archived_gz.exists(), "first rotation with gzip should create rbs.log.1.gz",);
    let size_before = fs::metadata(&archived_gz).unwrap().len();

    // Second batch: confirm that the already-archived gzip file is not written
    // again (its size should remain unchanged).
    let marker = "rotation gzip second batch marker";
    log::info!("{marker}");
    log::logger().flush();

    let size_after = fs::metadata(&archived_gz).unwrap().len();
    assert!(size_after == size_before, "archived gzip size should not change after further logging",);
}

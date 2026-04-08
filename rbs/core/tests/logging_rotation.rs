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

//! Integration tests for log rotation (size-based rolling, max_files).

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig, RotationCompression};
use std::fs;
use tempfile::tempdir;

/// Rotation with `max_files` must prune older archives beyond the configured limit.
#[test]
fn init_logging_rotation_respects_max_files() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("rbs.log");

    let max_files = 3u32;
    // Small size so each line (~60+ bytes including timestamp and metadata)
    // will quickly exceed the threshold and trigger a roll.
    let max_file_size_bytes = 60u64;

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: true,
        rotation: LogRotationConfig {
            max_file_size_bytes,
            max_files,
            compression: RotationCompression::None,
            file_mode: 0o440,
        },
        file_mode: 0o600,
    };

    init_logging(&config).expect("init_logging should succeed");

    for i in 0..15 {
        log::info!("rotation max_files test line number {}", i);
    }
    log::info!("rotation max_files test final line");
    log::logger().flush();

    let active = dir.path().join("rbs.log");
    let archived_1 = dir.path().join("rbs.log.1");
    let archived_2 = dir.path().join("rbs.log.2");
    let archived_3 = dir.path().join("rbs.log.3");
    let archived_4 = dir.path().join("rbs.log.4");

    let listing: Vec<String> = fs::read_dir(dir.path())
        .map(|d| d.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned())).collect())
        .unwrap_or_default();

    assert!(archived_1.exists(), "at least one roll should create rbs.log.1; listing: {:?}", listing);

    let mut archived_count = 0u32;
    if archived_1.exists() {
        archived_count += 1;
    }
    if archived_2.exists() {
        archived_count += 1;
    }
    if archived_3.exists() {
        archived_count += 1;
    }
    assert!(
        archived_count <= max_files,
        "archived files must not exceed max_files ({}); listing: {:?}",
        max_files,
        listing
    );
    assert!(!archived_4.exists(), "roller must not keep more than max_files archives; listing: {:?}", listing);

    let a1 = fs::read_to_string(&archived_1).unwrap_or_default();
    assert!(a1.contains("rotation max_files test"), "rbs.log.1 should contain rolled content");
    if active.exists() {
        let active_content = fs::read_to_string(&active).unwrap_or_default();
        assert!(
            active_content.contains("rotation max_files test"),
            "active log should contain test lines when present"
        );
    }
}

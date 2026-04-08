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

//! Integration test: init_logging must append to an existing file (not truncate).

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig};
use std::fs;
use tempfile::tempdir;

const EXISTING_LINE: &str = "existing log line before init";
const APPENDED_LINE: &str = "appended line after init";

/// When the log file already exists, `init_logging` must open it in append mode and
/// preserve existing content.
#[test]
fn init_logging_appends_to_existing_file() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("rbs.log");

    // Pre-create the log file with some content.
    fs::write(&log_file, format!("{}\n", EXISTING_LINE)).expect("write existing file");

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: false,
        rotation: LogRotationConfig::default(),
        file_mode: 0o600,
    };

    init_logging(&config).expect("init_logging should succeed in isolation");

    log::info!("{}", APPENDED_LINE);
    log::logger().flush();

    let content = fs::read_to_string(&log_file).unwrap();
    assert!(
        content.contains(EXISTING_LINE),
        "existing content must be preserved (append, not truncate); got: {}",
        content
    );
    assert!(content.contains(APPENDED_LINE), "new log line must be appended; got: {}", content);

    // Basic ordering check: existing line should appear before appended line.
    let existing_pos = content.find(EXISTING_LINE).expect("existing line should be present");
    let appended_pos = content.find(APPENDED_LINE).expect("appended line should be present");
    assert!(existing_pos < appended_pos, "existing content must appear before appended content; got: {}", content);
}

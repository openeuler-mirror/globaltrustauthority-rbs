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

//! Integration test: init_logging with JSON format writes valid JSON lines with message field.

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig};
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

/// `init_logging` with JSON format writes one JSON object per line to the log file.
#[test]
fn init_logging_with_file_json_format() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("rbs.json.log");

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "json".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: false,
        rotation: LogRotationConfig::default(),
        file_mode: 0o600,
    };

    init_logging(&config).expect("init_logging should succeed in isolation");

    log::info!("json_test_message");
    log::logger().flush();

    let content = fs::read_to_string(&log_file).unwrap();
    // Each non-empty line should be valid JSON, and at least one line must contain our message
    // in the structured "message"/"msg" field.
    let mut found_message = false;
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        let parsed: Value = serde_json::from_str(line).expect("each log line must be valid JSON when format=json");
        let msg_field = parsed.get("message").and_then(|v| v.as_str()).unwrap_or_default();
        if msg_field.contains("json_test_message") {
            found_message = true;
        }
    }
    assert!(found_message, "at least one JSON log line should contain the message; content: {}", content);
}

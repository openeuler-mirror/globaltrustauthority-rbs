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

//! Basic concurrency tests for logging: multiple threads writing to the same logger
//! should not lose messages.

use std::thread;

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig};
use tempfile::tempdir;

/// Multiple threads logging concurrently to the same file should produce all expected lines.
#[test]
fn concurrent_logging_produces_all_messages() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("concurrency.log");

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: false,
        rotation: LogRotationConfig::default(),
        file_mode: 0o600,
    };

    init_logging(&config).expect("init_logging should succeed");

    let threads = 4;
    let per_thread = 10;

    let mut handles = Vec::new();
    for t in 0..threads {
        handles.push(thread::spawn(move || {
            for i in 0..per_thread {
                log::info!("concurrency test thread-{t}-line-{i}");
            }
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    log::logger().flush();

    let content = std::fs::read_to_string(&log_file).expect("log file should be readable");

    for t in 0..threads {
        for i in 0..per_thread {
            let marker = format!("concurrency test thread-{t}-line-{i}");
            assert!(content.contains(&marker), "log content must contain marker {marker}, got: {content}");
        }
    }
}

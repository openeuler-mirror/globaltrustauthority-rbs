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

//! Logging integration tests.

use rbs_core::{init_logging, LogRotationConfig, LoggingConfig, RotationCompression};
use serial_test::serial;
use std::fs;
use tempfile::tempdir;

// ============ Init Tests ============

const EXISTING_LINE: &str = "existing log line before init";
const APPENDED_LINE: &str = "appended line after init";

/// When the log file already exists, `init_logging` must open it in append mode and
/// preserve existing content.
#[test]
#[serial]
fn init_logging_appends_to_existing_file() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("rbs.log");

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

    let existing_pos = content.find(EXISTING_LINE).expect("existing line should be present");
    let appended_pos = content.find(APPENDED_LINE).expect("appended line should be present");
    assert!(existing_pos < appended_pos, "existing content must appear before appended content; got: {}", content);
}

/// `init_logging` fails when the configured log directory does not exist.
#[test]
#[serial]
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

/// A whitespace-only `file_path` means "not configured": the logger falls back
/// to stderr instead of trying to open a blank path.
#[test]
#[serial]
fn init_logging_whitespace_file_path_falls_back_to_stderr() {
    let config = LoggingConfig { file_path: Some("   ".to_string()), ..LoggingConfig::default() };
    init_logging(&config).expect("whitespace-only path must be treated as unset");
}

/// An unopenable target (a directory) surfaces the open error instead of
/// panicking; the root path also has no parent directory.
#[test]
#[serial]
fn init_logging_unopenable_file_path_returns_error() {
    let config = LoggingConfig { file_path: Some("/".to_string()), ..LoggingConfig::default() };
    let err = init_logging(&config).expect_err("a directory is not a writable log target");
    assert!(err.to_string().to_lowercase().contains("directory"), "error should come from the open call: {err}");
}

// ============ Level Filtering Tests ============

/// `init_logging` maps every accepted level string onto `log::max_level`; the
/// fallback for unknown strings is `Info`.
#[test]
#[serial]
fn init_logging_maps_every_level_string_to_max_level() {
    let cases = [
        ("trace", log::LevelFilter::Trace),
        ("debug", log::LevelFilter::Debug),
        ("info", log::LevelFilter::Info),
        ("warn", log::LevelFilter::Warn),
        ("error", log::LevelFilter::Error),
        ("off", log::LevelFilter::Off),
        ("WARN", log::LevelFilter::Warn),
        ("not-a-level", log::LevelFilter::Info),
    ];

    for (level, expected) in cases {
        let config = LoggingConfig { level: level.to_string(), ..LoggingConfig::default() };
        init_logging(&config).expect("init_logging should accept every level string");
        assert_eq!(log::max_level(), expected, "level string '{level}' must map to {expected:?}");
    }

    // Leave the process-global max level at the library default for later tests.
    init_logging(&LoggingConfig::default()).expect("reset logging");
}

/// Records below the configured level are dropped by the logger itself, not only
/// by the `log` facade macros (the file target keeps its own filter).
#[test]
#[serial]
fn write_record_drops_records_below_configured_level() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("level-filter.log");
    let config = LoggingConfig {
        level: "warn".to_string(),
        format: "text".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: false,
        rotation: LogRotationConfig::default(),
        file_mode: 0o600,
    };
    init_logging(&config).expect("init_logging should succeed");

    // Bypass the facade's own max-level check so the record reaches the logger
    // and its internal level filter is exercised.
    log::set_max_level(log::LevelFilter::Trace);
    log::info!("dropped-because-below-level");
    log::warn!("kept-by-level-filter");
    log::logger().flush();
    log::set_max_level(log::LevelFilter::Info);

    let content = fs::read_to_string(&log_file).expect("read log file");
    assert!(content.contains("kept-by-level-filter"), "warn record must be written; got: {content:?}");
    assert!(
        !content.contains("dropped-because-below-level"),
        "info record below the configured level must be dropped; got: {content:?}"
    );
}

/// `RouterLogger::enabled` reports whether a level passes the global max level.
#[test]
#[serial]
fn router_logger_enabled_compares_against_max_level() {
    init_logging(&LoggingConfig { level: "info".to_string(), ..LoggingConfig::default() })
        .expect("init_logging should succeed");

    let mut builder = log::MetadataBuilder::new();
    builder.level(log::Level::Info);
    builder.target("logging_tests");
    let metadata = builder.build();
    assert!(log::logger().enabled(&metadata), "info must be enabled at max level info");

    let mut builder = log::MetadataBuilder::new();
    builder.level(log::Level::Debug);
    builder.target("logging_tests");
    let metadata = builder.build();
    assert!(!log::logger().enabled(&metadata), "debug must be disabled at max level info");
}

// ============ Rotation / Compression Tests ============

/// Gzip rotation: each archived generation is compressed to `<file>.N.gz`, the
/// uncompressed generation is removed, and existing archives are shifted up.
#[test]
#[serial]
fn rotation_with_gzip_compresses_archives_and_shifts_generations() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("rbs-gzip.log");

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: true,
        rotation: LogRotationConfig {
            max_file_size_bytes: 1024,
            max_files: 3,
            compression: RotationCompression::Gzip,
            file_mode: 0o440,
        },
        file_mode: 0o600,
    };
    init_logging(&config).expect("init_logging should succeed");

    // Enough lines for several rotations (each line is well under 100 bytes).
    for i in 0..200 {
        log::info!("gzip rotation test line number {} with some padding", i);
    }
    log::logger().flush();

    let archive = dir.path().join("rbs-gzip.log.1.gz");
    assert!(archive.exists(), "first gzip archive should exist: {archive:?}");
    let shifted = dir.path().join("rbs-gzip.log.2.gz");
    assert!(shifted.exists(), "older gzip archive should be shifted to .2.gz: {shifted:?}");
    assert!(
        !dir.path().join("rbs-gzip.log.1").exists(),
        "the uncompressed generation must be removed after compression"
    );

    let bytes = fs::read(&archive).expect("read gzip archive");
    assert!(bytes.len() > 2, "gzip archive must not be empty");
    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "archive must carry the gzip magic header");
}

// ============ Log Injection Tests ============

/// Payload shaped like the verified #33 vector: an unauthenticated JWT `sub`
/// claim smuggled into a warn log, attempting to forge a follow-up log line
/// that looks like a legitimate later event (here: a successful admin login).
const FORGED_SUB: &str = "alice\n2026-01-01 00:00:00  INFO - admin login success\r\u{2028}fake";

/// Plain-text output must keep one record on one line: CR/LF and the Unicode
/// line separators in untrusted message content are escaped, so the forged
/// "admin login success" line cannot appear as its own log line.
#[test]
#[serial]
fn plain_text_log_escapes_line_breaks_in_message() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("log-injection.log");

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "text".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: false,
        rotation: LogRotationConfig::default(),
        file_mode: 0o600,
    };

    init_logging(&config).expect("init_logging should succeed");
    log::warn!("token validation failed for sub={FORGED_SUB}");
    log::logger().flush();

    let content = fs::read_to_string(&log_file).unwrap();
    assert_eq!(
        content.matches('\n').count(),
        1,
        "one record must be exactly one line (trailing newline only); got: {content:?}"
    );
    assert!(!content.contains('\r'), "no raw CR may reach the file; got: {content:?}");
    assert!(!content.contains('\u{2028}'), "no raw U+2028; got: {content:?}");
    assert!(
        content.contains("token validation failed for sub=alice"),
        "readable message prefix intact; got: {content:?}"
    );
    assert!(
        content.contains("alice\\n2026-01-01"),
        "forged line stays visibly escaped in place; got: {content:?}"
    );
}

/// JSON output must keep the same forged payload inside one parseable record
/// (serde_json escaping inside the message string; no sanitization needed).
#[test]
#[serial]
fn json_log_keeps_forged_message_in_one_record() {
    let dir = tempdir().expect("create temp dir");
    let log_file = dir.path().join("log-injection.json");

    let config = LoggingConfig {
        level: "info".to_string(),
        format: "json".to_string(),
        file_path: Some(log_file.to_string_lossy().to_string()),
        enable_rotation: false,
        rotation: LogRotationConfig::default(),
        file_mode: 0o600,
    };

    init_logging(&config).expect("init_logging should succeed");
    log::warn!("token validation failed for sub={FORGED_SUB}");
    log::logger().flush();

    let content = fs::read_to_string(&log_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 1, "one record per line; got {} lines", lines.len());
    let record: serde_json::Value =
        serde_json::from_str(lines[0]).expect("line must be a single parseable JSON record");
    assert_eq!(record["message"], format!("token validation failed for sub={FORGED_SUB}"));
}

// ============ Stderr Tests ============

#[cfg(unix)]
mod unix {
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::io::FromRawFd;

    use super::*;

    struct RestoreStderr(libc::c_int);

    impl Drop for RestoreStderr {
        fn drop(&mut self) {
            unsafe {
                let _ = libc::dup2(self.0, libc::STDERR_FILENO);
                let _ = libc::close(self.0);
            }
        }
    }

    fn capture_stderr_while(f: impl FnOnce()) -> Vec<u8> {
        let mut fds: [libc::c_int; 2] = [0, 0];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe() for stderr capture");
        let read_fd = fds[0];
        let write_fd = fds[1];

        let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
        assert!(saved_stderr >= 0, "dup(STDERR_FILENO)");

        assert_eq!(unsafe { libc::dup2(write_fd, libc::STDERR_FILENO) }, libc::STDERR_FILENO, "dup2(pipe, STDERR)");
        unsafe {
            libc::close(write_fd);
        }

        {
            let _restore = RestoreStderr(saved_stderr);
            f();
        }

        let mut pipe_read = unsafe { File::from_raw_fd(read_fd) };
        let mut buf = Vec::new();
        pipe_read.read_to_end(&mut buf).expect("read captured stderr");
        buf
    }

    #[test]
    #[serial]
    fn init_logging_stderr_contains_log_message() {
        const MARKER: &str = "logging_stderr_test_marker_xyz";

        let captured = capture_stderr_while(|| {
            let config = LoggingConfig::default();
            init_logging(&config).expect("init_logging to stderr should succeed");
            log::info!("{MARKER}");
            log::logger().flush();
        });

        let text = String::from_utf8_lossy(&captured);
        assert!(text.contains(MARKER), "stderr must contain the log line; got: {text:?}");
    }
}

#[cfg(not(unix))]
#[test]
#[serial]
fn init_logging_stderr_succeeds_without_file_path() {
    let config = LoggingConfig::default();
    init_logging(&config).expect("init_logging without file_path should succeed");
    log::info!("logging_stderr_test message");
    log::logger().flush();
}

// ============ Permissions Tests ============

#[cfg(unix)]
mod permissions {
    use super::*;

    use std::os::unix::fs::PermissionsExt;

    /// When configured without rotation, the created log file must respect the configured
    /// file mode on Unix platforms.
    #[test]
    #[serial]
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

    /// Rotated archives must honour the configured rotation file mode on Unix platforms.
    #[test]
    #[serial]
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
}


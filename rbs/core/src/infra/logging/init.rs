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

//! Logging initialization.

use std::borrow::Cow;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
use std::time::SystemTime;

use flate2::write::GzEncoder;
use flate2::Compression;
use log::{Log, Metadata, Record};
use rbs_api_types::config::{LoggingConfig, RotationCompression};

static STATE: Mutex<Option<Arc<Mutex<LoggerInner>>>> = Mutex::new(None);
static INIT_LOGGER: Once = Once::new();

/// Logger inner state.
struct LoggerInner {
    level_filter: log::LevelFilter,
    /// Active log file when `file_path` is set; `None` means stderr only.
    active_file: Option<File>,
    bytes_written: u64,
    path: Option<PathBuf>,
    config: LoggingConfig,
}

impl LoggerInner {
    fn open(config: &LoggingConfig) -> anyhow::Result<Self> {
        let level_filter = parse_level_filter(&config.level);
        if let Some(ref p) = config.file_path {
            if !p.trim().is_empty() {
                let path = PathBuf::from(p);
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        anyhow::bail!("log directory does not exist: {}", parent.display());
                    }
                }
                let file = OpenOptions::new().create(true).append(true).open(&path)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = config.file_mode & 0o777;
                    let mut perms = file.metadata()?.permissions();
                    perms.set_mode(mode);
                    fs::set_permissions(&path, perms)?;
                }
                let bytes_written = file.metadata()?.len();
                return Ok(Self {
                    level_filter,
                    active_file: Some(file),
                    bytes_written,
                    path: Some(path),
                    config: config.clone(),
                });
            }
        }
        Ok(Self { level_filter, active_file: None, bytes_written: 0, path: None, config: config.clone() })
    }

    fn write_record(&mut self, record: &Record<'_>) -> io::Result<()> {
        if record.level() > self.level_filter {
            return Ok(());
        }
        let line = format_line(record, &self.config);
        let line_len = line.len() as u64;

        if self.path.is_some() {
            if self.config.enable_rotation && self.config.rotation.max_file_size_bytes > 0 {
                if self.bytes_written + line_len > self.config.rotation.max_file_size_bytes {
                    self.rotate_current_file()?;
                }
            }
            if let Some(f) = &mut self.active_file {
                f.write_all(line.as_bytes())?;
                self.bytes_written += line_len;
                f.flush()?;
            }
        } else {
            let mut s = io::stderr().lock();
            s.write_all(line.as_bytes())?;
            s.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(f) = &mut self.active_file {
            f.flush()?;
        }
        Ok(())
    }

    fn rotate_current_file(&mut self) -> io::Result<()> {
        let path = match &self.path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };
        // Close handle so rename works on all platforms.
        self.active_file = None;

        let max = self.config.rotation.max_files.max(1);

        for i in (1..max).rev() {
            let from = numbered_path(&path, i);
            let to = numbered_path(&path, i + 1);
            if from.exists() {
                let _ = fs::rename(&from, &to);
            }
            let from_gz = gz_path(&path, i);
            let to_gz = gz_path(&path, i + 1);
            if from_gz.exists() {
                let _ = fs::rename(&from_gz, &to_gz);
            }
        }

        if path.exists() {
            let first = numbered_path(&path, 1);
            fs::rename(&path, &first)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = self.config.rotation.file_mode & 0o777;
                let mut perms = fs::metadata(&first)?.permissions();
                perms.set_mode(mode);
                fs::set_permissions(&first, perms)?;
            }

            if self.config.rotation.compression == RotationCompression::Gzip {
                let gz_path = gz_path(&path, 1);
                let data = fs::read(&first)?;
                let gz_file = File::create(&gz_path)?;
                let mut enc = GzEncoder::new(gz_file, Compression::default());
                enc.write_all(&data)?;
                enc.finish()?;
                fs::remove_file(&first)?;
            }
        }

        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = self.config.file_mode & 0o777;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(mode);
            fs::set_permissions(&path, perms)?;
        }
        self.bytes_written = file.metadata()?.len();
        self.active_file = Some(file);
        Ok(())
    }
}

fn numbered_path(base: &Path, n: u32) -> PathBuf {
    PathBuf::from(format!("{}.{}", base.display(), n))
}

fn gz_path(base: &Path, n: u32) -> PathBuf {
    PathBuf::from(format!("{}.{}.gz", base.display(), n))
}

fn format_timestamp(time: &SystemTime) -> String {
    let duration = time.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();
    let datetime = chrono::DateTime::from_timestamp(secs as i64, 0)
        .unwrap_or_default();
    let local: chrono::DateTime<chrono::Local> = chrono::DateTime::from(datetime);
    local.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Escape line-break characters in a log message so untrusted values
/// interpolated into it (e.g. a JWT `sub` claim from an unauthenticated
/// request, or a path parameter) cannot forge additional log lines in the
/// plain-text format (log injection, CWE-117). The escapes are visible
/// (`\n`, `\r`, `\u2028`, `\u2029`) to preserve the information.
///
/// The JSON branch of `format_line` needs no such pre-escaping: `serde_json`
/// escapes CR/LF and quotes inside the message string, so a message can never
/// break out of its own JSON record.
fn sanitize_plain_text_message(msg: &str) -> Cow<'_, str> {
    if !msg.chars().any(|c| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')) {
        return Cow::Borrowed(msg);
    }
    let mut out = String::with_capacity(msg.len() + 16);
    for c in msg.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

fn format_line(record: &Record<'_>, config: &LoggingConfig) -> String {
    let timestamp = format_timestamp(&std::time::SystemTime::now());
    if config.format.eq_ignore_ascii_case("json") {
        let msg = record.args().to_string();
        let level = format!("{:?}", record.level());
        format!("{{\"level\":\"{level}\",\"timestamp\":\"{timestamp}\",\"message\":{}}}\n", serde_json::json!(msg))
    } else {
        // See `sanitize_plain_text_message`: the message is the only
        // attacker-influenced part of the line (level and timestamp are
        // generated here), and it must not be able to forge new lines.
        let raw_msg = record.args().to_string();
        let msg = sanitize_plain_text_message(&raw_msg);
        format!("{} {} - {}\n", timestamp, record.level(), msg)
    }
}

struct RouterLogger;

impl Log for RouterLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if let Ok(guard) = STATE.lock() {
            if let Some(inner) = guard.as_ref() {
                if let Ok(mut w) = inner.lock() {
                    let _ = w.write_record(record);
                }
            }
        }
    }

    fn flush(&self) {
        if let Ok(guard) = STATE.lock() {
            if let Some(inner) = guard.as_ref() {
                if let Ok(mut w) = inner.lock() {
                    let _ = w.flush();
                }
            }
        }
    }
}

static ROUTER: RouterLogger = RouterLogger;

/// Initialize `log` with file or stderr output according to `config`.
pub fn init_logging(config: &LoggingConfig) -> anyhow::Result<()> {
    let inner = Arc::new(Mutex::new(LoggerInner::open(config)?));
    {
        let mut g = STATE.lock().map_err(|_| anyhow::anyhow!("STATE poisoned"))?;
        *g = Some(inner);
    }

    log::set_max_level(parse_level_filter(&config.level));

    INIT_LOGGER.call_once(|| {
        log::set_logger(&ROUTER).expect("set_logger");
    });

    Ok(())
}

fn parse_level_filter(s: &str) -> log::LevelFilter {
    match s.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        "off" => log::LevelFilter::Off,
        _ => log::LevelFilter::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_config() -> LoggingConfig {
        LoggingConfig { format: "text".to_string(), ..LoggingConfig::default() }
    }

    fn json_config() -> LoggingConfig {
        LoggingConfig { format: "json".to_string(), ..LoggingConfig::default() }
    }

    /// Build a record from `msg` and render it. The record construction and
    /// the `format_line` call must stay in one expression: `format_args!`
    /// creates temporary arrays whose borrow ends with the enclosing
    /// statement, so an intermediate `let record = ...` binding would dangle.
    fn line_for(msg: &str, config: &LoggingConfig) -> String {
        format_line(
            &Record::builder()
                .args(format_args!("{}", msg))
                .level(log::Level::Warn)
                .target("sanitize_test")
                .build(),
            config,
        )
    }

    #[test]
    fn sanitize_clean_message_is_borrowed_unchanged() {
        let clean = "auth failed for sub=alice (reason: bad signature)";
        let sanitized = sanitize_plain_text_message(clean);
        assert!(matches!(sanitized, Cow::Borrowed(s) if s == clean));
    }

    #[test]
    fn sanitize_escapes_each_line_break_char_visibly() {
        assert_eq!(sanitize_plain_text_message("a\nb"), "a\\nb");
        assert_eq!(sanitize_plain_text_message("a\rb"), "a\\rb");
        assert_eq!(sanitize_plain_text_message("a\u{2028}b"), "a\\u2028b");
        assert_eq!(sanitize_plain_text_message("a\u{2029}b"), "a\\u2029b");
        // Mixed, including CRLF pairs used for classic log forging.
        assert_eq!(
            sanitize_plain_text_message("x\r\n2026-01-01 00:00:00 INFO - forged\u{2028}y"),
            "x\\r\\n2026-01-01 00:00:00 INFO - forged\\u2028y",
        );
    }

    /// The plain-text branch must emit exactly one line for one record, no
    /// matter what the message contains — a forged timestamp/level line
    /// smuggled in via CR/LF stays inside the single message field.
    #[test]
    fn format_line_plain_text_escapes_forged_newlines() {
        let forged = "user\r\n2026-01-01 00:00:00  INFO - admin login ok\u{2028}fake";
        let line = line_for(forged, &plain_config());
        assert_eq!(line.matches('\n').count(), 1, "only the trailing newline; got: {line:?}");
        assert!(!line.contains('\r'), "no raw CR; got: {line:?}");
        assert!(!line.contains('\u{2028}'), "no raw U+2028; got: {line:?}");
        assert!(line.contains("WARN - user"), "level/prefix intact; got: {line:?}");
        assert!(
            line.contains("user\\r\\n2026-01-01"),
            "forged content stays visibly escaped in place; got: {line:?}"
        );
    }

    /// The JSON branch keeps the same forged message inside one parseable
    /// record via serde_json escaping (no pre-escaping needed there).
    #[test]
    fn format_line_json_keeps_forged_message_in_one_record() {
        let forged = "user\r\n2026-01-01 00:00:00  INFO - admin login ok";
        let line = line_for(forged, &json_config());
        assert!(line.ends_with('\n'));
        let record: serde_json::Value =
            serde_json::from_str(line.trim_end()).expect("one parseable JSON record");
        assert_eq!(record["level"], "Warn");
        assert_eq!(record["message"], forged);
    }
}

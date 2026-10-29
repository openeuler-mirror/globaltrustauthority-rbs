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

//! Integration tests for the `rbs-cli` binary entry point (`src/bin/main.rs`) and the
//! `tracing` initialisation it relies on (`src/common/logging.rs`).
//!
//! The binary is spawned as a child process (`CARGO_BIN_EXE_rbs-cli`), because the entry point
//! installs a process-global subscriber and maps results to `ExitCode`, neither of which is
//! observable in-process. Each case runs in its own process, so every `init_logging` branch
//! (`default`, `verbose`, `quiet`, `RUST_LOG`) is exercised exactly once.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Upper bound for a single child invocation; every covered case fails fast or exits at once.
const CHILD_TIMEOUT: Duration = Duration::from_secs(60);

/// Base URL pointing at a closed loopback port: subcommands fail without network round-trips.
const UNREACHABLE_BASE_URL: &str = "http://127.0.0.1:1";

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Minimal unique temporary directory helper (the crate has no `tempfile` dev-dependency).
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("system time").as_nanos();
        let path = std::env::temp_dir().join(format!("rbs-cli-{prefix}-{nanos}-{unique}"));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Build a command for the `rbs-cli` binary with a deterministic environment: every
/// `RBS_*`/`RUST_LOG` variable that influences `resolve_global_options` or `init_logging` is
/// cleared, so ambient settings cannot change the outcome.
fn cli_command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rbs-cli"));
    cmd.args(args)
        .env_remove("RBS_BASE_URL")
        .env_remove("RBS_TOKEN")
        .env_remove("RBS_CERT")
        .env_remove("RBS_FORMAT")
        .env_remove("RUST_LOG")
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::null());
    cmd
}

/// Drain a child pipe to completion on a background thread.
fn spawn_pipe_reader<R: Read + Send + 'static>(mut pipe: R) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// Remove ANSI SGR sequences so log assertions do not depend on coloured output.
///
/// `tracing-subscriber` emits ANSI escapes even when stderr is a pipe, so CI output
/// contains sequences such as `source\u{1b}[0m\u{1b}[2m=\u{1b}[0mverbose`.
fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            // Skip parameter bytes, then consume the final byte of the CSI sequence.
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        }
    }
    out
}

/// Run a prepared command, returning its exit status plus captured stdout/stderr.
fn run_with_output(mut cmd: Command) -> (ExitStatus, String, String) {
    let mut child: Child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rbs-cli binary");
    let stdout = spawn_pipe_reader(child.stdout.take().expect("stdout pipe"));
    let stderr = spawn_pipe_reader(child.stderr.take().expect("stderr pipe"));

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("poll child status") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("rbs-cli child did not exit within {CHILD_TIMEOUT:?}");
            },
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    (
        status,
        strip_ansi(&stdout.join().expect("stdout reader")),
        strip_ansi(&stderr.join().expect("stderr reader")),
    )
}

/// Run `rbs-cli <args>` with the default environment.
fn run(args: &[&str]) -> (ExitStatus, String, String) {
    run_with_output(cli_command(args))
}

/// `--help` is handled by clap before `main`'s body runs.
#[test]
fn help_lists_commands_and_exits_zero() {
    let (status, stdout, stderr) = run(&["--help"]);
    assert!(status.success(), "--help must exit 0, got {status:?}; stderr: {stderr}");
    assert!(stdout.contains("Usage: rbs-cli"), "help should show usage, got: {stdout}");
    assert!(stdout.contains("version"), "help should list the version command, got: {stdout}");
}

/// `arg_required_else_help` makes a bare invocation print usage and exit non-zero.
#[test]
fn no_arguments_prints_usage_and_exits_nonzero() {
    let (status, stdout, stderr) = run(&[]);
    assert!(!status.success(), "bare invocation must fail, got {status:?}");
    let text = format!("{stdout}{stderr}");
    assert!(text.contains("Usage: rbs-cli"), "usage should be printed, got: {text}");
}

/// `version` renders through `emit_output` in text mode and exits 0.
#[test]
fn version_command_prints_name_and_version() {
    let (status, stdout, stderr) = run(&["version"]);
    assert!(status.success(), "version must exit 0, got {status:?}; stderr: {stderr}");
    assert_eq!(
        stdout.trim(),
        format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        "unexpected version text"
    );
}

/// `--format json` drives the JSON branch of `emit_output`.
#[test]
fn version_command_json_format_renders_json() {
    let (status, stdout, stderr) = run(&["--format", "json", "version"]);
    assert!(status.success(), "version --format json must exit 0, got {status:?}; stderr: {stderr}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["name"], env!("CARGO_PKG_NAME"));
    assert_eq!(parsed["version"], env!("CARGO_PKG_VERSION"));
}

/// `--quiet` selects the `Quiet` log level source and suppresses the rendered output.
#[test]
fn quiet_flag_suppresses_command_output() {
    let (status, stdout, stderr) = run(&["--quiet", "version"]);
    assert!(status.success(), "-q version must exit 0, got {status:?}; stderr: {stderr}");
    assert!(stdout.is_empty(), "quiet mode must not print the result, got: {stdout}");
    assert!(!stderr.contains("starting rbs-cli"), "quiet mode must not log info lines, got: {stderr}");
}

/// `--verbose` selects the `Verbose` log level source and logs the startup lines.
#[test]
fn verbose_flag_logs_startup_lines() {
    let (status, stdout, stderr) = run(&["--verbose", "version"]);
    assert!(status.success(), "-v version must exit 0, got {status:?}; stderr: {stderr}");
    assert!(stdout.contains(env!("CARGO_PKG_NAME")), "verbose mode still prints the result, got: {stdout}");
    assert!(stderr.contains("starting rbs-cli"), "verbose mode should log startup, got: {stderr}");
    assert!(stderr.contains("source=verbose"), "startup log should report the verbose source, got: {stderr}");
    assert!(stderr.contains("resolved global options"), "verbose mode should log resolved options, got: {stderr}");
}

/// `RUST_LOG` selects the `RustLog` source and installs an `EnvFilter` from the environment.
#[test]
fn rust_log_env_selects_rust_log_source() {
    let mut cmd = cli_command(&["version"]);
    cmd.env("RUST_LOG", "debug");
    let (status, stdout, stderr) = run_with_output(cmd);
    assert!(status.success(), "version with RUST_LOG must exit 0, got {status:?}; stderr: {stderr}");
    assert!(stdout.contains(env!("CARGO_PKG_NAME")), "result should still be printed, got: {stdout}");
    assert!(stderr.contains("starting rbs-cli"), "RUST_LOG=debug should log startup, got: {stderr}");
    assert!(stderr.contains("source=rust_log"), "startup log should report the rust_log source, got: {stderr}");
}

/// An unknown subcommand is rejected by clap with a non-zero exit.
#[test]
fn unknown_subcommand_is_rejected() {
    let (status, _stdout, stderr) = run(&["definitely-not-a-subcommand"]);
    assert!(!status.success(), "unknown subcommand must fail, got {status:?}");
    assert!(stderr.contains("unrecognized subcommand"), "stderr should explain the rejection, got: {stderr}");
}

/// An invalid `RBS_BASE_URL` is not covered by clap's value parsers, so
/// `resolve_global_options` fails and `main` reports it through `emit_err`.
#[test]
fn invalid_base_url_env_reports_resolution_error() {
    let mut cmd = cli_command(&["version"]);
    cmd.env("RBS_BASE_URL", "not-a-url");
    let (status, stdout, stderr) = run_with_output(cmd);
    assert!(!status.success(), "invalid RBS_BASE_URL must fail, got {status:?}");
    assert!(stdout.is_empty(), "no output should be rendered on failure, got: {stdout}");
    assert!(stderr.contains("failed to resolve global options"), "stderr should log the failure, got: {stderr}");
    assert!(stderr.contains("Error: invalid url"), "stderr should carry the user-facing error, got: {stderr}");
}

/// A result that cannot be written drives the `emit_output` error branch of `main`.
#[test]
fn unwritable_output_file_reports_error() {
    let dir = TempDir::new("missing-parent");
    let output_file = dir.path().join("absent-dir").join("out.txt");
    let (status, stdout, stderr) = run(&["--output-file", output_file.to_str().expect("utf-8 path"), "version"]);
    assert!(!status.success(), "unwritable output file must fail, got {status:?}");
    assert!(stdout.is_empty(), "failure must not print to stdout, got: {stdout}");
    assert!(stderr.contains("Error:"), "stderr should carry the error, got: {stderr}");
}

/// Every non-version subcommand is dispatched through its own arm of `main`; with an
/// unreachable base URL (or missing inputs) each one fails fast instead of hanging.
///
/// The cases run with `--verbose` so the startup `info!` event is enabled: its
/// `command = command_name(..)` field is only evaluated for enabled events, which is what
/// exercises the `command_name` arms for every variant.
#[test]
fn every_subcommand_is_dispatched() {
    let dir = TempDir::new("token-key");
    let invalid_key = dir.path().join("invalid_private_key.pem");
    fs::write(&invalid_key, b"not a private key\n").expect("write invalid key");

    let cases: [(&str, Vec<&str>); 9] = [
        ("cert", vec!["-b", UNREACHABLE_BASE_URL, "--verbose", "cert", "list"]),
        ("client", vec!["-b", UNREACHABLE_BASE_URL, "--verbose", "client", "challenge"]),
        ("policy", vec!["-b", UNREACHABLE_BASE_URL, "--verbose", "policy", "list"]),
        ("ref-value", vec!["-b", UNREACHABLE_BASE_URL, "--verbose", "ref-value", "list"]),
        (
            "res",
            vec!["-b", UNREACHABLE_BASE_URL, "--verbose", "res", "get-res-info", "--uri", "vault/default/secret/smoke"],
        ),
        ("res-policy", vec!["-b", UNREACHABLE_BASE_URL, "--verbose", "res-policy", "list"]),
        (
            "token",
            vec![
                "-b",
                UNREACHABLE_BASE_URL,
                "--verbose",
                "token",
                "gen",
                "--private-key-file",
                invalid_key.to_str().expect("utf-8 path"),
            ],
        ),
        ("user", vec!["-b", UNREACHABLE_BASE_URL, "--verbose", "user", "list"]),
        ("version", vec!["-b", UNREACHABLE_BASE_URL, "version"]),
    ];

    for (name, args) in cases {
        let (status, stdout, stderr) = run(&args);
        if name == "version" {
            assert!(status.success(), "version dispatch must succeed, got {status:?}; stderr: {stderr}");
            assert!(stdout.contains(env!("CARGO_PKG_NAME")), "version output missing for {name}: {stdout}");
            continue;
        }
        assert!(!status.success(), "`{name}` must fail without a server, got {status:?}; stdout: {stdout}");
        assert!(stderr.contains("Error:"), "`{name}` should report an error, got: {stderr}");
    }
}

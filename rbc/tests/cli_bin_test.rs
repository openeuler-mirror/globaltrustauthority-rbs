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

//! Integration tests for the `rbc-cli` binary entry point (`src/bin/main.rs`).
//!
//! The entry point installs a process-global `tracing` subscriber and parses the real process
//! arguments, neither of which is observable in-process, so every case spawns the binary
//! (`CARGO_BIN_EXE_rbc-cli`) as a child process. Each invocation gets its own process and
//! therefore exercises exactly one `run()` path.
//!
//! Subprocess coverage is merged by the coverage tooling only when the child inherits the
//! parent environment (notably `LLVM_PROFILE_FILE`), so the spawned commands never clear the
//! inherited environment.

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Upper bound for a single child invocation; every case fails fast without network I/O.
const CHILD_TIMEOUT: Duration = Duration::from_secs(60);

/// Base URL pointing at a closed loopback port: commands fail without a network round-trip.
const UNREACHABLE_BASE_URL: &str = "http://127.0.0.1:1";

/// Partial attestation agent config shipped with the crate; it exists on disk so the
/// `--agent-config` value parser accepts it, but it cannot initialise the agent.
const AGENT_CONFIG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/agent_config.yaml");

/// Build a command for the `rbc-cli` binary, inheriting the parent environment.
fn cli_command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rbc-cli"));
    cmd.args(args).current_dir(std::env::temp_dir()).stdin(Stdio::null());
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

/// Run a prepared command, returning its exit status plus captured stdout/stderr.
fn run_with_output(mut cmd: Command) -> (ExitStatus, String, String) {
    let mut child: Child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn rbc-cli binary");
    let stdout = spawn_pipe_reader(child.stdout.take().expect("stdout pipe"));
    let stderr = spawn_pipe_reader(child.stderr.take().expect("stderr pipe"));

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("poll child status") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("rbc-cli child did not exit within {CHILD_TIMEOUT:?}");
            },
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    (status, stdout.join().expect("stdout reader"), stderr.join().expect("stderr reader"))
}

/// Run `rbc-cli <args>`.
fn run(args: &[&str]) -> (ExitStatus, String, String) {
    run_with_output(cli_command(args))
}

/// `--help` is handled by clap inside `Cli::parse`, before the rest of `run()` executes.
#[test]
fn help_lists_commands_and_exits_zero() {
    let (status, stdout, stderr) = run(&["--help"]);
    assert!(status.success(), "--help must exit 0, got {status:?}; stderr: {stderr}");
    assert!(stdout.contains("Run RBC CLI commands"), "help should show the about text, got: {stdout}");
    assert!(stdout.contains("challenge"), "help should list the challenge command, got: {stdout}");
    assert!(stdout.contains("get-resource"), "help should list the get-resource command, got: {stdout}");
}

/// A command whose provider initialisation fails must report the error from `run()` and exit
/// non-zero, exercising the `execute_action` error path together with the startup log line.
#[test]
fn challenge_reports_provider_init_failure() {
    let (status, stdout, stderr) =
        run(&["-b", UNREACHABLE_BASE_URL, "challenge", "--agent-config", AGENT_CONFIG]);
    assert!(!status.success(), "uninitialisable providers must fail, got {status:?}");
    assert!(stdout.is_empty(), "failed commands must not render output, got: {stdout}");
    assert!(stderr.contains("Error:"), "stderr should carry the error, got: {stderr}");
    assert!(
        stderr.contains("attestation_client init failed"),
        "stderr should carry the provider init error, got: {stderr}"
    );
}

/// Every accepted `--key-algorithm` value reaches its own arm of `parse_key_algorithm`.
#[test]
fn challenge_accepts_every_key_algorithm() {
    for algorithm in ["rsa", "ec", "sm2"] {
        let (status, _stdout, stderr) = run(&[
            "-b",
            UNREACHABLE_BASE_URL,
            "--key-algorithm",
            algorithm,
            "challenge",
            "--agent-config",
            AGENT_CONFIG,
        ]);
        assert!(!status.success(), "--key-algorithm {algorithm} must parse and then fail on providers");
        assert!(
            stderr.contains("attestation_client init failed"),
            "--key-algorithm {algorithm} should reach the provider error, got: {stderr}"
        );
    }
}

/// An unknown key algorithm is rejected by the `parse_key_algorithm` error arm.
#[test]
fn invalid_key_algorithm_is_rejected() {
    let (status, stdout, stderr) =
        run(&["-b", UNREACHABLE_BASE_URL, "--key-algorithm", "dsa", "challenge", "--agent-config", AGENT_CONFIG]);
    assert!(!status.success(), "unknown key algorithm must be rejected, got {status:?}");
    assert!(stdout.is_empty(), "rejected arguments must not render output, got: {stdout}");
    assert!(
        stderr.contains("invalid key algorithm `dsa`"),
        "stderr should explain the rejection, got: {stderr}"
    );
}

/// `--quiet` lowers the log level to ERROR and hides the startup line.
#[test]
fn quiet_flag_suppresses_startup_log() {
    let (status, _stdout, stderr) = run(&[
        "-b",
        UNREACHABLE_BASE_URL,
        "--quiet",
        "challenge",
        "--agent-config",
        AGENT_CONFIG,
    ]);
    assert!(!status.success(), "provider init still fails in quiet mode");
    assert!(!stderr.contains("starting rbc-cli"), "quiet mode must not log info lines, got: {stderr}");
}

/// `--verbose` raises the log level to INFO and emits the startup line.
#[test]
fn verbose_flag_emits_startup_log() {
    let (status, _stdout, stderr) = run(&[
        "-b",
        UNREACHABLE_BASE_URL,
        "--verbose",
        "challenge",
        "--agent-config",
        AGENT_CONFIG,
    ]);
    assert!(!status.success(), "provider init still fails in verbose mode");
    assert!(stderr.contains("starting rbc-cli"), "verbose mode should log startup, got: {stderr}");
}

/// An invalid base URL is rejected by the `validate_base_url` value parser.
#[test]
fn invalid_base_url_is_rejected() {
    let (status, stdout, stderr) = run(&["--base-url", "ftp://rbs.example.com", "challenge"]);
    assert!(!status.success(), "invalid base URL must be rejected, got {status:?}");
    assert!(stdout.is_empty(), "rejected arguments must not render output, got: {stdout}");
    assert!(
        stderr.contains("base URL must use http or https"),
        "stderr should explain the rejection, got: {stderr}"
    );
}

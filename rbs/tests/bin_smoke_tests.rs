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

//! Integration tests for the `rbs` binary entry point (`src/bin/main.rs`).
//!
//! The binary is spawned as a child process (`CARGO_BIN_EXE_rbs`) so the real startup
//! sequence — config loading, validation, logging init, SQLite bootstrap/admin creation and
//! REST bind — is exercised. Every child terminates on its own:
//!
//! * `--help` exits before any work is done;
//! * a missing config file fails at load;
//! * an already-occupied `rest.listen_addr` fails at bind after bootstrap completed;
//! * a SIGTERM on a successfully started server triggers actix graceful shutdown, so the
//!   process exits normally with code 0.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Throwaway RSA-2048 public key used to satisfy `auth.attest_token.public_key_path` and
/// `admin.admin_key.public_key_path`. It is a public key from a key pair that was generated
/// only for these tests and then discarded, so it protects nothing.
const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsLciZ2WIz/mfYLzM4/31
4CLlQ61b5QlQ59Nu953odyUAT6OqzhzSBT2gXYnG4K6lQ0ObB0Q4BBfWm6LGcVX2
/nUEAXOpcAP0s3i+lVGXfia0iIVdr4QX0uE/4vHvSUmnRFIIVytCpGWP6nwE8D0t
nZVrWD5nC166xd87sP7SEbxxpZyuDRr90T/nlJ7nghDKpETz5ce2JqlUKplj4OOm
NgOZOGCARxB7zdgqRMUPi385wBvBbXlljNT3v+NtGCJLBH70yxpdxCri7hw/SMOb
PlXOjKI+rKRL91/DNCwg+VvUPaCOBBVPq/EbyNsj3Vfp5LksMJEfG6bCJ8cpTwT4
xQIDAQAB
-----END PUBLIC KEY-----
";

/// How long a child process may take before the test gives up and kills it.
const CHILD_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum time to wait for the server to accept connections on its listen address.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Absolute path of the SQLite schema applied at startup (`rbs/rdb_sql/sqlite_rbs.sql`).
fn sqlite_schema_path() -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("rdb_sql").join("sqlite_rbs.sql");
    assert!(path.is_file(), "expected SQLite schema at {}", path.display());
    path
}

/// Write the throwaway public key PEM into `dir` and return its path.
fn write_public_key(dir: &Path) -> PathBuf {
    let path = dir.join("rbs_smoke_pub.pem");
    std::fs::write(&path, TEST_PUBLIC_KEY_PEM).expect("write public key");
    path
}

/// Write a minimal but complete `rbs.yaml` into `dir`.
///
/// `listen_addr` is the string handed to `rest.listen_addr`; `db_name` names the SQLite file
/// created under `dir`. The database is created on first connect (`mode=rwc`), so the schema
/// in `rbs/rdb_sql/sqlite_rbs.sql` runs for real.
fn write_config(dir: &Path, listen_addr: &str, db_name: &str) -> PathBuf {
    let public_key = write_public_key(dir);
    write_config_with_admin_key(dir, listen_addr, db_name, &public_key)
}

/// Same as [`write_config`] but with an explicit `admin.admin_key.public_key_path`.
fn write_config_with_admin_key(dir: &Path, listen_addr: &str, db_name: &str, admin_key: &Path) -> PathBuf {
    let public_key = write_public_key(dir);
    let db_path = dir.join(db_name);
    let config = format!(
        r#"rest:
  listen_addr: "{listen_addr}"
logging:
  level: info
  format: text
auth:
  attest_token:
    public_key_path: "{public_key}"
    issuer: "Global Trust Authority"
  bearer_token:
    issuer: "rbs-cli"
    audience: "globaltrustauthority-rbs"
admin:
  max_users: 10
  admin_key:
    public_key_path: "{admin_key}"
attestation:
  default_as_provider: gta
  backends:
    gta:
      mode: rest
      rest:
        base_url: "http://127.0.0.1:9"
        timeout_secs: 5
        retries: 0
        tls_verify: false
        ca_file: ""
        credentials:
          user_id: "rbs-smoke"
storage:
  db_type: sqlite
  max_connections: 10
  timeout: 30
  url: "sqlite://{db_path}?mode=rwc"
  sql_file_path: "{sql_path}"
"#,
        listen_addr = listen_addr,
        public_key = public_key.display(),
        admin_key = admin_key.display(),
        db_path = db_path.display(),
        sql_path = sqlite_schema_path().display(),
    );
    let path = dir.join("rbs.yaml");
    std::fs::write(&path, config).expect("write config");
    path
}

/// Build a command for the `rbs` binary with a deterministic environment.
fn rbs_command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rbs"));
    cmd.args(args)
        .env_remove("RBS_CONFIG")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
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

/// Wait for `child` to exit while its pipes are drained; kill it if `timeout` elapses.
fn wait_with_output(mut child: Child, stdout: std::thread::JoinHandle<String>, stderr: std::thread::JoinHandle<String>)
    -> (ExitStatus, String, String) {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("poll child status") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("rbs child did not exit within {CHILD_TIMEOUT:?}");
            },
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    (status, stdout.join().expect("stdout reader"), stderr.join().expect("stderr reader"))
}

/// Run `client` to completion, returning exit status plus captured stdout/stderr.
fn run_with_output(mut cmd: Command) -> (ExitStatus, String, String) {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rbs binary");
    let stdout = spawn_pipe_reader(child.stdout.take().expect("stdout pipe"));
    let stderr = spawn_pipe_reader(child.stderr.take().expect("stderr pipe"));
    wait_with_output(child, stdout, stderr)
}

/// Bind an ephemeral loopback port and keep the listener so the port stays occupied.
fn occupied_loopback_addr() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    (listener, addr)
}

/// Reserve an ephemeral loopback port and release it so the child process can bind it.
fn free_loopback_addr() -> SocketAddr {
    let (listener, addr) = occupied_loopback_addr();
    drop(listener);
    addr
}

/// `rbs --help` prints usage and exits successfully before touching the config file.
#[test]
fn rbs_binary_help_exits_zero() {
    let (status, stdout, stderr) = run_with_output(rbs_command(&["--help"]));
    assert!(status.success(), "--help must exit 0, got {status:?}; stderr: {stderr}");
    assert!(stdout.contains("Usage: rbs"), "help should show usage, got: {stdout}");
    assert!(stdout.contains("--config"), "help should document --config, got: {stdout}");
}

/// A missing config file fails the `load_config` context in `main`.
#[test]
fn rbs_binary_missing_config_file_exits_nonzero() {
    let dir = TempDir::new().expect("temp dir");
    let missing = dir.path().join("absent.yaml");
    assert!(!missing.exists());

    let (status, _stdout, stderr) =
        run_with_output(rbs_command(&["--config", missing.to_str().expect("utf-8 path")]));
    assert!(!status.success(), "missing config must fail, got {status:?}");
    assert!(stderr.contains("load config from"), "stderr should carry the load context, got: {stderr}");
    assert!(stderr.contains("absent.yaml"), "stderr should name the config path, got: {stderr}");
}

/// After logging/database/admin bootstrap the server bind fails when the port is taken, which
/// terminates the process with an error instead of serving forever.
#[test]
fn rbs_binary_fails_when_listen_addr_is_occupied() {
    let dir = TempDir::new().expect("temp dir");
    let (_listener, addr) = occupied_loopback_addr();
    let config = write_config(dir.path(), &addr.to_string(), "occupied.sqlite");

    let (status, _stdout, stderr) =
        run_with_output(rbs_command(&["--config", config.to_str().expect("utf-8 path")]));
    assert!(!status.success(), "bind failure must exit non-zero, got {status:?}");
    assert!(stderr.contains("bind REST server"), "stderr should carry the bind context, got: {stderr}");
    assert!(stderr.contains(&addr.to_string()), "stderr should name the listen address, got: {stderr}");
    // Startup work before the bind ran to completion.
    assert!(stderr.contains("Database initialized successfully"), "stderr: {stderr}");
    assert!(stderr.contains("Admin bootstrap check completed"), "stderr: {stderr}");
    assert!(dir.path().join("occupied.sqlite").is_file(), "SQLite database should have been created");
}

/// Probe the version endpoint; a `200` answer proves the worker threads are already serving.
fn version_endpoint_ready(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let request = format!("GET /rbs/version HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        return false;
    }
    String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200")
}

/// Send SIGTERM to `pid`, preferring the standalone `kill` binary and falling back to the
/// shell builtin.
fn send_sigterm(pid: u32) -> bool {
    Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .map(|status| status.success())
        .unwrap_or_else(|_| {
            Command::new("sh")
                .arg("-c")
                .arg(format!("kill -TERM {pid}"))
                .status()
                .map(|status| status.success())
                .unwrap_or(false)
        })
}

/// One start → serve → SIGTERM → exit attempt.
///
/// Returns the exit status plus captured stdout/stderr, or an error string when the server never
/// became ready or could not be signalled.
fn serve_and_terminate(config: &Path, addr: SocketAddr) -> Result<(ExitStatus, String, String), String> {
    let mut cmd = rbs_command(&["--config", config.to_str().expect("utf-8 path")]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn rbs binary: {e}"))?;
    let stdout_reader = spawn_pipe_reader(child.stdout.take().expect("stdout pipe"));
    let stderr_reader = spawn_pipe_reader(child.stderr.take().expect("stderr pipe"));

    let startup_deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if version_endpoint_ready(addr) {
            break;
        }
        if let Some(status) = child.try_wait().expect("poll child status") {
            let stderr = stderr_reader.join().expect("stderr reader");
            let _ = stdout_reader.join();
            return Err(format!("rbs exited before serving {addr} ({status:?}); stderr: {stderr}"));
        }
        if Instant::now() >= startup_deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = stderr_reader.join().expect("stderr reader");
            let _ = stdout_reader.join();
            return Err(format!("rbs did not serve {addr} within {STARTUP_TIMEOUT:?}; stderr: {stderr}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // The OS signal handlers are registered by actix-server right after its worker threads are
    // spawned, so give the runtime a moment past the first served request before signalling.
    std::thread::sleep(Duration::from_millis(300));

    if !send_sigterm(child.id()) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = stderr_reader.join();
        let _ = stdout_reader.join();
        return Err("could not send SIGTERM to the rbs child".to_string());
    }

    let (status, stdout, stderr) = wait_with_output(child, stdout_reader, stderr_reader);
    Ok((status, stdout, stderr))
}

/// An unparsable admin public key makes `bootstrap_admin` fail; `main` must turn that into a
/// startup error rather than panicking.
#[test]
fn rbs_binary_fails_when_admin_key_is_unparsable() {
    let dir = TempDir::new().expect("temp dir");
    let bad_key = dir.path().join("bad_admin.pem");
    std::fs::write(&bad_key, b"not a public key\n").expect("write bad admin key");
    let addr = free_loopback_addr();
    let config = write_config_with_admin_key(dir.path(), &addr.to_string(), "bad_admin.sqlite", &bad_key);

    let (status, _stdout, stderr) =
        run_with_output(rbs_command(&["--config", config.to_str().expect("utf-8 path")]));
    assert!(!status.success(), "invalid admin key must fail startup, got {status:?}");
    assert!(stderr.contains("bootstrap admin user"), "stderr should carry the bootstrap context, got: {stderr}");
    assert!(stderr.contains("Public key"), "stderr should explain the key failure, got: {stderr}");
}

/// Start the server for real, then stop it with SIGTERM: the graceful shutdown path makes
/// `run()` return and `main` exit with code 0.
///
/// SIGTERM can land before actix-server installs its handler (the default disposition then
/// kills the child), so the scenario is retried on a fresh port before failing the test.
#[test]
fn rbs_binary_serves_until_sigterm_then_exits_zero() {
    let dir = TempDir::new().expect("temp dir");

    let mut last_failure = String::new();
    for attempt in 1..=3 {
        let addr = free_loopback_addr();
        let config = write_config(dir.path(), &addr.to_string(), "serve.sqlite");
        match serve_and_terminate(&config, addr) {
            Ok((status, stdout, stderr)) if status.success() => {
                assert!(!stdout.contains("Error"), "unexpected stdout: {stdout}");
                assert!(stderr.contains("RBS config loaded from"), "stderr should log config load, got: {stderr}");
                assert!(
                    stderr.contains("init table executed successfully"),
                    "stderr should log schema init, got: {stderr}"
                );
                assert!(
                    stderr.contains("Admin bootstrap check completed"),
                    "stderr should log bootstrap, got: {stderr}"
                );
                assert!(
                    stderr.contains("RBS REST server starting on"),
                    "stderr should log the start line, got: {stderr}"
                );
                assert!(
                    stderr.contains("RBS REST server listening on"),
                    "stderr should log the listen line, got: {stderr}"
                );
                assert!(dir.path().join("serve.sqlite").is_file(), "SQLite database should have been created");
                return;
            },
            Ok((status, _stdout, stderr)) => {
                last_failure = format!("attempt {attempt} exited with {status:?}; stderr: {stderr}");
            },
            Err(err) => last_failure = format!("attempt {attempt}: {err}"),
        }
    }
    panic!("rbs did not shut down gracefully after 3 attempts: {last_failure}");
}

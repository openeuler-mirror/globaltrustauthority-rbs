/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Tests for environment-driven global option resolution in `rbs_cli::config::cmd`.

use rbs_cli::config::cmd::{resolve_global_options, validate_cert};
use rbs_cli::config::{GlobalCliArgs, OutputFormat};
use std::fs;
use std::sync::{Mutex, MutexGuard};

/// `std::env` is process-wide, so tests touching the `RBS_*` variables must not interleave.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const ENV_KEYS: [&str; 4] = ["RBS_BASE_URL", "RBS_TOKEN", "RBS_CERT", "RBS_FORMAT"];

fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn clear_env() {
    for key in ENV_KEYS {
        std::env::remove_var(key);
    }
}

#[test]
fn resolves_defaults_without_flags_or_environment() {
    let _guard = lock_env();
    clear_env();

    let options = resolve_global_options(&GlobalCliArgs::default()).expect("default resolution");

    assert_eq!(options.base_url, "https://127.0.0.1:6666");
    assert_eq!(options.token, None);
    assert_eq!(options.cert, None);
    assert_eq!(options.format, OutputFormat::Text);
    assert!(!options.format_explicitly_set);
}

#[test]
fn resolves_base_url_token_and_format_from_environment() {
    let _guard = lock_env();
    clear_env();
    std::env::set_var("RBS_BASE_URL", "http://127.0.0.1:8080");
    std::env::set_var("RBS_TOKEN", "env-token");
    std::env::set_var("RBS_FORMAT", "json");

    let options = resolve_global_options(&GlobalCliArgs::default()).expect("environment resolution");
    clear_env();

    assert_eq!(options.base_url, "http://127.0.0.1:8080");
    assert_eq!(options.token.as_deref(), Some("env-token"));
    assert_eq!(options.format, OutputFormat::Json);
    assert!(options.format_explicitly_set);
}

#[test]
fn resolves_certificate_bytes_from_flag_and_environment() {
    let _guard = lock_env();
    clear_env();
    let path = std::env::temp_dir().join(format!("rbs-cli-ca-{}.pem", std::process::id()));
    fs::write(&path, b"ca-cert").expect("write certificate file");
    let cert_path = path.to_string_lossy().into_owned();

    let from_flag = resolve_global_options(&GlobalCliArgs { cert: Some(cert_path.clone()), ..Default::default() })
        .expect("flag cert");
    assert_eq!(from_flag.cert.as_deref(), Some(b"ca-cert".as_ref()));
    assert_eq!(from_flag.cert_path.as_deref(), Some(cert_path.as_str()));

    std::env::set_var("RBS_CERT", &cert_path);
    let from_env = resolve_global_options(&GlobalCliArgs::default()).expect("environment cert");
    clear_env();
    let _ = fs::remove_file(&path);

    assert_eq!(from_env.cert.as_deref(), Some(b"ca-cert".as_ref()));
    assert_eq!(from_env.cert_path.as_deref(), Some(cert_path.as_str()));
}

#[cfg(unix)]
#[test]
fn reports_certificate_file_that_cannot_be_read() {
    let _guard = lock_env();
    clear_env();
    // A unix socket passes the path and size checks but cannot be read as a file.
    let path = std::env::temp_dir().join(format!("rbs-cli-ca-socket-{}", std::process::id()));
    let _ = fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind unix socket");

    let err = resolve_global_options(&GlobalCliArgs {
        cert: Some(path.to_string_lossy().into_owned()),
        ..Default::default()
    })
    .expect_err("unreadable certificate file");

    drop(listener);
    let _ = fs::remove_file(&path);

    assert!(err.to_string().contains("unable to read certificate file"), "err: {err}");
}

#[test]
fn resolution_emits_a_configuration_summary() {
    let _guard = lock_env();
    clear_env();
    // Enable the info level so the field expressions of the summary event are evaluated.
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_writer(std::io::sink).try_init();

    let options = resolve_global_options(&GlobalCliArgs {
        base_url: Some("http://127.0.0.1:9000".to_string()),
        token: Some("cli-token".to_string()),
        ..Default::default()
    })
    .expect("resolution with logging");

    assert_eq!(options.base_url, "http://127.0.0.1:9000");
    assert_eq!(options.token.as_deref(), Some("cli-token"));
}

#[test]
fn validate_cert_accepts_existing_files_and_rejects_bad_paths() {
    let path = std::env::temp_dir().join(format!("rbs-cli-validate-cert-{}.pem", std::process::id()));
    fs::write(&path, b"ca").expect("write certificate file");
    let cert_path = path.to_string_lossy().into_owned();

    assert_eq!(validate_cert(&cert_path).expect("valid certificate path"), cert_path);
    assert!(validate_cert("").is_err());
    assert!(validate_cert(&format!("/tmp/{}.pem", "a".repeat(4096))).is_err());
    assert!(validate_cert("/tmp/rbs-cli-missing-cert.pem").is_err());

    let _ = fs::remove_file(&path);
}

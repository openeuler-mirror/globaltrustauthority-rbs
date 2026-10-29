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

//! Tests for the shared output sinks, formatter emitters, and file helpers used by `rbs-cli`.

use rbs_cli::common::formatter::{emit_err, emit_output, TextOutput};
use rbs_cli::common::output::{write_output, write_private_file};
use rbs_cli::common::utils::{read_cert_file, read_path_file};
use rbs_cli::config::{GlobalOptions, OutputFormat};
use rbs_cli::error::CliError;
use std::fs;
use std::path::PathBuf;

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rbs-cli-emit-{name}-{}", std::process::id()))
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

#[test]
fn emit_output_covers_json_quiet_and_stdout_paths() {
    let output = TextOutput::new("payload");

    let json = GlobalOptions { format: OutputFormat::Json, noout: true, ..Default::default() };
    emit_output(&output, &json).expect("json output");

    let quiet = GlobalOptions { quiet: true, ..Default::default() };
    emit_output(&output, &quiet).expect("quiet output");

    // The plain path prints to stdout and reports success.
    emit_output(&output, &GlobalOptions::default()).expect("stdout output");
}

#[test]
fn emit_output_covers_output_file_branches() {
    let output = TextOutput::new("payload");

    // A quiet run still writes the file and then stays silent.
    let quiet_path = temp_path("quiet.txt");
    let quiet = GlobalOptions {
        output_file: Some(quiet_path.to_string_lossy().into_owned()),
        quiet: true,
        ..Default::default()
    };
    emit_output(&output, &quiet).expect("quiet file output");
    assert_eq!(fs::read_to_string(&quiet_path).expect("read quiet output"), "payload");
    cleanup(&quiet_path);

    // An explicit format echoes the rendered payload in addition to the file.
    let explicit_path = temp_path("explicit.json");
    let explicit = GlobalOptions {
        format: OutputFormat::Json,
        output_file: Some(explicit_path.to_string_lossy().into_owned()),
        format_explicitly_set: true,
        ..Default::default()
    };
    emit_output(&output, &explicit).expect("explicit format file output");
    assert!(fs::read_to_string(&explicit_path).expect("read explicit output").contains("payload"));
    cleanup(&explicit_path);

    // `--noout` only writes the file.
    let noout_path = temp_path("noout.txt");
    let noout = GlobalOptions {
        output_file: Some(noout_path.to_string_lossy().into_owned()),
        noout: true,
        ..Default::default()
    };
    emit_output(&output, &noout).expect("noout file output");
    assert_eq!(fs::read_to_string(&noout_path).expect("read noout output"), "payload");
    cleanup(&noout_path);
}

#[test]
fn emit_err_respects_quiet() {
    let err = CliError::InvalidArgument("boom".to_string());

    emit_err(&err, &GlobalOptions { quiet: true, ..Default::default() });
    emit_err(&err, &GlobalOptions::default());
}

#[test]
fn read_cert_file_and_read_path_file_report_io_errors() {
    let path = temp_path("cert.pem");
    fs::write(&path, b"cert-bytes").expect("write cert file");
    assert_eq!(read_cert_file(&path.to_string_lossy()).expect("read cert file"), b"cert-bytes");
    cleanup(&path);

    let missing = temp_path("missing-cert.pem");
    let err = read_cert_file(&missing.to_string_lossy()).expect_err("missing cert file");
    assert!(err.to_string().contains("unable to read certificate file"), "err: {err}");

    let err = read_path_file(&format!("@{}", missing.display())).expect_err("missing content file");
    assert!(err.to_string().contains("unable to read file"), "err: {err}");
}

#[test]
fn write_output_covers_stdout_and_file_sinks() {
    write_output(&GlobalOptions::default(), "payload").expect("stdout output");

    let path = temp_path("write-output.txt");
    let global =
        GlobalOptions { output_file: Some(path.to_string_lossy().into_owned()), noout: true, ..Default::default() };
    write_output(&global, "payload").expect("file output");
    assert_eq!(fs::read_to_string(&path).expect("read output"), "payload");
    cleanup(&path);
}

#[test]
fn write_private_file_passes_through_unrelated_io_errors() {
    let missing_parent = temp_path("missing-parent").join("out.txt");

    let err = write_private_file(&missing_parent.to_string_lossy(), "payload")
        .expect_err("missing parent directory must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(!err.to_string().contains("symlink"), "err: {err}");
}

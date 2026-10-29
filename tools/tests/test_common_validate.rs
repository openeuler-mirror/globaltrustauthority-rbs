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

//! Boundary tests for the shared CLI validators in `rbs_cli::common::validate`.

use rbs_cli::common::validate::{
    validate_cert_file, validate_file_path, validate_file_reference_path, validate_file_size, validate_max_len,
    validate_pubkey_file, validate_query_ids, validate_url,
};
use rbs_cli::common::{CERT_FILE_MAX_SIZE, PUBKEY_FILE_MAX_SIZE, URL_MAX_LEN};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(prefix: &str, contents: &[u8]) -> Self {
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("system time before unix epoch").as_nanos();
        let path = std::env::temp_dir().join(format!("rbs-cli-validate-{prefix}-{nanos}-{unique}.pem"));
        fs::write(&path, contents).expect("failed to write temporary file");
        Self { path }
    }

    fn display(&self) -> String {
        self.path.display().to_string()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

// Each accepted value is stored behind a distinct `HasLen` implementation, so the
// generic length helper must work for `String`, `Vec<T>`, and `[T]` alike.
#[test]
fn validate_max_len_supports_owned_and_slice_values() {
    let owned = String::from("abcd");
    assert!(validate_max_len(&owned, 4).is_ok());
    let err = validate_max_len(&owned, 3).expect_err("owned string too long");
    assert!(err.to_string().contains("value length must not exceed 3 characters; got 4"), "error: {err}");

    let vector = vec![1u8, 2, 3];
    assert!(validate_max_len(&vector, 3).is_ok());
    assert!(validate_max_len(&vector, 2).is_err());

    let slice: &[u8] = &[1u8, 2, 3];
    assert!(validate_max_len::<[u8]>(slice, 3).is_ok());
    assert!(validate_max_len::<[u8]>(slice, 1).is_err());

    assert!(validate_max_len("short", 5).is_ok());
    assert!(validate_max_len("short", 4).is_err());
}

#[test]
fn validate_query_ids_rejects_blank_entries() {
    assert_eq!(
        validate_query_ids(Some(&["".to_string()]), 36).expect_err("blank id").to_string(),
        "ids must not contain empty values"
    );
    assert_eq!(
        validate_query_ids(Some(&[" ".to_string()]), 36).expect_err("spaces only").to_string(),
        "ids must not contain empty values"
    );
    assert_eq!(
        validate_query_ids(Some(&["id-1".to_string(), "".to_string()]), 36)
            .expect_err("trailing empty value")
            .to_string(),
        "ids must not contain empty values"
    );
    assert_eq!(validate_query_ids(None, 36).expect("absent ids"), None);
}

#[test]
fn validate_file_path_rejects_empty_nul_and_nameless_paths() {
    assert_eq!(validate_file_path("  ").expect_err("blank path").to_string(), "file path must not be empty");
    assert_eq!(
        validate_file_path("bad\0path").expect_err("NUL byte").to_string(),
        "invalid linux file path `bad\0path`"
    );
    // A path ending in `..` has no file name and does not exist, so it fails the
    // file-name check rather than the existing-directory check.
    let nameless = format!("{}/rbs-cli-validate-missing/..", std::env::temp_dir().display());
    let err = validate_file_path(&nameless).expect_err("nameless path");
    assert!(err.to_string().contains("does not contain a file name"), "error: {err}");

    let oversize = "a".repeat(4097);
    assert!(validate_file_path(&oversize).is_err());
    assert!(validate_file_path("relative-key.pem").is_ok());
}

#[test]
fn validate_file_reference_path_rejects_nul_bytes() {
    let err = validate_file_reference_path("@bad\0path", "content").expect_err("NUL byte in reference");
    assert_eq!(err.to_string(), "content file path contains an invalid character");
    assert_eq!(
        validate_file_reference_path("@", "content").expect_err("empty reference").to_string(),
        "content file path must not be empty"
    );
    assert_eq!(validate_file_reference_path("key\0value", "content").expect("inline value"), None);
}

#[test]
fn validate_file_size_reports_missing_and_oversized_files() {
    let file = TempFile::new("size", b"12345678");
    assert_eq!(validate_file_size(&file.display(), 8).expect("exact size"), file.display());
    assert_eq!(validate_file_size(&file.display(), 9).expect("within limit"), file.display());

    let err = validate_file_size(&file.display(), 4).expect_err("oversized file");
    assert_eq!(err.to_string(), format!("file `{}` exceeds the maximum size of 4 bytes; got 8 bytes", file.display()));

    let missing = format!("{}/rbs-cli-validate-absent-file", std::env::temp_dir().display());
    let err = validate_file_size(&missing, 8).expect_err("missing file");
    assert!(err.to_string().contains("unable to access file"), "error: {err}");
    assert!(err.to_string().contains("Please check that the file exists"), "error: {err}");
}

#[test]
fn validate_url_rejects_oversized_and_malformed_urls() {
    let long_url = format!("https://example.com/{}", "a".repeat(URL_MAX_LEN));
    let err = validate_url(&long_url).expect_err("oversized url");
    assert!(
        err.to_string()
            .contains(&format!("url length must not exceed {URL_MAX_LEN} characters; got {}", long_url.len())),
        "error: {err}"
    );

    let err = validate_url("not a url").expect_err("malformed url");
    assert!(err.to_string().contains("invalid url `not a url`"), "error: {err}");
    assert!(validate_url("https://127.0.0.1:6666/rbs/version").is_ok());
}

#[test]
fn validate_cert_file_checks_referenced_file_size() {
    let cert = "-----BEGIN CERTIFICATE-----mock-----END CERTIFICATE-----";
    assert_eq!(validate_cert_file(cert).expect("inline cert"), cert);

    let file = TempFile::new("cert", b"inline-certificate");
    assert_eq!(validate_cert_file(&format!("@{}", file.display())).expect("cert file"), format!("@{}", file.display()));

    // The inline form has no wording that would leak the supplied value; assert the
    // byte limit is enforced for both the dependency-free inline and `@file` forms.
    let oversized_inline = "c".repeat(CERT_FILE_MAX_SIZE as usize + 1);
    let err = validate_cert_file(&oversized_inline).expect_err("oversized inline cert");
    assert!(err.to_string().contains("certificate content must not exceed"), "error: {err}");
    assert!(!err.to_string().contains(&oversized_inline));

    let oversized_file = TempFile::new("big-cert", &vec![b'c'; CERT_FILE_MAX_SIZE as usize + 1]);
    let err = validate_cert_file(&format!("@{}", oversized_file.display())).expect_err("oversized cert file");
    assert!(err.to_string().contains("exceeds the maximum size"), "error: {err}");
}

#[test]
fn validate_pubkey_file_checks_referenced_file_size() {
    let key = "-----BEGIN PUBLIC KEY-----mock-----END PUBLIC KEY-----";
    assert_eq!(validate_pubkey_file(key).expect("inline key"), key);

    let file = TempFile::new("pubkey", b"inline-public-key");
    assert_eq!(
        validate_pubkey_file(&format!("@{}", file.display())).expect("pubkey file"),
        format!("@{}", file.display())
    );

    let oversized_inline = "k".repeat(PUBKEY_FILE_MAX_SIZE as usize + 1);
    let err = validate_pubkey_file(&oversized_inline).expect_err("oversized inline key");
    assert!(err.to_string().contains("public key content must not exceed"), "error: {err}");
    assert!(!err.to_string().contains(&oversized_inline));

    let oversized_file = TempFile::new("big-pubkey", &vec![b'k'; PUBKEY_FILE_MAX_SIZE as usize + 1]);
    let err = validate_pubkey_file(&format!("@{}", oversized_file.display())).expect_err("oversized pubkey file");
    assert!(err.to_string().contains("exceeds the maximum size"), "error: {err}");
}

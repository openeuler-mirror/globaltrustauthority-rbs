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

//! CLI-level tests for `rbs-cli res get` JWE decryption and `res update` option parsing.

use base64::Engine as _;
use clap::Parser;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use rbs_cli::admin::res::{self, GetContentArgs, PathArgs, ResCli, ResCommand};
use rbs_cli::config::{Cli, Command, GlobalOptions};
use rbs_cli::rbc::tools::tee_key::{KeyType, TeeKeyPair};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RESOURCE_URI: &str = "vault/default/secret/demo";
const RESOURCE_PATH: &str = "/rbs/v0/vault/default/secret/demo";
const PASSPHRASE: &str = "test-passphrase";

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(prefix: &str, contents: &[u8]) -> Self {
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("system time before unix epoch").as_nanos();
        let path = std::env::temp_dir().join(format!("rbs-cli-res-get-{prefix}-{nanos}-{unique}.pem"));
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

fn global(server: &MockServer) -> GlobalOptions {
    GlobalOptions { base_url: server.uri(), token: Some("bearer-token".to_string()), ..Default::default() }
}

fn run_blocking(cli: ResCli, global: GlobalOptions) -> Result<(String, String), String> {
    std::thread::spawn(move || match res::run(&cli, &global) {
        Ok(formatter) => {
            let text = formatter.render_text().map_err(|err| err.to_string())?;
            let json = formatter.render_json().map_err(|err| err.to_string())?;
            Ok((text, json))
        },
        Err(err) => Err(err.to_string()),
    })
    .join()
    .expect("command thread")
}

fn ec_key_pair() -> TeeKeyPair {
    TeeKeyPair::generate(KeyType::Ec).expect("generate EC key pair")
}

fn private_key_file(pair: &TeeKeyPair) -> TempFile {
    TempFile::new("key", pair.to_private_pem().expect("export private key PEM").as_bytes())
}

fn encrypted_private_key_file(pair: &TeeKeyPair, passphrase: &str) -> TempFile {
    let pem = pair.to_private_pem().expect("export private key PEM");
    let pkey = PKey::private_key_from_pem(pem.as_bytes()).expect("parse private key PEM");
    let encrypted =
        pkey.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase.as_bytes()).expect("encrypt PEM");
    TempFile::new("enc-key", &encrypted)
}

fn jwe_content(pair: &TeeKeyPair, plaintext: &[u8]) -> String {
    let jwe = pair.public_key().encrypt_jwe(plaintext).expect("encrypt JWE");
    base64::engine::general_purpose::STANDARD.encode(jwe)
}

fn get_cli(private_key_file: &str, passphrase: Option<Option<String>>) -> ResCli {
    ResCli {
        command: ResCommand::Get(GetContentArgs {
            path: PathArgs { uri: RESOURCE_URI.to_string() },
            private_key_file: private_key_file.to_string(),
            private_key_passphrase: passphrase,
        }),
    }
}

async fn mock_content(server: &MockServer, content: &str) {
    Mock::given(method("GET"))
        .and(path(RESOURCE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": RESOURCE_URI,
            "content": content,
            "content_type": "text",
            "export_mode": "jwe",
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn res_get_decrypts_jwe_content() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    mock_content(&server, &jwe_content(&pair, b"plain secret")).await;

    let key = private_key_file(&pair);
    let (text, json) = run_blocking(get_cli(&key.display(), None), global(&server)).expect("res get");
    assert_eq!(text, "plain secret");
    assert!(json.contains(RESOURCE_URI), "json: {json}");
    assert!(json.contains("\"content_type\": \"text\""), "json: {json}");
    assert!(json.contains("\"export_mode\": \"jwe\""), "json: {json}");
}

#[tokio::test]
async fn res_get_renders_binary_content_as_base64() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    let payload = [0u8, 159, 146, 150];
    mock_content(&server, &jwe_content(&pair, &payload)).await;

    let key = private_key_file(&pair);
    let (text, _) = run_blocking(get_cli(&key.display(), None), global(&server)).expect("res get binary");
    assert_eq!(text, base64::engine::general_purpose::STANDARD.encode(payload));
}

#[tokio::test]
async fn res_get_reads_passphrase_from_file() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    mock_content(&server, &jwe_content(&pair, b"encrypted-key secret")).await;

    let key = encrypted_private_key_file(&pair, PASSPHRASE);
    // A trailing CRLF is trimmed before the passphrase is handed to OpenSSL.
    let passphrase_file = TempFile::new("passphrase", format!("{PASSPHRASE}\r\n").as_bytes());
    let (text, _) =
        run_blocking(get_cli(&key.display(), Some(Some(format!("@{}", passphrase_file.display())))), global(&server))
            .expect("res get with passphrase file");
    assert_eq!(text, "encrypted-key secret");
}

#[tokio::test]
async fn res_get_rejects_inline_passphrase() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    mock_content(&server, &jwe_content(&pair, b"secret")).await;

    let key = private_key_file(&pair);
    let err = run_blocking(get_cli(&key.display(), Some(Some(PASSPHRASE.to_string()))), global(&server))
        .expect_err("inline passphrase");
    assert!(err.contains("--private-key-passphrase @path"), "error: {err}");
}

#[tokio::test]
async fn res_get_rejects_unreadable_passphrase_file() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    mock_content(&server, &jwe_content(&pair, b"secret")).await;

    let key = private_key_file(&pair);
    let err = run_blocking(
        get_cli(&key.display(), Some(Some("@/nonexistent/rbs-cli-res-get-passphrase".to_string()))),
        global(&server),
    )
    .expect_err("missing passphrase file");
    assert!(err.contains("unable to read private key passphrase file"), "error: {err}");
}

#[tokio::test]
async fn res_get_rejects_oversized_passphrase_file() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    mock_content(&server, &jwe_content(&pair, b"secret")).await;

    let key = private_key_file(&pair);
    let passphrase_file = TempFile::new("long-passphrase", "p".repeat(1025).as_bytes());
    let err =
        run_blocking(get_cli(&key.display(), Some(Some(format!("@{}", passphrase_file.display())))), global(&server))
            .expect_err("oversized passphrase");
    assert!(err.contains("private key passphrase must not exceed 1024 characters"), "error: {err}");
}

#[tokio::test]
async fn res_get_rejects_unparsable_private_key() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    mock_content(&server, &jwe_content(&pair, b"secret")).await;

    let key = TempFile::new("broken-key", b"-----BEGIN PRIVATE KEY-----\nnot-a-key\n");
    let err = run_blocking(get_cli(&key.display(), None), global(&server)).expect_err("broken private key");
    assert!(err.contains("failed to load private key"), "error: {err}");
}

#[tokio::test]
async fn res_get_rejects_unsupported_private_key_type() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    mock_content(&server, &jwe_content(&pair, b"secret")).await;

    let ed25519 = PKey::generate_ed25519().expect("generate ed25519 key");
    let key = TempFile::new("ed25519-key", &ed25519.private_key_to_pem_pkcs8().expect("export ed25519 PEM"));
    let err = run_blocking(get_cli(&key.display(), None), global(&server)).expect_err("unsupported key type");
    assert!(err.contains("failed to load private key for JWE decryption"), "error: {err}");
}

#[tokio::test]
async fn res_get_rejects_non_base64_content() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    mock_content(&server, "%%%not-base64%%%").await;

    let key = private_key_file(&pair);
    let err = run_blocking(get_cli(&key.display(), None), global(&server)).expect_err("invalid base64 content");
    assert!(err.contains("not valid Base64 JWE data"), "error: {err}");
}

#[tokio::test]
async fn res_get_rejects_non_utf8_jwe_content() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    let non_utf8 = base64::engine::general_purpose::STANDARD.encode([0xffu8, 0xfe, 0xfd]);
    mock_content(&server, &non_utf8).await;

    let key = private_key_file(&pair);
    let err = run_blocking(get_cli(&key.display(), None), global(&server)).expect_err("invalid UTF-8 JWE");
    assert!(err.contains("not valid UTF-8 JWE"), "error: {err}");
}

#[tokio::test]
async fn res_get_rejects_content_encrypted_for_another_key() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    let other_pair = ec_key_pair();
    mock_content(&server, &jwe_content(&other_pair, b"secret")).await;

    let key = private_key_file(&pair);
    let err = run_blocking(get_cli(&key.display(), None), global(&server)).expect_err("wrong private key");
    assert!(err.contains("failed to decrypt resource content"), "error: {err}");
}

#[tokio::test]
async fn res_get_propagates_server_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(RESOURCE_PATH))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "resource not found"})))
        .mount(&server)
        .await;

    let pair = ec_key_pair();
    let key = private_key_file(&pair);
    let err = run_blocking(get_cli(&key.display(), None), global(&server)).expect_err("missing resource");
    assert!(!err.is_empty(), "error should be reported");
}

#[test]
fn res_update_parses_policy_id_and_additional_info() {
    let cli = Cli::try_parse_from([
        "rbs-cli",
        "res",
        "update",
        "--uri",
        RESOURCE_URI,
        "--policy-id",
        "policy-2",
        "--additional-info",
        "note",
    ])
    .expect("parse res update");
    match cli.command {
        Command::Res(ResCli { command: ResCommand::Update(args) }) => {
            assert_eq!(args.policy_id.as_deref(), Some("policy-2"));
            assert_eq!(args.additional_info.as_deref(), Some("note"));
        },
        other => panic!("expected res update command, got {other:?}"),
    }
}

#[test]
fn res_update_rejects_blank_policy_id() {
    let err = Cli::try_parse_from(["rbs-cli", "res", "update", "--uri", RESOURCE_URI, "--policy-id", "   "])
        .expect_err("blank policy-id should be rejected");
    assert!(err.to_string().contains("policy-id must not be empty"), "error: {err}");
}

// When `--private-key-passphrase` is passed without a value and stdin is not a
// terminal, the passphrase is read from stdin as a line. This path prompts on a
// terminal, so it is exercised through the built binary with stdin closed.
#[tokio::test]
async fn res_get_reads_passphrase_from_stdin_when_not_a_terminal() {
    let server = MockServer::start().await;
    let pair = ec_key_pair();
    mock_content(&server, &jwe_content(&pair, b"stdin secret")).await;

    let key = private_key_file(&pair);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rbs-cli"))
        .args(["--base-url", &server.uri(), "--token", "bearer-token"])
        .args(["res", "get", "--uri", RESOURCE_URI, "--private-key-file", &key.display()])
        .arg("--private-key-passphrase")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run rbs-cli res get");

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "stdin secret");
}

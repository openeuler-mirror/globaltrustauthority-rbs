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

//! CLI-level tests for `rbs-cli admin cert` commands against a mock RBS server.

use rbs_cli::admin::cert::{self, CertCli, CertCommand, CreateArgs, DeleteArgs, GetArgs, ListArgs, UpdateArgs};
use rbs_cli::config::GlobalOptions;
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn global(server: &MockServer) -> GlobalOptions {
    GlobalOptions { base_url: server.uri(), token: Some("bearer-token".to_string()), ..Default::default() }
}

fn run_blocking(cli: CertCli, global: GlobalOptions) -> Result<(String, String), String> {
    std::thread::spawn(move || match cert::run(&cli, &global) {
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

/// Run a command on its own thread and report whether the command panicked.
fn run_panics(cli: CertCli, global: GlobalOptions) -> bool {
    std::thread::spawn(move || {
        let _ = cert::run(&cli, &global);
    })
    .join()
    .is_err()
}

fn cert_content_path(name: &str) -> String {
    format!("@{}", std::env::temp_dir().join(format!("rbs-cli-cert-{name}-{}", std::process::id())).display())
}

fn list_body() -> serde_json::Value {
    json!({
        "certs": [{
            "cert_id": "c-1",
            "cert_name": "cert1",
            "description": "demo",
            "cert_content": "PEM",
            "type": ["tpm"],
            "is_default": true,
            "version": 1
        }],
        "total_count": 1,
        "limit": 10,
        "offset": 0
    })
}

fn mutation_body() -> serde_json::Value {
    json!({"cert": {"cert_id": "c-1", "cert_name": "cert1", "version": 2}})
}

#[tokio::test]
async fn list_and_get_render_results() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/cert"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_body()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/cert/c-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_body()))
        .mount(&server)
        .await;

    let cli = CertCli {
        command: CertCommand::List(ListArgs {
            ids: None,
            cert_type: Some("tpm".to_string()),
            limit: Some("5".to_string()),
            offset: Some("0".to_string()),
        }),
    };
    let (text, json) = run_blocking(cli, global(&server)).expect("list certs");
    assert!(text.contains("cert1"), "text: {text}");
    assert!(json.contains("\"total_count\": 1"), "json: {json}");

    let cli = CertCli { command: CertCommand::Get(GetArgs { id: "c-1".to_string() }) };
    let (text, _) = run_blocking(cli, global(&server)).expect("get cert");
    assert!(text.contains("cert1"), "text: {text}");
}

#[tokio::test]
async fn create_normal_cert_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rbs/v0/attestation/gta/cert"))
        .respond_with(ResponseTemplate::new(201).set_body_json(mutation_body()))
        .mount(&server)
        .await;

    let cli = CertCli {
        command: CertCommand::Create(CreateArgs {
            name: "cert1".to_string(),
            description: Some("demo".to_string()),
            cert_type: vec!["tpm".to_string()],
            content: Some("PEM".to_string()),
            crl_content: None,
            is_default: Some("true".to_string()),
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("create cert");
    assert!(text.contains("cert1"), "text: {text}");
}

#[tokio::test]
async fn delete_and_invalid_input_are_handled() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/attestation/gta/cert"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let cli = CertCli {
        command: CertCommand::Delete(DeleteArgs {
            delete_type: Some("id".to_string()),
            ids: vec!["c-1".to_string()],
            cert_type: None,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete cert");
    assert!(text.contains("Delete"), "text: {text}");

    let cli = CertCli { command: CertCommand::Get(GetArgs { id: "bad id!".to_string() }) };
    assert!(run_blocking(cli, global(&server)).is_err());
}

#[tokio::test]
async fn update_cert_sends_every_updatable_field() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/rbs/v0/attestation/gta/cert"))
        .and(body_partial_json(json!({
            "id": "c-1",
            "name": "cert1",
            "description": "demo",
            "type": ["tpm"],
            "is_default": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(mutation_body()))
        .mount(&server)
        .await;

    let cli = CertCli {
        command: CertCommand::Update(UpdateArgs {
            id: "c-1".to_string(),
            name: Some("cert1".to_string()),
            description: Some("demo".to_string()),
            cert_type: Some(vec!["tpm".to_string()]),
            is_default: Some("true".to_string()),
        }),
    };
    let (text, json) = run_blocking(cli, global(&server)).expect("update cert");
    assert!(text.contains("cert1"), "text: {text}");
    assert!(json.contains("\"version\": 2"), "json: {json}");
}

#[tokio::test]
async fn update_cert_rejects_crl_and_invalid_default() {
    let server = MockServer::start().await;

    let cli = CertCli {
        command: CertCommand::Update(UpdateArgs {
            id: "c-1".to_string(),
            name: None,
            description: None,
            cert_type: Some(vec!["crl".to_string()]),
            is_default: None,
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("crl type cannot be updated");
    assert!(err.contains("update does not support cert type `crl`"), "err: {err}");

    let cli = CertCli {
        command: CertCommand::Update(UpdateArgs {
            id: "c-1".to_string(),
            name: None,
            description: None,
            cert_type: None,
            is_default: Some("maybe".to_string()),
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("invalid is-default value");
    assert!(err.contains("is-default is invalid"), "err: {err}");
}

#[tokio::test]
async fn create_rejects_missing_and_unreadable_content() {
    let server = MockServer::start().await;

    let cli = CertCli {
        command: CertCommand::Create(CreateArgs {
            name: "cert1".to_string(),
            description: None,
            cert_type: vec!["tpm".to_string()],
            content: None,
            crl_content: None,
            is_default: None,
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("content is required for normal certs");
    assert!(err.contains("--content is required for non-CRL certs"), "err: {err}");

    let cli = CertCli {
        command: CertCommand::Create(CreateArgs {
            name: "cert1".to_string(),
            description: None,
            cert_type: vec!["tpm".to_string()],
            content: Some(cert_content_path("missing")),
            crl_content: None,
            is_default: None,
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("missing content file");
    assert!(err.contains("unable to access certificate content file"), "err: {err}");

    let directory = format!("@{}", std::env::temp_dir().display());
    let cli = CertCli {
        command: CertCommand::Create(CreateArgs {
            name: "cert1".to_string(),
            description: None,
            cert_type: vec!["tpm".to_string()],
            content: Some(directory),
            crl_content: None,
            is_default: None,
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("directory content path");
    assert!(err.contains("certificate content path must point to a file"), "err: {err}");
}

#[tokio::test]
async fn delete_covers_every_delete_mode() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/attestation/gta/cert"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let cli = CertCli {
        command: CertCommand::Delete(DeleteArgs {
            delete_type: Some("type".to_string()),
            ids: vec![],
            cert_type: Some("tpm".to_string()),
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete by type");
    assert!(text.contains("certs removed by type: tpm"), "text: {text}");

    let cli = CertCli {
        command: CertCommand::Delete(DeleteArgs { delete_type: Some("all".to_string()), ids: vec![], cert_type: None }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete all certs");
    assert!(text.contains("all certs removed"), "text: {text}");

    let cli = CertCli {
        command: CertCommand::Delete(DeleteArgs { delete_type: None, ids: vec![], cert_type: Some("crl".to_string()) }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete all crls");
    assert!(text.contains("all CRLs removed"), "text: {text}");

    let cli = CertCli {
        command: CertCommand::Delete(DeleteArgs {
            delete_type: None,
            ids: vec!["c-1".to_string()],
            cert_type: Some("crl".to_string()),
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete crls by id");
    assert!(text.contains("CRLs removed: c-1"), "text: {text}");
}

#[tokio::test]
async fn delete_requires_a_delete_mode_and_ids() {
    let server = MockServer::start().await;

    let cli = CertCli { command: CertCommand::Delete(DeleteArgs { delete_type: None, ids: vec![], cert_type: None }) };
    let err = run_blocking(cli, global(&server)).expect_err("missing delete mode");
    assert!(err.contains("delete_type is required for normal cert deletion"), "err: {err}");

    let cli = CertCli {
        command: CertCommand::Delete(DeleteArgs { delete_type: Some("id".to_string()), ids: vec![], cert_type: None }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("missing ids for id mode");
    assert!(err.contains("ids are required when delete_type is `id`"), "err: {err}");
}

/// The `Some(_) => unreachable!()` arm of `build_delete_request` is only reachable
/// when `DeleteArgs` bypasses clap value validation, so it needs a panic check.
#[tokio::test]
async fn unknown_delete_type_hits_the_defensive_guard() {
    let server = MockServer::start().await;
    let cli = CertCli {
        command: CertCommand::Delete(DeleteArgs {
            delete_type: Some("bogus".to_string()),
            ids: vec![],
            cert_type: None,
        }),
    };
    assert!(run_panics(cli, global(&server)), "unvalidated delete types must hit the defensive guard");
}

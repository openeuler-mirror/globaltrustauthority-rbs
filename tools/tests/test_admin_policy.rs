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

//! CLI-level tests for `rbs-cli admin policy` commands against a mock RBS server.

use rbs_cli::admin::policy::{self, CreateArgs, DeleteArgs, GetArgs, ListArgs, PolicyCli, PolicyCommand, UpdateArgs};
use rbs_cli::config::GlobalOptions;
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn global(server: &MockServer) -> GlobalOptions {
    GlobalOptions { base_url: server.uri(), token: Some("bearer-token".to_string()), ..Default::default() }
}

fn run_blocking(cli: PolicyCli, global: GlobalOptions) -> Result<(String, String), String> {
    std::thread::spawn(move || match policy::run(&cli, &global) {
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
fn run_panics(cli: PolicyCli, global: GlobalOptions) -> bool {
    std::thread::spawn(move || {
        let _ = policy::run(&cli, &global);
    })
    .join()
    .is_err()
}

fn policy_content_path(name: &str) -> String {
    format!("@{}", std::env::temp_dir().join(format!("rbs-cli-policy-{name}-{}", std::process::id())).display())
}

fn policy_list_body() -> serde_json::Value {
    json!({
        "policies": [{
            "id": "p-1",
            "name": "policy1",
            "attester_type": ["tpm"],
            "description": "demo",
            "content": "content",
            "is_default": true,
            "version": 1,
            "update_time": 1700000000,
            "valid_code": 0
        }],
        "total_count": 1,
        "limit": 10,
        "offset": 0
    })
}

fn mutation_body() -> serde_json::Value {
    json!({"policy": {"id": "p-1", "name": "policy1", "version": 2}})
}

#[tokio::test]
async fn list_and_get_render_results() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_list_body()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/policy/p-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_list_body()))
        .mount(&server)
        .await;

    let cli = PolicyCli {
        command: PolicyCommand::List(ListArgs {
            ids: Some(vec!["p-1".to_string()]),
            attester_type: Some("tpm".to_string()),
            limit: Some("5".to_string()),
            offset: Some("0".to_string()),
        }),
    };
    let (text, json) = run_blocking(cli, global(&server)).expect("list policies");
    assert!(text.contains("policy1"), "text: {text}");
    assert!(json.contains("\"total_count\": 1"), "json: {json}");

    let cli = PolicyCli { command: PolicyCommand::Get(GetArgs { id: "p-1".to_string() }) };
    let (text, _) = run_blocking(cli, global(&server)).expect("get policy");
    assert!(text.contains("policy1"), "text: {text}");
}

#[tokio::test]
async fn create_and_update_post_expected_payloads() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .respond_with(ResponseTemplate::new(201).set_body_json(mutation_body()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mutation_body()))
        .mount(&server)
        .await;

    let cli = PolicyCli {
        command: PolicyCommand::Create(CreateArgs {
            name: "policy1".to_string(),
            description: Some("demo".to_string()),
            attester_type: vec!["tpm".to_string()],
            content_type: "text".to_string(),
            content: "plain policy".to_string(),
            is_default: Some(true),
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("create policy");
    assert!(text.contains("policy1"), "text: {text}");

    let cli = PolicyCli {
        command: PolicyCommand::Update(UpdateArgs {
            id: "p-1".to_string(),
            name: Some("policy1".to_string()),
            description: None,
            attester_type: None,
            content_type: Some("text".to_string()),
            content: Some("updated policy".to_string()),
            is_default: None,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("update policy");
    assert!(text.contains("policy1"), "text: {text}");
}

#[tokio::test]
async fn delete_by_id_and_all_succeed() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let cli = PolicyCli {
        command: PolicyCommand::Delete(DeleteArgs {
            delete_type: "id".to_string(),
            ids: vec!["p-1".to_string()],
            attester_type: None,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete by id");
    assert!(text.contains("Delete"), "text: {text}");

    let cli = PolicyCli {
        command: PolicyCommand::Delete(DeleteArgs { delete_type: "all".to_string(), ids: vec![], attester_type: None }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete all");
    assert!(text.contains("Delete"), "text: {text}");
}

#[tokio::test]
async fn validation_errors_are_reported_before_any_request() {
    let server = MockServer::start().await;

    let cli = PolicyCli { command: PolicyCommand::Get(GetArgs { id: "bad id!".to_string() }) };
    assert!(run_blocking(cli, global(&server)).is_err());

    let cli = PolicyCli {
        command: PolicyCommand::Create(CreateArgs {
            name: "policy1".to_string(),
            description: None,
            attester_type: vec![],
            content_type: "text".to_string(),
            content: "x".to_string(),
            is_default: None,
        }),
    };
    assert!(run_blocking(cli, global(&server)).is_err());
}

#[tokio::test]
async fn jwt_content_is_forwarded_without_base64_encoding() {
    let server = MockServer::start().await;
    // JWT policies must be forwarded verbatim; only `text` content is Base64-encoded.
    Mock::given(method("POST"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .and(body_partial_json(json!({
            "content_type": "jwt",
            "content": "header.payload.signature"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(mutation_body()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .and(body_partial_json(json!({
            "id": "p-1",
            "content_type": "jwt",
            "content": "header.payload.signature"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(mutation_body()))
        .mount(&server)
        .await;

    let cli = PolicyCli {
        command: PolicyCommand::Create(CreateArgs {
            name: "policy1".to_string(),
            description: None,
            attester_type: vec!["tpm".to_string()],
            content_type: "jwt".to_string(),
            content: "header.payload.signature".to_string(),
            is_default: None,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("create jwt policy");
    assert!(text.contains("policy1"), "text: {text}");

    let cli = PolicyCli {
        command: PolicyCommand::Update(UpdateArgs {
            id: "p-1".to_string(),
            name: None,
            description: None,
            attester_type: None,
            content_type: Some("jwt".to_string()),
            content: Some("header.payload.signature".to_string()),
            is_default: None,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("update jwt policy");
    assert!(text.contains("policy1"), "text: {text}");
}

#[tokio::test]
async fn update_without_content_leaves_the_payload_untouched() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/rbs/v0/attestation/gta/policy"))
        .and(body_partial_json(json!({"id": "p-1", "name": "policy1", "is_default": true})))
        .respond_with(ResponseTemplate::new(200).set_body_json(mutation_body()))
        .mount(&server)
        .await;

    let cli = PolicyCli {
        command: PolicyCommand::Update(UpdateArgs {
            id: "p-1".to_string(),
            name: Some("policy1".to_string()),
            description: None,
            attester_type: None,
            content_type: None,
            content: None,
            is_default: Some(true),
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("update metadata only");
    assert!(text.contains("policy1"), "text: {text}");
}

#[tokio::test]
async fn create_rejects_unreadable_policy_content_file() {
    let server = MockServer::start().await;

    let cli = PolicyCli {
        command: PolicyCommand::Create(CreateArgs {
            name: "policy1".to_string(),
            description: None,
            attester_type: vec!["tpm".to_string()],
            content_type: "text".to_string(),
            content: policy_content_path("missing"),
            is_default: None,
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("missing policy content file");
    assert!(err.contains("unable to access policy content file"), "err: {err}");

    let cli = PolicyCli {
        command: PolicyCommand::Create(CreateArgs {
            name: "policy1".to_string(),
            description: None,
            attester_type: vec!["tpm".to_string()],
            content_type: "text".to_string(),
            content: format!("@{}", std::env::temp_dir().display()),
            is_default: None,
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("directory policy content path");
    assert!(err.contains("policy content path must point to a file"), "err: {err}");
}

/// The `_ => unreachable!()` arm of `build_delete_request` is only reachable when
/// `DeleteArgs` bypasses clap value validation, so it needs a panic check.
#[tokio::test]
async fn unknown_delete_type_hits_the_defensive_guard() {
    let server = MockServer::start().await;
    let cli = PolicyCli {
        command: PolicyCommand::Delete(DeleteArgs {
            delete_type: "bogus".to_string(),
            ids: vec![],
            attester_type: None,
        }),
    };
    assert!(run_panics(cli, global(&server)), "unvalidated delete types must hit the defensive guard");
}

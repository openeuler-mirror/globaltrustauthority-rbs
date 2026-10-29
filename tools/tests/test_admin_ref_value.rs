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

//! CLI-level tests for `rbs-cli admin ref-value` commands against a mock RBS server.

use rbs_cli::admin::ref_value::{
    self, CreateArgs, DeleteArgs, GetArgs, ListArgs, RefValueCli, RefValueCommand, UpdateArgs,
};
use rbs_cli::config::GlobalOptions;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn global(server: &MockServer) -> GlobalOptions {
    GlobalOptions { base_url: server.uri(), token: Some("bearer-token".to_string()), ..Default::default() }
}

fn run_blocking(cli: RefValueCli, global: GlobalOptions) -> Result<(String, String), String> {
    std::thread::spawn(move || match ref_value::run(&cli, &global) {
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
fn run_panics(cli: RefValueCli, global: GlobalOptions) -> bool {
    std::thread::spawn(move || {
        let _ = ref_value::run(&cli, &global);
    })
    .join()
    .is_err()
}

fn ref_value_content_path(name: &str) -> String {
    format!("@{}", std::env::temp_dir().join(format!("rbs-cli-ref-value-{name}-{}", std::process::id())).display())
}

fn list_body() -> serde_json::Value {
    json!({
        "ref_values": [{
            "id": "rv-1",
            "name": "baseline",
            "attester_type": "tpm",
            "content": "content",
            "content_type": "jwt",
            "version": 1,
            "valid_code": 0
        }],
        "total_count": 1,
        "limit": 10,
        "offset": 0
    })
}

fn mutation_body() -> serde_json::Value {
    json!({"ref_value": {"id": "rv-1", "name": "baseline", "version": 2}})
}

#[tokio::test]
async fn list_and_get_render_results() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/ref_value"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_body()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/ref_value/rv-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_body()))
        .mount(&server)
        .await;

    let cli = RefValueCli {
        command: RefValueCommand::List(ListArgs {
            ids: None,
            attester_type: Some("tpm".to_string()),
            limit: None,
            offset: None,
        }),
    };
    let (text, json) = run_blocking(cli, global(&server)).expect("list ref values");
    assert!(text.contains("baseline"), "text: {text}");
    assert!(json.contains("\"total_count\": 1"), "json: {json}");

    let cli = RefValueCli { command: RefValueCommand::Get(GetArgs { id: "rv-1".to_string() }) };
    let (text, _) = run_blocking(cli, global(&server)).expect("get ref value");
    assert!(text.contains("baseline"), "text: {text}");
}

#[tokio::test]
async fn create_and_update_succeed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rbs/v0/attestation/gta/ref_value"))
        .respond_with(ResponseTemplate::new(201).set_body_json(mutation_body()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rbs/v0/attestation/gta/ref_value"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mutation_body()))
        .mount(&server)
        .await;

    let cli = RefValueCli {
        command: RefValueCommand::Create(CreateArgs {
            name: "baseline".to_string(),
            description: Some("demo".to_string()),
            attester_type: "tpm".to_string(),
            content: "content".to_string(),
            content_type: "jwt".to_string(),
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("create ref value");
    assert!(text.contains("baseline"), "text: {text}");

    let cli = RefValueCli {
        command: RefValueCommand::Update(UpdateArgs {
            id: "rv-1".to_string(),
            name: Some("baseline".to_string()),
            description: None,
            attester_type: None,
            content: None,
            content_type: None,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("update ref value");
    assert!(text.contains("baseline"), "text: {text}");
}

#[tokio::test]
async fn delete_by_type_and_all_succeed() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/attestation/gta/ref_value"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let cli = RefValueCli {
        command: RefValueCommand::Delete(DeleteArgs {
            delete_type: "type".to_string(),
            ids: vec![],
            attester_type: Some("tpm".to_string()),
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete by type");
    assert!(text.contains("Delete"), "text: {text}");

    let cli = RefValueCli {
        command: RefValueCommand::Delete(DeleteArgs {
            delete_type: "all".to_string(),
            ids: vec![],
            attester_type: None,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete all");
    assert!(text.contains("Delete"), "text: {text}");
}

#[tokio::test]
async fn invalid_id_is_rejected_before_request() {
    let server = MockServer::start().await;
    let cli = RefValueCli { command: RefValueCommand::Get(GetArgs { id: "bad id!".to_string() }) };
    assert!(run_blocking(cli, global(&server)).is_err());
}

#[tokio::test]
async fn empty_list_and_missing_detail_are_rendered() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/ref_value"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref_values": [],
            "total_count": 0,
            "limit": 10,
            "offset": 0
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/attestation/gta/ref_value/rv-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ref_values": []})))
        .mount(&server)
        .await;

    let cli = RefValueCli {
        command: RefValueCommand::List(ListArgs { ids: None, attester_type: None, limit: None, offset: None }),
    };
    let (text, json) = run_blocking(cli, global(&server)).expect("empty ref value list");
    assert!(text.contains("<empty>"), "text: {text}");
    assert!(json.contains("\"total_count\": 0"), "json: {json}");

    let cli = RefValueCli { command: RefValueCommand::Get(GetArgs { id: "rv-1".to_string() }) };
    let err = run_blocking(cli, global(&server)).expect_err("missing ref value detail");
    assert!(err.contains("Reference value not found."), "err: {err}");
}

#[tokio::test]
async fn delete_rejects_incomplete_targets() {
    let server = MockServer::start().await;

    let cli = RefValueCli {
        command: RefValueCommand::Delete(DeleteArgs {
            delete_type: "id".to_string(),
            ids: vec![],
            attester_type: None,
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("id mode without ids");
    assert!(err.contains("ids are required when delete_type is `id`"), "err: {err}");

    let cli = RefValueCli {
        command: RefValueCommand::Delete(DeleteArgs {
            delete_type: "type".to_string(),
            ids: vec![],
            attester_type: None,
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("type mode without attester type");
    assert!(err.contains("attester_type is required when delete_type is `type`"), "err: {err}");

    let cli = RefValueCli {
        command: RefValueCommand::Delete(DeleteArgs {
            delete_type: "all".to_string(),
            ids: vec![],
            attester_type: Some("tpm".to_string()),
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("all mode with an attester type");
    assert!(err.contains("must not be set when delete_type is `all`"), "err: {err}");
}

#[tokio::test]
async fn create_rejects_unreadable_content_file() {
    let server = MockServer::start().await;

    let cli = RefValueCli {
        command: RefValueCommand::Create(CreateArgs {
            name: "baseline".to_string(),
            description: None,
            attester_type: "tpm".to_string(),
            content: ref_value_content_path("missing"),
            content_type: "jwt".to_string(),
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("missing ref value content file");
    assert!(err.contains("unable to access ref value content file"), "err: {err}");

    let cli = RefValueCli {
        command: RefValueCommand::Create(CreateArgs {
            name: "baseline".to_string(),
            description: None,
            attester_type: "tpm".to_string(),
            content: format!("@{}", std::env::temp_dir().display()),
            content_type: "jwt".to_string(),
        }),
    };
    let err = run_blocking(cli, global(&server)).expect_err("directory ref value content path");
    assert!(err.contains("ref value content path must point to a file"), "err: {err}");
}

/// The `_ => unreachable!()` arm of `build_delete_request` is only reachable when
/// `DeleteArgs` bypasses clap value validation, so it needs a panic check.
#[tokio::test]
async fn unknown_delete_type_hits_the_defensive_guard() {
    let server = MockServer::start().await;
    let cli = RefValueCli {
        command: RefValueCommand::Delete(DeleteArgs {
            delete_type: "bogus".to_string(),
            ids: vec![],
            attester_type: None,
        }),
    };
    assert!(run_panics(cli, global(&server)), "unvalidated delete types must hit the defensive guard");
}

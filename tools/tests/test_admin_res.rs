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

//! CLI-level tests for `rbs-cli res` commands against a mock RBS server.

use clap::Parser;
use rbs_cli::admin::res::{self, CreateArgs, PathArgs, ResCli, ResCommand, UpdateArgs};
use rbs_cli::config::{Cli, GlobalOptions};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

fn resource_body() -> serde_json::Value {
    json!({
        "uri": "/rbs/v0/vault/default/secret/demo",
        "provider_name": "vault",
        "repository_name": "default",
        "resource_type": "secret",
        "resource_name": "demo",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "content_type": "text",
        "export_mode": "jwe",
        "policy_id": "policy-1",
        "additional_info": "note"
    })
}

fn path_args() -> PathArgs {
    PathArgs { uri: "vault/default/secret/demo".to_string() }
}

#[tokio::test]
async fn get_res_info_renders_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/vault/default/secret/demo/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resource_body()))
        .mount(&server)
        .await;

    let cli = ResCli { command: ResCommand::GetResInfo(path_args()) };
    let (text, json) = run_blocking(cli, global(&server)).expect("get res info");
    assert!(text.contains("policy-1"), "text: {text}");
    assert!(json.contains("\"provider_name\": \"vault\""), "json: {json}");
}

#[tokio::test]
async fn create_and_update_render_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rbs/v0/vault/default/secret/demo"))
        .respond_with(ResponseTemplate::new(201).set_body_json(resource_body()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rbs/v0/vault/default/secret/demo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resource_body()))
        .mount(&server)
        .await;

    let cli = ResCli {
        command: ResCommand::Create(CreateArgs {
            path: path_args(),
            policy_id: "policy-1".to_string(),
            additional_info: Some("note".to_string()),
            content: None,
            content_type: Some("text".to_string()),
            export_mode: Some("jwe".to_string()),
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("create");
    assert!(text.contains("vault"), "text: {text}");

    let cli = ResCli {
        command: ResCommand::Update(UpdateArgs {
            path: path_args(),
            policy_id: Some("policy-1".to_string()),
            additional_info: None,
            content: None,
            content_type: None,
            export_mode: None,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("update");
    assert!(text.contains("demo"), "text: {text}");
}

#[tokio::test]
async fn delete_reports_success() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/vault/default/secret/demo"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let cli = ResCli { command: ResCommand::Delete(path_args()) };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete");
    assert!(text.contains("Delete succeeded"), "text: {text}");
}

#[tokio::test]
async fn commands_require_bearer_token() {
    let server = MockServer::start().await;
    let mut global = global(&server);
    global.token = None;
    let cli = ResCli { command: ResCommand::Delete(path_args()) };
    let err = run_blocking(cli, global).expect_err("missing token");
    assert!(err.contains("bearer token"), "error: {err}");
}

#[test]
fn uri_parser_rejects_malformed_resource_uri() {
    let err = Cli::try_parse_from(["rbs-cli", "res", "delete", "--uri", "vault/default/secret"])
        .expect_err("three segments must be rejected");
    assert!(err.to_string().contains("provider/repository/type/name"), "error: {err}");
    assert!(Cli::try_parse_from(["rbs-cli", "res", "delete", "--uri", "vault/default/secret/demo"]).is_ok());
}

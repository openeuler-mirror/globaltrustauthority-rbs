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

//! CLI-level tests for `rbs-cli admin user` commands against a mock RBS server.

use rbs_cli::admin::user::{self, CreateArgs, DeleteArgs, GetArgs, ListArgs, UpdateArgs, UserCli, UserCommand};
use rbs_cli::common::clap::Page;
use rbs_cli::config::{GlobalOptions, OutputFormat};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn global(server: &MockServer) -> GlobalOptions {
    GlobalOptions { base_url: server.uri(), token: Some("bearer-token".to_string()), ..Default::default() }
}

/// `*::run` builds its own Tokio runtime, so it must not be called from inside
/// the test runtime. Run it on a plain thread and return the rendered outputs.
fn run_blocking(cli: UserCli, global: GlobalOptions) -> Result<(String, String), String> {
    std::thread::spawn(move || match user::run(&cli, &global) {
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

fn user_body(username: &str) -> serde_json::Value {
    json!({
        "id": "id-1",
        "username": username,
        "role": "user",
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z"
    })
}

#[tokio::test]
async fn list_renders_text_and_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "users": [user_body("alice")],
            "total_count": 1,
            "limit": 10,
            "offset": 0
        })))
        .mount(&server)
        .await;

    let cli = UserCli { command: UserCommand::List(ListArgs { page: Page { limit: None, offset: None } }) };
    let (text, json) = run_blocking(cli, global(&server)).expect("list users");
    assert!(text.contains("alice"), "text output: {text}");
    assert!(json.contains("\"total_count\": 1"), "json output: {json}");
}

#[tokio::test]
async fn list_rejects_invalid_pagination() {
    let server = MockServer::start().await;
    let cli =
        UserCli { command: UserCommand::List(ListArgs { page: Page { limit: Some("0".to_string()), offset: None } }) };
    let err = run_blocking(cli, global(&server)).expect_err("limit 0 must fail");
    assert!(err.contains("limit"), "error: {err}");
}

#[tokio::test]
async fn get_and_create_and_update_succeed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/users/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_body("alice")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rbs/v0/users"))
        .respond_with(ResponseTemplate::new(201).set_body_json(user_body("bob")))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rbs/v0/users/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_body("alice")))
        .mount(&server)
        .await;

    let cli = UserCli { command: UserCommand::Get(GetArgs { username: "alice".to_string() }) };
    let (text, _) = run_blocking(cli, global(&server)).expect("get user");
    assert!(text.contains("alice"));

    let cli = UserCli {
        command: UserCommand::Create(CreateArgs {
            username: "bob".to_string(),
            role: None,
            enabled: Some(true),
            public_key: Some("-----BEGIN PUBLIC KEY-----".to_string()),
            jwk: None,
        }),
    };
    let (_, json) = run_blocking(cli, global(&server)).expect("create user");
    assert!(json.contains("bob"));

    let cli = UserCli {
        command: UserCommand::Update(UpdateArgs {
            username: "alice".to_string(),
            role: Some("user".to_string()),
            enabled: Some(false),
            public_key: None,
            jwk: None,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("update user");
    assert!(text.contains("alice"));
}

#[tokio::test]
async fn delete_reports_success_and_client_errors() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/users/alice"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let cli = UserCli { command: UserCommand::Delete(DeleteArgs { username: "alice".to_string() }) };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete user");
    assert!(text.contains("Delete succeeded"));

    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/users/ghost"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    let cli = UserCli { command: UserCommand::Delete(DeleteArgs { username: "ghost".to_string() }) };
    assert!(run_blocking(cli, global(&server)).is_err());
}

#[tokio::test]
async fn commands_require_bearer_token() {
    let server = MockServer::start().await;
    let mut global = global(&server);
    global.token = None;
    let cli = UserCli { command: UserCommand::List(ListArgs { page: Page { limit: None, offset: None } }) };
    let err = run_blocking(cli, global).expect_err("missing token");
    assert!(err.contains("bearer token"), "error: {err}");
}

#[tokio::test]
async fn output_format_json_is_honoured_by_render_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/users/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_body("alice")))
        .mount(&server)
        .await;

    let mut global = global(&server);
    global.format = OutputFormat::Json;
    let cli = UserCli { command: UserCommand::Get(GetArgs { username: "alice".to_string() }) };
    let (_, json) = run_blocking(cli, global).expect("get user");
    let json: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    assert_eq!(json["username"], "alice");
}

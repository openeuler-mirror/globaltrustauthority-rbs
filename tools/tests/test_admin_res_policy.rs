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

//! CLI-level tests for `rbs-cli res-policy` commands against a mock RBS server.

use clap::Args as _;
use rbs_admin_client::res_policy::ResourcePolicyContentType;
use rbs_cli::admin::res_policy::{
    self, CreateArgs, DeleteArgs, GetArgs, ListArgs, ResPolicyCli, ResPolicyCommand, ResPolicyContentTypeArg,
    UpdateArgs,
};
use rbs_cli::config::GlobalOptions;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn global(server: &MockServer) -> GlobalOptions {
    GlobalOptions { base_url: server.uri(), token: Some("bearer-token".to_string()), ..Default::default() }
}

fn run_blocking(cli: ResPolicyCli, global: GlobalOptions) -> Result<(String, String), String> {
    std::thread::spawn(move || match res_policy::run(&cli, &global) {
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

fn policy_body() -> serde_json::Value {
    json!({
        "policy_id": "policy-1",
        "policy_name": "allow-secret",
        "policy_version": 1,
        "content_type": "base64",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "applied_resources": ["vault/default/secret/demo"]
    })
}

#[tokio::test]
async fn list_and_get_render_results() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/resource/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [policy_body()],
            "total_count": 1,
            "limit": 10,
            "offset": 0
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/resource/policy/policy-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_body()))
        .mount(&server)
        .await;

    let cli = ResPolicyCli {
        command: ResPolicyCommand::List(ListArgs {
            ids: Some(vec!["policy-1".to_string()]),
            limit: None,
            offset: None,
        }),
    };
    let (text, json) = run_blocking(cli, global(&server)).expect("list policies");
    assert!(text.contains("allow-secret"), "text: {text}");
    assert!(json.contains("\"total_count\": 1"), "json: {json}");

    let cli = ResPolicyCli { command: ResPolicyCommand::Get(GetArgs { id: "policy-1".to_string() }) };
    let (text, _) = run_blocking(cli, global(&server)).expect("get policy");
    assert!(text.contains("allow-secret"), "text: {text}");
}

#[tokio::test]
async fn create_and_update_succeed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rbs/v0/resource/policy"))
        .respond_with(ResponseTemplate::new(201).set_body_json(policy_body()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rbs/v0/resource/policy/policy-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_body()))
        .mount(&server)
        .await;

    let cli = ResPolicyCli {
        command: ResPolicyCommand::Create(CreateArgs {
            name: "allow-secret".to_string(),
            content: "cGFja2FnZQ==".to_string(),
            content_type: ResPolicyContentTypeArg::Base64,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("create policy");
    assert!(text.contains("allow-secret"), "text: {text}");

    let cli = ResPolicyCli {
        command: ResPolicyCommand::Update(UpdateArgs {
            id: "policy-1".to_string(),
            name: "allow-secret".to_string(),
            content: "cGFja2FnZQ==".to_string(),
            content_type: ResPolicyContentTypeArg::Base64,
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("update policy");
    assert!(text.contains("allow-secret"), "text: {text}");
}

#[tokio::test]
async fn delete_single_and_batch_succeed() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/resource/policy/policy-1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/rbs/v0/resource/policy"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let cli =
        ResPolicyCli { command: ResPolicyCommand::Delete(DeleteArgs { id: Some("policy-1".to_string()), ids: None }) };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete single");
    assert!(text.contains("policy-1"), "text: {text}");

    let cli = ResPolicyCli {
        command: ResPolicyCommand::Delete(DeleteArgs {
            id: None,
            ids: Some(vec!["policy-1".to_string(), "policy-2".to_string()]),
        }),
    };
    let (text, _) = run_blocking(cli, global(&server)).expect("delete batch");
    assert!(text.contains("policy-1"), "text: {text}");
}

#[tokio::test]
async fn missing_token_and_bad_pagination_are_rejected() {
    let server = MockServer::start().await;
    let mut opts = global(&server);
    opts.token = None;
    let cli = ResPolicyCli { command: ResPolicyCommand::Get(GetArgs { id: "policy-1".to_string() }) };
    assert!(run_blocking(cli, opts).is_err());

    let cli = ResPolicyCli {
        command: ResPolicyCommand::List(ListArgs { ids: None, limit: Some("0".to_string()), offset: None }),
    };
    assert!(run_blocking(cli, global(&server)).is_err());
}

#[tokio::test]
async fn list_without_items_renders_the_header_only() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rbs/v0/resource/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "total_count": 0,
            "limit": 10,
            "offset": 0
        })))
        .mount(&server)
        .await;

    let cli = ResPolicyCli { command: ResPolicyCommand::List(ListArgs { ids: None, limit: None, offset: None }) };
    let (text, _) = run_blocking(cli, global(&server)).expect("empty policy list");
    assert!(text.contains("resource_policies: total=0"), "text: {text}");
    assert!(!text.contains("policy_name"), "text: {text}");
}

#[test]
fn content_type_argument_displays_and_converts() {
    assert_eq!(ResPolicyContentTypeArg::Base64.to_string(), "base64");
    assert_eq!(ResourcePolicyContentType::from(ResPolicyContentTypeArg::Base64), ResourcePolicyContentType::Base64);
}

#[test]
fn argument_value_parsers_validate_ids_names_and_content() {
    let list = || ListArgs::augment_args(clap::Command::new("list"));
    list().try_get_matches_from(["list", "--ids", "policy-1,policy-2"]).expect("valid list ids");
    list().try_get_matches_from(["list", "--ids", "policy?debug=true"]).expect_err("list id with a query delimiter");

    let create = || CreateArgs::augment_args(clap::Command::new("create"));
    create()
        .try_get_matches_from(["create", "--name", "allow-secret", "--content", "cGFja2FnZQ=="])
        .expect("valid create args");
    create()
        .try_get_matches_from(["create", "--name", "   ", "--content", "cGFja2FnZQ=="])
        .expect_err("blank create name");

    let update = || UpdateArgs::augment_args(clap::Command::new("update"));
    update()
        .try_get_matches_from(["update", "--id", "policy-1", "--name", "allow-secret", "--content", "cGFja2FnZQ=="])
        .expect("valid update args");
    update()
        .try_get_matches_from(["update", "--id", "policy/1", "--name", "allow-secret", "--content", "cGFja2FnZQ=="])
        .expect_err("update id with a path separator");
    update()
        .try_get_matches_from(["update", "--id", "policy-1", "--name", "  ", "--content", "cGFja2FnZQ=="])
        .expect_err("blank update name");

    let delete = || DeleteArgs::augment_args(clap::Command::new("delete"));
    delete().try_get_matches_from(["delete", "--id", "policy-1"]).expect("valid delete id");
    delete().try_get_matches_from(["delete", "--ids", "policy-1,policy-2"]).expect("valid delete ids");
    delete().try_get_matches_from(["delete", "--id", "policy?debug=true"]).expect_err("delete id control chars");
}

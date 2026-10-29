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

//! CLI-level tests for `rbs-cli client` command dispatch and error mapping.
//!
//! `Client::new` builds the configured attestation providers before any request is
//! sent, so the assertions below cover the CLI dispatch layer (`run`, action
//! naming, and `rbc::cli::CliError` to `CliError` mapping) without reaching the
//! network. Provider and client behaviour is covered by `rbc`'s own tests.

use rbs_cli::client::cmd::{
    self, ChallengeArgs, ClientAction, ClientCli, CollectEvidenceArgs, GetResourceArgs, GetTokenArgs,
};
use rbs_cli::config::GlobalOptions;
use rbs_cli::rbc::cli::AgentConfigArgs;
use wiremock::MockServer;

const MISSING_AGENT_CONFIG: &str = "/nonexistent/rbs-cli-agent-config.yaml";

// `run` emits its dispatch log through `tracing`; without an active subscriber the
// `info!` field expressions (action name and provider types) are never evaluated.
fn init_tracing() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_writer(std::io::sink).try_init();
}

fn global(server: &MockServer) -> GlobalOptions {
    GlobalOptions { base_url: server.uri(), ..Default::default() }
}

fn run_blocking(cli: ClientCli, global: GlobalOptions) -> Result<(String, String), String> {
    std::thread::spawn(move || match cmd::run(&cli, &global) {
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

fn agent(agent_config: &str) -> AgentConfigArgs {
    AgentConfigArgs { agent_config: agent_config.to_string() }
}

fn collect_evidence(attester_pubkey: &str, attester_data: Option<&str>) -> ClientCli {
    ClientCli {
        command: ClientAction::CollectEvidence(CollectEvidenceArgs {
            agent: agent(MISSING_AGENT_CONFIG),
            nonce: "nonce-value".to_string(),
            attester_pubkey: attester_pubkey.to_string(),
            attester_data: attester_data.map(str::to_string),
            runtime_data: Vec::new(),
        }),
    }
}

fn get_token(evidence: Option<&str>) -> ClientCli {
    ClientCli {
        command: ClientAction::GetToken(GetTokenArgs {
            agent: agent(MISSING_AGENT_CONFIG),
            attester_pubkey: if evidence.is_some() { None } else { Some("attester.pem".to_string()) },
            attester_data: None,
            runtime_data: Vec::new(),
            evidence: evidence.map(str::to_string),
        }),
    }
}

fn get_resource(attest_token: &str, uri: &str) -> ClientCli {
    ClientCli {
        command: ClientAction::GetResource(GetResourceArgs {
            agent: agent(MISSING_AGENT_CONFIG),
            uri: uri.to_string(),
            attest_token: Some(attest_token.to_string()),
            evidence: None,
            passport: false,
            background: false,
            attester_data: None,
            runtime_data: Vec::new(),
            private_key_file: None,
            private_key_passphrase: None,
        }),
    }
}

#[tokio::test]
async fn challenge_reports_missing_agent_config() {
    init_tracing();
    let server = MockServer::start().await;
    let cli = ClientCli { command: ClientAction::Challenge(ChallengeArgs { agent: agent(MISSING_AGENT_CONFIG) }) };

    let err = run_blocking(cli, global(&server)).expect_err("challenge without agent config");
    assert!(err.contains("attestation_client init failed"), "error: {err}");
}

#[tokio::test]
async fn collect_evidence_rejects_unparsable_attester_pubkey() {
    init_tracing();
    let server = MockServer::start().await;

    let err =
        run_blocking(collect_evidence("not-a-public-key", None), global(&server)).expect_err("invalid attester pubkey");
    assert_eq!(err, "failed to parse public key or certificate PEM");
}

#[tokio::test]
async fn collect_evidence_reports_unreadable_attester_data_file() {
    init_tracing();
    let server = MockServer::start().await;

    let err = run_blocking(
        collect_evidence("attester.pem", Some("@/nonexistent/rbs-cli-attester-data.json")),
        global(&server),
    )
    .expect_err("missing attester-data file");
    assert!(err.contains("unable to read file `/nonexistent/rbs-cli-attester-data.json`"), "error: {err}");
}

#[tokio::test]
async fn collect_evidence_rejects_malformed_attester_data_json() {
    init_tracing();
    let server = MockServer::start().await;

    let err = run_blocking(collect_evidence("attester.pem", Some("{not-json")), global(&server))
        .expect_err("malformed attester-data JSON");
    assert!(err.starts_with("invalid attester-data JSON"), "error: {err}");
}

#[tokio::test]
async fn get_token_rejects_malformed_evidence_json() {
    init_tracing();
    let server = MockServer::start().await;

    let err = run_blocking(get_token(Some("{not-json")), global(&server)).expect_err("malformed evidence JSON");
    // `serde_json` errors are mapped through `CliError::Json` and reported verbatim.
    assert!(err.contains("key must be a string"), "error: {err}");
}

#[tokio::test]
async fn get_token_reports_provider_setup_failure() {
    init_tracing();
    let server = MockServer::start().await;

    let err = run_blocking(get_token(Some("{}")), global(&server)).expect_err("missing token provider config");
    assert!(err.contains("attestation_client init failed"), "error: {err}");
}

#[tokio::test]
async fn get_resource_reports_provider_setup_failure_before_uri_validation() {
    init_tracing();
    let server = MockServer::start().await;

    let err = run_blocking(get_resource("attest-token", "vault/default/secret/demo"), global(&server))
        .expect_err("missing evidence provider config");
    assert!(err.contains("attestation_client init failed"), "error: {err}");
}

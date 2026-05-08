/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use std::fs;
use std::io::{self, IsTerminal, Read};

use base64::Engine as _;
use clap::{ArgAction, Args, Subcommand};
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::{Id, PKey, Public};
use openssl::x509::X509;
use rbc::client::{RbsRestClient, TlsConfig};
use rbc::sdk::{Client as RbcClient, Config as RbcConfig, ConfigBuilder, ProviderRawConfig, ProviderType};
use rbc::tools::tee_key::{KeyType, TeeKeyPair, TeePublicKey};
use rbs_api_types::{AttestRequest, AttestResponse, AttesterData, AuthChallengeResponse, RbcEvidencesPayload, ResourceContentResponse};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::common::formatter::Formatter;
use crate::common::utils::read_path_file;
use crate::common::validate::{validate_file_path, validate_not_empty};
use crate::config::GlobalOptions;
use crate::error::CliError;
use crate::token::cmd::{GenerateArgs, TokenGenerate};

const DEFAULT_AGENT_CONFIG: &str = "/etc/attestation_agent/agent_config.yaml";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Args, Debug, Clone)]
pub struct ClientCli {
    #[command(subcommand)]
    pub command: ClientCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ClientCommand {
    Auth(AuthArgs),
    CollectEvidence(CollectEvidenceArgs),
    Attest(AttestArgs),
    GetToken(GetTokenArgs),
    GetRes(GetResArgs),
}

#[derive(Args, Debug, Clone, Default)]
pub struct AuthArgs {
    #[arg(long)]
    pub as_provider: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct CollectEvidenceArgs {
    #[arg(long)]
    pub nonce: Option<String>,

    #[arg(long, value_parser = validate_not_empty)]
    pub attester_pubkey: String,

    #[arg(long)]
    pub attester_data: Option<String>,

    #[arg(long = "runtime-data", action = ArgAction::Append)]
    pub runtime_data: Vec<String>,

    #[arg(long, default_value = DEFAULT_AGENT_CONFIG, value_parser = validate_file_path)]
    pub agent_config: String,
}

#[derive(Args, Debug, Clone, Default)]
pub struct AttestArgs {
    #[arg(long)]
    pub evidence: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct GetTokenArgs {
    #[arg(long, value_parser = validate_not_empty)]
    pub attest_pubkey: String,

    #[arg(long = "policy-ids", value_delimiter = ',', num_args = 1..)]
    pub policy_ids: Vec<String>,

    #[arg(long = "refvalue-ids", value_delimiter = ',', num_args = 1..)]
    pub refvalue_ids: Vec<String>,

    #[arg(long, default_value = DEFAULT_AGENT_CONFIG, value_parser = validate_file_path)]
    pub agent_config: String,
}

#[derive(Args, Debug, Clone, Default)]
pub struct GetResArgs {
    #[arg(long, value_parser = validate_not_empty)]
    pub uri: String,

    #[arg(long)]
    pub attest_token: bool,

    #[arg(long)]
    pub evidence: Option<String>,

    #[arg(long = "runtime-data", action = ArgAction::Append)]
    pub runtime_data: Vec<String>,

    #[arg(long, value_parser = validate_file_path)]
    pub private_key_file: Option<String>,

    #[arg(long, num_args = 0..=1, value_name = "@PATH")]
    pub private_key_passphrase: Option<Option<String>>,
}

pub fn run(cli: &ClientCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|err| CliError::Message(format!("failed to create async runtime: {err}")))?;
    runtime.block_on(execute_client_command(cli, global))
}

async fn execute_client_command(cli: &ClientCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let rest_client = build_rest_client(global)?;
    match &cli.command {
        ClientCommand::Auth(args) => {
            let resp = rest_client.get_nonce(args.as_provider.clone()).await?;
            Ok(Box::new(AuthOutput(resp)))
        }
        ClientCommand::CollectEvidence(args) => {
            let nonce = resolve_nonce_input(args.nonce.as_deref(), &rest_client).await?;
            let attester_data = build_attester_data(Some(&args.attester_pubkey), args.attester_data.as_deref(), &args.runtime_data)?;
            let client = build_evidence_client(global, &args.agent_config)?;
            let session = client.new_session(Some(&attester_data))?;
            let challenge = AuthChallengeResponse { nonce };
            let evidence = session.collect_evidence(&challenge)?;
            Ok(Box::new(JsonValueOutput(evidence)))
        }
        ClientCommand::Attest(args) => {
            let evidence = read_evidence_payload(args.evidence.as_deref())?;
            let resp = rest_client
                .post_attest(
                    &AttestRequest {
                        as_provider: None,
                        rbc_evidences: evidence,
                        attester_data: None,
                    },
                    &Default::default(),
                )
                .await
                ?;
            Ok(Box::new(AttestOutput(resp)))
        }
        ClientCommand::GetToken(args) => {
            validate_string_list(&args.policy_ids, 10, "--policy-ids")?;
            validate_string_list(&args.refvalue_ids, 5, "--refvalue-ids")?;

            let nonce = resolve_nonce_input(None, &rest_client).await?;
            let attester_data = build_get_token_attester_data(&args.attest_pubkey, &args.refvalue_ids)?;
            let client = build_evidence_client(global, &args.agent_config)?;
            let session = client.new_session(Some(&attester_data))?;
            let challenge = AuthChallengeResponse { nonce };
            let evidence = session.collect_evidence(&challenge)?;
            let evidence = apply_policy_ids_to_evidence(evidence, &args.policy_ids)?;
            let rbc_evidences: RbcEvidencesPayload = serde_json::from_value(evidence)
                .map_err(|err| CliError::InvalidArgument(format!("invalid collected evidence JSON: {err}")))?;
            let resp = rest_client
                .post_attest(
                    &AttestRequest {
                        as_provider: None,
                        rbc_evidences,
                        attester_data: None,
                    },
                    &Default::default(),
                )
                .await?;
            Ok(Box::new(AttestOutput(resp)))
        }
        ClientCommand::GetRes(args) => {
            let resp = if let Some(evidence_input) = args.evidence.as_deref() {
                let evidence = read_evidence_payload(Some(evidence_input))?;
                let attester_data = if args.runtime_data.is_empty() {
                    None
                } else {
                    Some(build_attester_data(None, None, &args.runtime_data)?)
                };
                rest_client
                    .get_resource_by_evidence(
                        &args.uri,
                        &AttestRequest {
                            as_provider: None,
                            rbc_evidences: evidence,
                            attester_data,
                        },
                    )
                    .await
                    ?
            } else {
                let token = global
                    .token
                    .as_deref()
                    .ok_or_else(|| CliError::InvalidArgument("missing required token; pass -t/--token or set RBS_TOKEN".to_string()))?;
                let _use_attest_token_header = args.attest_token;
                rest_client.get_resource(&args.uri, token).await?
            };

            let content = maybe_decrypt_resource(&resp, args)?;
            Ok(Box::new(ResourceOutput {
                uri: resp.uri,
                content,
                content_type: resp.content_type,
            }))
        }
    }
}

fn build_rest_client(global: &GlobalOptions) -> Result<RbsRestClient, CliError> {
    let tls = global.cert_path.as_ref().map(|path| TlsConfig {
        ca_cert: Some(path.clone()),
    });
    Ok(RbsRestClient::new(&global.base_url, tls.as_ref(), Some(DEFAULT_TIMEOUT_SECS))?)
}

fn build_evidence_client(global: &GlobalOptions, agent_config: &str) -> Result<RbcClient, CliError> {
    let mut provider_rest = Map::new();
    provider_rest.insert("config_path".to_string(), Value::String(agent_config.to_string()));

    build_rbc_config(global)?
        .evidence_provider(vec![ProviderRawConfig {
            provider_type: ProviderType::Native,
            enabled: true,
            rest: provider_rest,
        }])
        .build()
        .and_then(RbcClient::new)
        .map_err(CliError::from)
}

fn build_rbc_config(global: &GlobalOptions) -> Result<ConfigBuilder, CliError> {
    let mut builder = RbcConfig::builder().base_url(&global.base_url).timeout_secs(DEFAULT_TIMEOUT_SECS);
    if let Some(path) = global.cert_path.as_deref() {
        builder = builder.ca_cert(path);
    }
    Ok(builder)
}

async fn resolve_nonce_input(input: Option<&str>, rest_client: &RbsRestClient) -> Result<String, CliError> {
    match input {
        Some(value) => Ok(value.to_string()),
        None => {
            if let Some(value) = read_optional_stdin()? {
                return Ok(value);
            }
            let resp = rest_client.get_nonce(None).await?;
            Ok(resp.nonce)
        }
    }
}

fn read_evidence_payload(input: Option<&str>) -> Result<RbcEvidencesPayload, CliError> {
    let raw = match input {
        Some("-") => read_required_stdin("missing evidence on stdin")?,
        Some(value) => read_path_file(value)?,
        None => read_required_stdin("missing evidence; pass --evidence or pipe JSON to stdin")?,
    };
    serde_json::from_str(raw.trim()).map_err(|err| CliError::InvalidArgument(format!("invalid evidence JSON: {err}")))
}

fn read_optional_stdin() -> Result<Option<String>, CliError> {
    if io::stdin().is_terminal() {
        return Ok(None);
    }
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn read_required_stdin(message: &str) -> Result<String, CliError> {
    let value = read_optional_stdin()?;
    value.ok_or_else(|| CliError::InvalidArgument(message.to_string()))
}

fn build_attester_data(
    attester_pubkey: Option<&str>,
    attester_data: Option<&str>,
    runtime_data: &[String],
) -> Result<AttesterData, CliError> {
    let mut data = match attester_data {
        Some(value) => {
            let raw = read_path_file(value)?;
            serde_json::from_str::<AttesterData>(raw.trim())
                .map_err(|err| CliError::InvalidArgument(format!("invalid attester-data JSON: {err}")))?
        }
        None => AttesterData::default(),
    };

    let runtime = data.runtime_data.get_or_insert_with(Map::new);
    for entry in runtime_data {
        let (key, value) = parse_runtime_data_entry(entry)?;
        runtime.insert(key, value);
    }

    if let Some(pubkey) = attester_pubkey {
        runtime.insert("tee_pubkey".to_string(), public_key_to_jwk_value(pubkey)?);
    }

    Ok(data)
}

fn build_get_token_attester_data(attest_pubkey: &str, refvalue_ids: &[String]) -> Result<AttesterData, CliError> {
    let mut data = build_attester_data(Some(attest_pubkey), None, &[])?;
    if !refvalue_ids.is_empty() {
        data.runtime_data
            .get_or_insert_with(Map::new)
            .insert(
                "refvalue_ids".to_string(),
                Value::Array(refvalue_ids.iter().cloned().map(Value::String).collect()),
            );
    }
    Ok(data)
}

fn validate_string_list(values: &[String], max: usize, flag: &str) -> Result<(), CliError> {
    if values.len() > max {
        return Err(CliError::InvalidArgument(format!(
            "{flag} supports at most {max} items; got {}",
            values.len()
        )));
    }
    for value in values {
        validate_not_empty(value)?;
    }
    Ok(())
}

fn apply_policy_ids_to_evidence(value: Value, policy_ids: &[String]) -> Result<Value, CliError> {
    if policy_ids.is_empty() {
        return Ok(value);
    }

    let mut payload: RbcEvidencesPayload = serde_json::from_value(value)
        .map_err(|err| CliError::InvalidArgument(format!("invalid evidence JSON: {err}")))?;
    for measurement in &mut payload.measurements {
        if let Some(evidences) = &mut measurement.evidences {
            for evidence in evidences {
                evidence.policy_ids = Some(policy_ids.to_vec());
            }
        }
    }
    serde_json::to_value(payload).map_err(|_| CliError::InternalFormat)
}

fn parse_runtime_data_entry(entry: &str) -> Result<(String, Value), CliError> {
    let Some((key, value)) = entry.split_once('=') else {
        return Err(CliError::InvalidArgument(format!(
            "invalid --runtime-data `{entry}`; expected key=value"
        )));
    };
    validate_not_empty(key)?;
    let value = if let Some(path) = value.strip_prefix('@') {
        let content = fs::read_to_string(path).map_err(|_| {
            CliError::FileReadError(format!(
                "unable to read file `{path}`. Please check that the file exists and is readable"
            ))
        })?;
        parse_json_or_string(content.trim())
    } else {
        parse_json_or_string(value)
    };
    Ok((key.to_string(), value))
}

fn parse_json_or_string(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
}

fn public_key_to_jwk_value(input: &str) -> Result<Value, CliError> {
    let raw = read_path_file(input)?;
    let trimmed = raw.trim();

    if let Ok(jwk) = TeePublicKey::from_jwk_json(trimmed) {
        jwk.validate_params()?;
        return serde_json::from_str(trimmed)
            .map_err(|err| CliError::InvalidArgument(format!("invalid JWK JSON: {err}")));
    }

    let pkey = parse_public_key(trimmed.as_bytes())?;
    let jwk = match pkey.id() {
        Id::RSA => rsa_public_key_to_jwk(&pkey)?,
        Id::EC => ec_public_key_to_jwk(&pkey)?,
        other => {
            return Err(CliError::InvalidArgument(format!(
                "unsupported public key type `{other:?}`; expected RSA or EC"
            )))
        }
    };

    TeePublicKey::from_jwk_json(&serde_json::to_string(&jwk).map_err(|_| CliError::InternalFormat)?)
        .and_then(|key| key.validate_params().map(|_| key))
        ?;

    Ok(jwk)
}

fn parse_public_key(raw: &[u8]) -> Result<PKey<Public>, CliError> {
    PKey::public_key_from_pem(raw)
        .or_else(|_| X509::from_pem(raw).and_then(|cert| cert.public_key()))
        .map_err(|_| CliError::InvalidArgument("failed to parse public key or certificate PEM".to_string()))
}

fn rsa_public_key_to_jwk(pkey: &PKey<Public>) -> Result<Value, CliError> {
    let rsa = pkey
        .rsa()
        .map_err(|err| CliError::InvalidArgument(format!("failed to read RSA public key: {err}")))?;
    Ok(json!({
        "kty": "RSA",
        "alg": "RSA-OAEP-256",
        "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
        "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
    }))
}

fn ec_public_key_to_jwk(pkey: &PKey<Public>) -> Result<Value, CliError> {
    let ec_key = pkey
        .ec_key()
        .map_err(|err| CliError::InvalidArgument(format!("failed to read EC public key: {err}")))?;
    let group = ec_key.group();
    let curve = match group.curve_name() {
        Some(openssl::nid::Nid::X9_62_PRIME256V1) => ("P-256", 32usize),
        Some(openssl::nid::Nid::SECP384R1) => ("P-384", 48usize),
        Some(openssl::nid::Nid::SECP521R1) => ("P-521", 66usize),
        _ => {
            return Err(CliError::InvalidArgument(
                "unsupported EC curve; expected P-256, P-384, or P-521".to_string(),
            ))
        }
    };

    let mut ctx = BigNumContext::new()
        .map_err(|err| CliError::Message(format!("failed to allocate OpenSSL context: {err}")))?;
    let encoded = ec_key
        .public_key()
        .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|err| CliError::InvalidArgument(format!("failed to encode EC public key: {err}")))?;
    let expected_len = 1 + (curve.1 * 2);
    if encoded.len() != expected_len || encoded.first() != Some(&4) {
        return Err(CliError::InvalidArgument("unexpected EC public key encoding".to_string()));
    }

    let x = &encoded[1..1 + curve.1];
    let y = &encoded[1 + curve.1..];
    Ok(json!({
        "kty": "EC",
        "alg": "ECDH-ES+A256KW",
        "crv": curve.0,
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y),
    }))
}

fn maybe_decrypt_resource(resp: &ResourceContentResponse, args: &GetResArgs) -> Result<Vec<u8>, CliError> {
    let decoded = decode_resource_content(&resp.content);
    let Some(private_key_file) = args.private_key_file.as_ref() else {
        return Ok(decoded);
    };

    let (key_type, private_pem) = load_private_key_pem(private_key_file, &args.private_key_passphrase)?;
    let key_pair = TeeKeyPair::from_private_pem(key_type, &private_pem, None)?;
    let ciphertext = String::from_utf8(decoded)
        .map_err(|_| CliError::InvalidArgument("resource content is not valid UTF-8 JWE; cannot decrypt".to_string()))?;
    Ok(key_pair.decrypt_jwe(&ciphertext)?)
}

fn decode_resource_content(content: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(content)
        .unwrap_or_else(|_| content.as_bytes().to_vec())
}

fn load_private_key_pem(path: &str, passphrase: &Option<Option<String>>) -> Result<(KeyType, String), CliError> {
    let mut args = GenerateArgs::default();
    args.private_key_file = Some(path.to_string());
    args.private_key_passphrase = passphrase.clone();

    let private_key = TokenGenerate::load_private_key(&args)?;
    let pem = private_key
        .private_key_to_pem_pkcs8()
        .map_err(|err| CliError::InvalidArgument(format!("failed to export private key: {err}")))?;
    let pem = String::from_utf8(pem)
        .map_err(|err| CliError::InvalidArgument(format!("private key PEM is not valid UTF-8: {err}")))?;

    let key_type = match private_key.id() {
        Id::RSA => KeyType::Rsa,
        Id::EC => KeyType::Ec,
        other => {
            return Err(CliError::InvalidArgument(format!(
                "unsupported private key type `{other:?}`; expected RSA or EC"
            )))
        }
    };

    Ok((key_type, pem))
}

#[derive(Debug, Serialize)]
struct AuthOutput(AuthChallengeResponse);

impl Formatter for AuthOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(self.0.nonce.clone())
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct AttestOutput(AttestResponse);

impl Formatter for AttestOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(self.0.token.clone())
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct JsonValueOutput(Value);

impl Formatter for JsonValueOutput {
    fn render_text(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct ResourceOutput {
    uri: String,
    #[serde(skip_serializing)]
    content: Vec<u8>,
    content_type: Option<String>,
}

impl Formatter for ResourceOutput {
    fn render_text(&self) -> Result<String, CliError> {
        match String::from_utf8(self.content.clone()) {
            Ok(text) => Ok(text),
            Err(_) => Ok(base64::engine::general_purpose::STANDARD.encode(&self.content)),
        }
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&json!({
            "uri": self.uri,
            "content": base64::engine::general_purpose::STANDARD.encode(&self.content),
            "content_type": self.content_type,
        }))
        .map_err(|_| CliError::InternalFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_data_supports_json_and_string_values() {
        let (json_key, json_value) = parse_runtime_data_entry("count=1").expect("json runtime-data should parse");
        assert_eq!(json_key, "count");
        assert_eq!(json_value, Value::Number(1.into()));

        let (string_key, string_value) =
            parse_runtime_data_entry("name=alice").expect("string runtime-data should parse");
        assert_eq!(string_key, "name");
        assert_eq!(string_value, Value::String("alice".to_string()));
    }

    #[test]
    fn auth_output_text_is_bare_nonce() {
        let output = AuthOutput(AuthChallengeResponse {
            nonce: "nonce-value".to_string(),
        });
        assert_eq!(output.render_text().expect("render text"), "nonce-value");
    }

    #[test]
    fn resource_output_text_falls_back_to_base64_for_binary() {
        let output = ResourceOutput {
            uri: "vault/default/key/demo".to_string(),
            content: vec![0, 159, 146, 150],
            content_type: Some("binary".to_string()),
        };
        assert_eq!(
            output.render_text().expect("render text"),
            base64::engine::general_purpose::STANDARD.encode([0, 159, 146, 150])
        );
    }

    #[test]
    fn apply_policy_ids_updates_each_evidence_item() {
        let value = json!({
            "agent_version": "1.0.0",
            "measurements": [{
                "nonce": "nonce",
                "evidences": [
                    {"attester_type": "tpm_boot", "evidence": {"quote": "a"}},
                    {"attester_type": "tpm_ima", "evidence": {"quote": "b"}}
                ]
            }]
        });

        let updated = apply_policy_ids_to_evidence(value, &["policy-a".to_string(), "policy-b".to_string()])
            .expect("policy ids should apply");
        let evidences = updated["measurements"][0]["evidences"].as_array().expect("evidences array");
        assert_eq!(evidences[0]["policy_ids"], json!(["policy-a", "policy-b"]));
        assert_eq!(evidences[1]["policy_ids"], json!(["policy-a", "policy-b"]));
    }
}

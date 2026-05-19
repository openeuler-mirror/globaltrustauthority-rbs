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
use std::path::Path;

use base64::Engine as _;
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::x509::X509;
use rbs_api_types::{AttesterData, AuthChallengeResponse, RbcEvidencesPayload};
use serde_json::{json, Map, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::cli::args::{AttesterArgs, ClientAction, CollectEvidenceArgs, GetResourceArgs, GetTokenArgs};
use crate::cli::context::{ClientCommandContext, ExecutionOptions};
use crate::cli::output::{ClientOutput, ResourceOutput};
use crate::error::RbcError;
use crate::sdk::{GetResourceRequest, Session};
use crate::tools::tee_key::{KeyType, TeePublicKey};

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    InvalidArgument(String),

    #[error("{0}")]
    Message(String),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Rbc(#[from] RbcError),
}

pub fn execute_action(
    action: &ClientAction,
    context: &ClientCommandContext,
    options: &ExecutionOptions,
) -> Result<ClientOutput, CliError> {
    match action {
        ClientAction::Challenge(_) => execute_challenge(context, options),
        ClientAction::CollectEvidence(args) => execute_collect_evidence(args, context),
        ClientAction::GetToken(args) => execute_get_token(args, context),
        ClientAction::GetResource(args) => execute_get_resource(args, context, options),
    }
}

fn execute_challenge(context: &ClientCommandContext, options: &ExecutionOptions) -> Result<ClientOutput, CliError> {
    let _ = options;
    let client = context.build_rbc_client(None)?;
    let resp = client.get_auth_challenge()?;
    Ok(ClientOutput::Auth(resp))
}

fn execute_collect_evidence(
    args: &CollectEvidenceArgs,
    context: &ClientCommandContext,
) -> Result<ClientOutput, CliError> {
    let attester_data = build_attester_data(&AttesterArgs {
        attester_pubkey: Some(args.attester_pubkey.clone()),
        attester_data: args.attester_data.clone(),
        runtime_data: args.runtime_data.clone(),
    })?;
    let client = context.build_rbc_client(Some(&args.agent_config))?;
    let session = client.new_session(Some(&attester_data))?;
    let challenge = AuthChallengeResponse { nonce: read_trimmed_path_value(&args.nonce)? };
    let evidence = session.collect_evidence(&challenge)?;
    Ok(ClientOutput::JsonValue(evidence))
}

fn execute_get_token(args: &GetTokenArgs, context: &ClientCommandContext) -> Result<ClientOutput, CliError> {
    let resp = if let Some(evidence_input) = args.evidence.as_deref() {
        let evidence = read_evidence_payload(evidence_input)?;
        let client = context.build_rbc_client(Some(&args.agent_config))?;
        let session = client.new_session(None)?;
        let evidence = serde_json::to_value(evidence)?;
        session.attest(Some(&evidence))?
    } else {
        let client = context.build_rbc_client(Some(&args.agent_config))?;
        let attester_pubkey = args
            .attester_pubkey
            .clone()
            .ok_or_else(|| CliError::InvalidArgument("missing required attester-pubkey".to_string()))?;
        let attester_data = build_attester_data(&AttesterArgs {
            attester_pubkey: Some(attester_pubkey),
            attester_data: args.attester_data.clone(),
            runtime_data: args.runtime_data.clone(),
        })?;
        let session = client.new_session(Some(&attester_data))?;
        session.attest(None)?
    };
    Ok(ClientOutput::Attest(resp))
}

fn execute_get_resource(
    args: &GetResourceArgs,
    context: &ClientCommandContext,
    options: &ExecutionOptions,
) -> Result<ClientOutput, CliError> {
    let _ = options;
    let client = context.build_rbc_client(None)?;
    let session = client.new_session(None)?;
    let resource = if let Some(evidence_input) = args.evidence.as_deref() {
        let evidence = read_evidence_payload(evidence_input)?;
        let evidence = serde_json::to_value(evidence)?;
        session.get_resource(&args.uri, GetResourceRequest::ByEvidence { value: &evidence })?
    } else if let Some(token) = args.attest_token.as_deref() {
        let token = read_trimmed_path_value(token)?;
        session.get_resource(&args.uri, GetResourceRequest::ByAttestToken(&token))?
    } else {
        let token = args
            .bearer_token
            .as_deref()
            .ok_or_else(|| CliError::InvalidArgument("missing required bearer token; pass --bearer-token".to_string()))?;
        let token = read_trimmed_path_value(token)?;
        session.get_resource(&args.uri, GetResourceRequest::ByBearerToken(&token))?
    };

    let content = maybe_decrypt_resource(&session, resource.content.as_ref(), args)?;
    Ok(ClientOutput::Resource(ResourceOutput { uri: resource.uri, content, content_type: resource.content_type }))
}

fn read_evidence_payload(input: &str) -> Result<RbcEvidencesPayload, CliError> {
    if input == "-" {
        return Err(CliError::InvalidArgument(
            "stdin evidence input is not supported; pass inline JSON or @path".to_string(),
        ));
    }
    let raw = read_path_file(input)?;
    Ok(serde_json::from_str(raw.trim())?)
}

fn read_trimmed_path_value(input: &str) -> Result<String, CliError> {
    Ok(read_path_file(input)?.trim().to_string())
}

fn build_attester_data(args: &AttesterArgs) -> Result<AttesterData, CliError> {
    let mut data = match args.attester_data.as_deref() {
        Some(value) => {
            let raw = read_path_file(value)?;
            serde_json::from_str::<AttesterData>(raw.trim())
                .map_err(|err| CliError::InvalidArgument(format!("invalid attester-data JSON: {err}")))?
        },
        None => AttesterData::default(),
    };

    let runtime = data.runtime_data.get_or_insert_with(Map::new);
    for entry in &args.runtime_data {
        let (key, value) = parse_runtime_data_entry(entry)?;
        runtime.insert(key, value);
    }

    if let Some(pubkey) = args.attester_pubkey.as_deref() {
        runtime.insert("tee-pubkey".to_string(), public_key_to_jwk_value(pubkey)?);
    }

    Ok(data)
}

fn parse_runtime_data_entry(entry: &str) -> Result<(String, Value), CliError> {
    let Some((key, value)) = entry.split_once('=') else {
        return Err(CliError::InvalidArgument(format!("invalid --runtime-data `{entry}`; expected key=value")));
    };
    validate_not_empty(key)?;
    let value = if let Some(path) = value.strip_prefix('@') {
        let content = fs::read_to_string(path).map_err(|_| {
            CliError::Message(format!(
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
        jwk.validate_params().map_err(|err| CliError::InvalidArgument(err.to_string()))?;
        return Ok(serde_json::from_str(trimmed)?);
    }

    let pkey = parse_public_key(trimmed.as_bytes())?;
    let jwk = match pkey.id() {
        Id::RSA => rsa_public_key_to_jwk(&pkey)?,
        Id::EC => ec_public_key_to_jwk(&pkey)?,
        other => {
            return Err(CliError::InvalidArgument(format!(
                "unsupported public key type `{other:?}`; expected RSA or EC"
            )))
        },
    };

    TeePublicKey::from_jwk_json(&serde_json::to_string(&jwk)?)
        .and_then(|key| key.validate_params().map(|_| key))
        .map_err(|err| CliError::InvalidArgument(err.to_string()))?;

    Ok(jwk)
}

fn parse_public_key(raw: &[u8]) -> Result<PKey<Public>, CliError> {
    PKey::public_key_from_pem(raw)
        .or_else(|_| X509::from_pem(raw).and_then(|cert| cert.public_key()))
        .map_err(|_| CliError::InvalidArgument("failed to parse public key or certificate PEM".to_string()))
}

fn rsa_public_key_to_jwk(pkey: &PKey<Public>) -> Result<Value, CliError> {
    let rsa = pkey.rsa().map_err(|err| CliError::InvalidArgument(format!("failed to read RSA public key: {err}")))?;
    Ok(json!({
        "kty": "RSA",
        "alg": "RSA-OAEP-256",
        "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
        "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
    }))
}

fn ec_public_key_to_jwk(pkey: &PKey<Public>) -> Result<Value, CliError> {
    let ec_key =
        pkey.ec_key().map_err(|err| CliError::InvalidArgument(format!("failed to read EC public key: {err}")))?;
    let group = ec_key.group();
    let curve = match group.curve_name() {
        Some(openssl::nid::Nid::X9_62_PRIME256V1) => ("P-256", 32usize),
        Some(openssl::nid::Nid::SECP384R1) => ("P-384", 48usize),
        Some(openssl::nid::Nid::SECP521R1) => ("P-521", 66usize),
        _ => {
            return Err(CliError::InvalidArgument("unsupported EC curve; expected P-256, P-384, or P-521".to_string()))
        },
    };

    let mut ctx =
        BigNumContext::new().map_err(|err| CliError::Message(format!("failed to allocate OpenSSL context: {err}")))?;
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

fn maybe_decrypt_resource(session: &Session, content: &[u8], args: &GetResourceArgs) -> Result<Vec<u8>, CliError> {
    let Some(private_key_file) = args.private_key_file.as_ref() else {
        return Ok(content.to_vec());
    };

    let (_key_type, private_pem) = load_private_key_pem(private_key_file, &args.private_key_passphrase)?;
    let ciphertext = String::from_utf8(content.to_vec()).map_err(|_| {
        CliError::InvalidArgument("resource content is not valid UTF-8 JWE; cannot decrypt".to_string())
    })?;
    let passphrase = load_passphrase_bytes(&args.private_key_passphrase)?;
    let plaintext =
        session.decrypt_content(&ciphertext, Some(&private_pem), passphrase.as_ref().map(|value| value.as_slice()))?;
    Ok(plaintext.to_vec())
}

fn load_private_key_pem(path: &str, passphrase: &Option<Option<String>>) -> Result<(KeyType, String), CliError> {
    let private_key = load_private_key(path, passphrase)?;
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
        },
    };

    Ok((key_type, pem))
}

fn load_passphrase_bytes(passphrase: &Option<Option<String>>) -> Result<Option<Zeroizing<Vec<u8>>>, CliError> {
    let passphrase = load_passphrase(passphrase)?;
    Ok(passphrase.map(|value| Zeroizing::new(value.as_bytes().to_vec())))
}

fn load_private_key(path: &str, passphrase: &Option<Option<String>>) -> Result<PKey<Private>, CliError> {
    let private_key_pem = Zeroizing::new(fs::read(path).map_err(|_| {
        CliError::Message(format!(
            "unable to read private key file `{path}`. Please check that the file exists and is readable"
        ))
    })?);
    let passphrase = load_passphrase(passphrase)?;

    match &passphrase {
        Some(passphrase) => PKey::private_key_from_pem_passphrase(&private_key_pem, passphrase.as_bytes())
            .map_err(|err| CliError::InvalidArgument(format!("unable to read the encrypted private key: {err}"))),
        None => PKey::private_key_from_pem(&private_key_pem)
            .map_err(|err| CliError::InvalidArgument(format!("failed to parse private key PEM: {err}"))),
    }
}

fn load_passphrase(passphrase: &Option<Option<String>>) -> Result<Option<Zeroizing<String>>, CliError> {
    match passphrase {
        None => Ok(None),
        Some(None) => {
            if io::stdin().is_terminal() {
                Ok(Some(
                    rpassword::prompt_password("Private key passphrase: ")
                        .map(Zeroizing::new)
                        .map_err(|_| CliError::Message("unable to read the private key passphrase".to_string()))?,
                ))
            } else {
                let mut value = Zeroizing::new(String::new());
                io::stdin()
                    .read_to_string(&mut value)
                    .map_err(|_| CliError::Message("unable to read the private key passphrase".to_string()))?;
                trim_line_end(&mut value);
                Ok(Some(value))
            }
        },
        Some(Some(value)) => {
            let Some(path) = value.strip_prefix('@') else {
                return Err(CliError::InvalidArgument(
                    "private key passphrase must be provided as --private-key-passphrase @path or entered interactively with --private-key-passphrase".to_string(),
                ));
            };
            let mut value = Zeroizing::new(fs::read_to_string(path).map_err(|_| {
                CliError::Message(format!(
                    "unable to read private key passphrase file `{path}`. Please check that the file exists and is readable"
                ))
            })?);
            trim_line_end(&mut value);
            Ok(Some(value))
        },
    }
}

fn trim_line_end(value: &mut String) {
    while matches!(value.chars().last(), Some('\n' | '\r')) {
        value.pop();
    }
}

fn read_path_file(file: &str) -> Result<String, CliError> {
    if let Some(path) = file.strip_prefix('@') {
        return fs::read_to_string(path).map_err(|_| {
            CliError::Message(format!(
                "unable to read file `{path}`. Please check that the file exists and is readable"
            ))
        });
    }
    Ok(file.to_string())
}

pub fn validate_not_empty(value: &str) -> Result<String, CliError> {
    if value.trim().is_empty() {
        return Err(CliError::InvalidArgument("value is empty".to_string()));
    }
    Ok(value.to_string())
}

pub fn validate_file_path(file_path: &str) -> Result<String, CliError> {
    if file_path.trim().is_empty() {
        return Err(CliError::InvalidArgument("file path must not be empty".to_string()));
    }
    let path = Path::new(file_path);
    if path.exists() && path.is_dir() {
        return Err(CliError::InvalidArgument(format!("path `{file_path}` points to an existing directory")));
    }
    if path.file_name().is_none() {
        return Err(CliError::InvalidArgument(format!("file path `{file_path}` does not contain a file name")));
    }
    Ok(file_path.to_string())
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
    fn resource_output_text_falls_back_to_base64_for_binary() {
        let output = ClientOutput::Resource(ResourceOutput {
            uri: "vault/default/key/demo".to_string(),
            content: vec![0, 159, 146, 150],
            content_type: Some("binary".to_string()),
        });
        assert_eq!(
            output.render_text().expect("render text"),
            base64::engine::general_purpose::STANDARD.encode([0, 159, 146, 150])
        );
    }

    #[test]
    fn read_trimmed_path_value_trims_inline_and_file_input() {
        assert_eq!(read_trimmed_path_value("  token-value \n").expect("inline"), "token-value");

        let path = std::env::temp_dir().join(format!("rbc-trimmed-value-{}.txt", std::process::id()));
        std::fs::write(&path, "nonce-value\n").expect("write value file");
        let value = read_trimmed_path_value(&format!("@{}", path.display())).expect("file");
        assert_eq!(value, "nonce-value");
        let _ = std::fs::remove_file(path);
    }

}

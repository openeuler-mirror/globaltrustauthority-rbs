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
use josekit::jwe::JweHeader;
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::{Id, PKey, Public};
use openssl::x509::X509;
use rbs_api_types::{AttesterData, AuthChallengeResponse, RbcEvidencesPayload};
use serde_json::{json, Map, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::cli::args::{AttesterArgs, ClientAction, CollectEvidenceArgs, GetResourceArgs, GetTokenArgs};
use crate::cli::context::{ClientCommandContext, ExecutionOptions};
use crate::cli::output::{ClientOutput, ResourceOutput};
use crate::cli::utils::load_private_key_pem;
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
    let client = context.build_rbc_client(None)?;
    let session = client.new_session(Some(&attester_data))?;
    let challenge = AuthChallengeResponse { nonce: read_trimmed_path_value(&args.nonce)? };
    let evidence = session.collect_evidence(&challenge)?;
    Ok(ClientOutput::JsonValue(evidence))
}

fn execute_get_token(args: &GetTokenArgs, context: &ClientCommandContext) -> Result<ClientOutput, CliError> {
    let resp = if let Some(evidence_input) = args.evidence.as_deref() {
        let evidence = read_evidence_payload(evidence_input)?;
        let client = context.build_rbc_client(None)?;
        let session = client.new_session(None)?;
        let evidence = serde_json::to_value(evidence)?;
        session.attest(Some(&evidence))?
    } else {
        let client = context.build_rbc_client(None)?;
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
    let auto_attester_data = if args.passport || args.background {
        Some(build_attester_data(&AttesterArgs {
            attester_pubkey: None,
            attester_data: args.attester_data.clone(),
            runtime_data: args.runtime_data.clone(),
        })?)
    } else {
        None
    };
    let session = client.new_session(auto_attester_data.as_ref())?;
    let resource = if args.background {
        let challenge = client.get_auth_challenge()?;
        let evidence = session.collect_evidence(&challenge)?;
        session.get_resource(&args.uri, GetResourceRequest::ByEvidence { value: &evidence })?
    } else if args.passport {
        let attest = session.attest(None)?;
        session.get_resource(&args.uri, GetResourceRequest::ByAttestToken(&attest.token))?
    } else if let Some(evidence_input) = args.evidence.as_deref() {
        let evidence = read_evidence_payload(evidence_input)?;
        let evidence = serde_json::to_value(evidence)?;
        session.get_resource(&args.uri, GetResourceRequest::ByEvidence { value: &evidence })?
    } else if let Some(token) = args.attest_token.as_deref() {
        let token = read_trimmed_path_value(token)?;
        session.get_resource(&args.uri, GetResourceRequest::ByAttestToken(&token))?
    } else {
        return Err(CliError::InvalidArgument(
            "missing resource authentication mode; pass --attest-token, --evidence, --passport, or --background"
                .to_string(),
        ));
    };

    let content = if args.passport || args.background {
        maybe_decrypt_resource_with_session_key(&session, resource.content.as_ref(), resource.content_type.as_deref())?
    } else {
        maybe_decrypt_resource(&session, resource.content.as_ref(), args)?
    };
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
        // tee-pubkey is only ever consumed by RBS's JWE encryption path, which
        // supports RSA/EC only — reject SM2 up front instead of letting the
        // key through and failing at resource-retrieval time server-side.
        if jwk.key_type() == KeyType::Sm2 {
            return Err(CliError::InvalidArgument(
                "SM2 public keys are not supported for tee-pubkey: the JWE envelope only supports \
                 RSA (>= 4096 bits) and EC P-256/P-384/P-521; SM2 keys are for signing only"
                    .to_string(),
            ));
        }
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

    let passphrase = load_passphrase_bytes(&args.private_key_passphrase)?;
    let private_pem = load_private_key_pem(private_key_file, passphrase.as_ref().map(|value| value.as_slice()))?;
    let ciphertext = String::from_utf8(content.to_vec()).map_err(|_| {
        CliError::InvalidArgument("resource content is not valid UTF-8 JWE; cannot decrypt".to_string())
    })?;
    let plaintext = session.decrypt_content(
        &ciphertext,
        Some(private_pem.as_str()),
        passphrase.as_ref().map(|value| value.as_slice()),
    )?;
    Ok(plaintext.to_vec())
}

fn maybe_decrypt_resource_with_session_key(
    session: &Session,
    content: &[u8],
    content_type: Option<&str>,
) -> Result<Vec<u8>, CliError> {
    if !should_attempt_session_decrypt(content, content_type) {
        return Ok(content.to_vec());
    }

    let ciphertext = String::from_utf8(content.to_vec()).map_err(|_| {
        CliError::InvalidArgument("resource content is not valid UTF-8 JWE; cannot decrypt".to_string())
    })?;
    let plaintext = session.decrypt_content(&ciphertext, None, None)?;
    Ok(plaintext.to_vec())
}

fn should_attempt_session_decrypt(content: &[u8], content_type: Option<&str>) -> bool {
    if matches!(content_type, Some("jwe")) {
        return true;
    }

    let Ok(value) = std::str::from_utf8(content) else {
        return false;
    };
    let mut parts = value.split('.');
    let Some(protected_header) = parts.next() else {
        return false;
    };
    if parts.count() != 4 {
        return false;
    }

    let Ok(header_json) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(protected_header) else {
        return false;
    };
    let Ok(header) = JweHeader::from_bytes(&header_json) else {
        return false;
    };
    header.algorithm().is_some() && header.content_encryption().is_some()
}

fn load_passphrase_bytes(passphrase: &Option<Option<String>>) -> Result<Option<Zeroizing<Vec<u8>>>, CliError> {
    let passphrase = load_passphrase(passphrase)?;
    Ok(passphrase.map(|value| Zeroizing::new(value.as_bytes().to_vec())))
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::symm::Cipher;
    use openssl::x509::X509NameBuilder;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::cli::args::{AgentConfigArgs, ChallengeArgs};
    use crate::sdk::{ProviderRawConfig, ProviderType, Session};
    use crate::tools::tee_key::TeeKeyPair;

    use super::*;

    /// Sequence used to keep concurrent temporary file names unique.
    static TEMP_FILE_SEQ: AtomicUsize = AtomicUsize::new(0);

    /// Temporary file that removes itself when the test ends.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(name: &str, contents: impl AsRef<[u8]>) -> Self {
            let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("rbc-execute-{}-{seq}-{name}", std::process::id()));
            fs::write(&path, contents.as_ref()).expect("write temporary file");
            Self { path }
        }

        /// Return the `@path` CLI form of this file.
        fn at(&self) -> String {
            format!("@{}", self.path.display())
        }

        /// Return the plain path form of this file.
        fn path(&self) -> String {
            self.path.display().to_string()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    /// Path that is guaranteed not to exist under the temporary directory.
    fn missing_path(name: &str) -> String {
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("rbc-execute-missing-{}-{seq}-{name}", std::process::id()))
            .display()
            .to_string()
    }

    /// Context without evidence/token providers: the RBS client builds offline and
    /// the native providers (which need a real attestation agent) are never created.
    fn offline_context(base_url: &str) -> ClientCommandContext {
        ClientCommandContext {
            base_url: base_url.to_string(),
            cert_path: None,
            timeout_secs: Some(10),
            key_algorithm: KeyType::Ec,
            agent_config: missing_path("agent_config.yaml"),
            evidence_provider: None,
            token_provider: None,
        }
    }

    /// Get-resource arguments with every authentication mode disabled.
    fn get_resource_args(uri: &str) -> GetResourceArgs {
        GetResourceArgs {
            agent: AgentConfigArgs { agent_config: missing_path("agent_config.yaml") },
            uri: uri.to_string(),
            attest_token: None,
            evidence: None,
            passport: false,
            background: false,
            attester_data: None,
            runtime_data: vec![],
            private_key_file: None,
            private_key_passphrase: None,
        }
    }

    /// Public key PEM of an OpenSSL-generated EC key on `curve`.
    fn ec_public_pem(curve: Nid) -> String {
        let group = EcGroup::from_curve_name(curve).expect("create ec group");
        let ec_key = EcKey::generate(&group).expect("generate ec key");
        let pkey = PKey::from_ec_key(ec_key).expect("build ec pkey");
        String::from_utf8(pkey.public_key_to_pem().expect("export ec public pem")).expect("utf8 ec public pem")
    }

    /// Public key PEM of an existing TEE key pair.
    fn tee_public_pem(key: &TeeKeyPair) -> String {
        let private_pem = key.to_private_pem().expect("export private pem");
        let pkey = PKey::private_key_from_pem(private_pem.as_bytes()).expect("parse private pem");
        String::from_utf8(pkey.public_key_to_pem().expect("export public pem")).expect("utf8 public pem")
    }

    /// Self-signed X.509 certificate PEM carrying an EC P-256 public key.
    fn self_signed_cert_pem() -> String {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("create ec group");
        let ec_key = EcKey::generate(&group).expect("generate ec key");
        let pkey = PKey::from_ec_key(ec_key).expect("build ec pkey");

        let mut name = X509NameBuilder::new().expect("create x509 name");
        name.append_entry_by_text("CN", "rbc-execute-test").expect("set common name");
        let name = name.build();

        let mut builder = X509::builder().expect("create x509 builder");
        builder.set_version(2).expect("set x509 version");
        let serial = openssl::bn::BigNum::from_u32(1).expect("create serial");
        builder.set_serial_number(&serial.to_asn1_integer().expect("encode serial")).expect("set serial");
        let not_before = Asn1Time::days_from_now(0).expect("not before");
        builder.set_not_before(&not_before).expect("set not before");
        let not_after = Asn1Time::days_from_now(1).expect("not after");
        builder.set_not_after(&not_after).expect("set not after");
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder.set_pubkey(&pkey).expect("set cert pubkey");
        builder.sign(&pkey, MessageDigest::sha256()).expect("sign certificate");
        String::from_utf8(builder.build().to_pem().expect("export certificate pem")).expect("utf8 certificate pem")
    }

    /// Build an offline client solely so a `Session` exists for helper-level tests.
    fn offline_session() -> Session {
        offline_context("http://127.0.0.1:1")
            .build_rbc_client(None)
            .expect("build offline client")
            .new_session(None)
            .expect("create offline session")
    }

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

    #[test]
    fn should_attempt_session_decrypt_detects_jwe_content() {
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RSA-OAEP-256","enc":"A256GCM"}"#);
        let jwe = format!("{header}.encrypted_key.iv.ciphertext.tag");

        assert!(should_attempt_session_decrypt(jwe.as_bytes(), Some("text")));
        assert!(should_attempt_session_decrypt(b"not-even-utf8", Some("jwe")));
        assert!(!should_attempt_session_decrypt(b"1.2.3.4.5", Some("text")));
        assert!(!should_attempt_session_decrypt(b"eyJhbGciOiJSU0EtT0FFUC0yNTYifQ.a.b.c.d", Some("text")));
        assert!(!should_attempt_session_decrypt(b"not-base64.a.b.c.d", Some("text")));
        assert!(!should_attempt_session_decrypt(b"{\"hello\":\"world\"}", Some("json")));
    }

    // Validate RBC CLI required strings and path inputs before any network call.
    #[test]
    fn cli_validator_boundary_matrix() {
        assert!(validate_not_empty("x").is_ok());
        assert!(validate_not_empty("  ").is_err());
        assert!(validate_file_path("relative.pem").is_ok());
        assert!(validate_file_path("").is_err());
        assert!(validate_file_path(".").is_err());
    }

    #[test]
    fn validate_file_path_rejects_path_without_file_name() {
        let err = validate_file_path("/rbc-execute-missing-dir/..").err().expect("path without file name rejected");
        assert!(matches!(err, CliError::InvalidArgument(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("does not contain a file name"), "unexpected message: {err}");
    }

    // --attester-pubkey must never accept SM2 JWKs: the tee-pubkey only feeds
    // RBS's JWE encryption, which has no SM2 support — a bare SM2 JWK passes
    // the shared key validation but would make every resource GET fail
    // server-side with 400 JWE encryption failed.
    #[test]
    fn public_key_to_jwk_value_rejects_sm2_jwk() {
        let jwk = crate::tools::tee_key::TeeKeyPair::generate(crate::tools::tee_key::KeyType::Sm2)
            .unwrap()
            .public_jwk_json()
            .unwrap();
        let err = public_key_to_jwk_value(&jwk).err().unwrap();
        assert!(err.to_string().contains("SM2"), "expected SM2 rejection, got: {err}");
    }

    #[test]
    fn build_attester_data_merges_inline_json_and_runtime_entries() {
        let args = AttesterArgs {
            attester_pubkey: None,
            attester_data: Some(r#"{"runtime_data":{"from-json":"value"}}"#.to_string()),
            runtime_data: vec!["count=1".to_string(), "name=alice".to_string()],
        };

        let runtime =
            build_attester_data(&args).expect("attester data should build").runtime_data.expect("runtime data");

        assert_eq!(runtime["from-json"], Value::String("value".to_string()));
        assert_eq!(runtime["count"], Value::Number(1.into()));
        assert_eq!(runtime["name"], Value::String("alice".to_string()));
    }

    #[test]
    fn build_attester_data_rejects_invalid_attester_data_json() {
        let args =
            AttesterArgs { attester_pubkey: None, attester_data: Some("{not-json".to_string()), runtime_data: vec![] };

        let err = build_attester_data(&args).err().expect("invalid JSON must be rejected");
        assert!(err.to_string().contains("invalid attester-data JSON"), "unexpected message: {err}");
    }

    #[test]
    fn build_attester_data_reads_runtime_data_from_files() {
        let json_file = TempFile::new("runtime-data.json", r#"{"nested":true}"#);
        let plain_file = TempFile::new("runtime-data.txt", "plain-value\n");
        let args = AttesterArgs {
            attester_pubkey: None,
            attester_data: None,
            runtime_data: vec![format!("json={}", json_file.at()), format!("plain={}", plain_file.at())],
        };

        let runtime =
            build_attester_data(&args).expect("attester data should build").runtime_data.expect("runtime data");

        assert_eq!(runtime["json"], json!({"nested": true}));
        assert_eq!(runtime["plain"], Value::String("plain-value".to_string()));
    }

    #[test]
    fn build_attester_data_embeds_attester_pubkey_as_tee_pubkey() {
        let pem_file = TempFile::new("attester-pubkey.pem", ec_public_pem(Nid::X9_62_PRIME256V1));
        let args = AttesterArgs {
            attester_pubkey: Some(pem_file.at()),
            attester_data: Some(r#"{"runtime_data":{"user-field":"user-value"}}"#.to_string()),
            runtime_data: vec![],
        };

        let runtime =
            build_attester_data(&args).expect("attester data should build").runtime_data.expect("runtime data");

        assert_eq!(runtime["user-field"], Value::String("user-value".to_string()));
        assert_eq!(runtime["tee-pubkey"]["kty"], Value::String("EC".to_string()));
        assert_eq!(runtime["tee-pubkey"]["crv"], Value::String("P-256".to_string()));
    }

    #[test]
    fn parse_runtime_data_entry_reports_unreadable_file() {
        let err = parse_runtime_data_entry(&format!("key=@{}", missing_path("runtime-data.txt")))
            .err()
            .expect("missing runtime-data file must be rejected");
        assert!(err.to_string().contains("unable to read file"), "unexpected message: {err}");
    }

    #[test]
    fn parse_runtime_data_entry_rejects_missing_separator_and_empty_key() {
        let err = parse_runtime_data_entry("no-separator").err().expect("missing '=' must be rejected");
        assert!(err.to_string().contains("expected key=value"), "unexpected message: {err}");

        let err = parse_runtime_data_entry("=value").err().expect("empty key must be rejected");
        assert!(err.to_string().contains("value is empty"), "unexpected message: {err}");
    }

    #[test]
    fn public_key_to_jwk_value_supports_ec_curves() {
        for (curve, name, coord_len) in
            [(Nid::X9_62_PRIME256V1, "P-256", 32usize), (Nid::SECP384R1, "P-384", 48), (Nid::SECP521R1, "P-521", 66)]
        {
            let pem_file = TempFile::new(&format!("ec-{name}.pem"), ec_public_pem(curve));
            let jwk = public_key_to_jwk_value(&pem_file.at()).expect("EC public key should convert");

            assert_eq!(jwk["kty"], Value::String("EC".to_string()));
            assert_eq!(jwk["alg"], Value::String("ECDH-ES+A256KW".to_string()));
            assert_eq!(jwk["crv"], Value::String(name.to_string()));
            for coord in ["x", "y"] {
                let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk[coord].as_str().expect("coordinate string"))
                    .expect("coordinate should be base64url");
                assert_eq!(decoded.len(), coord_len, "unexpected {coord} length for {name}");
            }
        }
    }

    #[test]
    fn public_key_to_jwk_value_supports_rsa_pem_and_jwk_input() {
        let key = TeeKeyPair::generate(KeyType::Rsa).expect("generate rsa key pair");

        let pem_file = TempFile::new("rsa-public.pem", tee_public_pem(&key));
        let jwk = public_key_to_jwk_value(&pem_file.at()).expect("RSA public key should convert");
        assert_eq!(jwk["kty"], Value::String("RSA".to_string()));
        assert_eq!(jwk["alg"], Value::String("RSA-OAEP-256".to_string()));
        let modulus_len =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(jwk["n"].as_str().expect("modulus")).unwrap().len();
        assert_eq!(modulus_len, 512, "RSA modulus must be 4096 bits");
        let exponent =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(jwk["e"].as_str().expect("exponent")).unwrap();
        assert_eq!(exponent, vec![1, 0, 1], "default RSA exponent should be 65537");

        let jwk_file = TempFile::new("rsa-public-jwk.json", key.public_jwk_json().expect("export rsa jwk"));
        let passthrough = public_key_to_jwk_value(&jwk_file.at()).expect("RSA JWK should pass through");
        assert_eq!(passthrough["kty"], Value::String("RSA".to_string()));
        assert_eq!(passthrough["n"], jwk["n"]);
    }

    #[test]
    fn public_key_to_jwk_value_reads_x509_certificate() {
        let cert_file = TempFile::new("attester-cert.pem", self_signed_cert_pem());

        let jwk = public_key_to_jwk_value(&cert_file.at()).expect("certificate public key should convert");

        assert_eq!(jwk["kty"], Value::String("EC".to_string()));
        assert_eq!(jwk["crv"], Value::String("P-256".to_string()));
    }

    #[test]
    fn public_key_to_jwk_value_rejects_unsupported_ec_curve() {
        let pem_file = TempFile::new("ec-secp256k1.pem", ec_public_pem(Nid::SECP256K1));

        let err = public_key_to_jwk_value(&pem_file.at()).err().expect("secp256k1 must be rejected");
        assert!(err.to_string().contains("unsupported EC curve"), "unexpected message: {err}");
    }

    #[test]
    fn public_key_to_jwk_value_rejects_non_rsa_ec_key_types() {
        let ed25519 = PKey::generate_ed25519().expect("generate ed25519 key");
        let pem_file = TempFile::new("ed25519.pem", ed25519.public_key_to_pem().expect("export ed25519 public key"));

        let err = public_key_to_jwk_value(&pem_file.at()).err().expect("Ed25519 must be rejected");
        assert!(err.to_string().contains("unsupported public key type"), "unexpected message: {err}");
    }

    #[test]
    fn public_key_to_jwk_value_rejects_invalid_pem() {
        let pem_file = TempFile::new("invalid-public.pem", "this is not a PEM file");

        let err = public_key_to_jwk_value(&pem_file.at()).err().expect("invalid PEM must be rejected");
        assert!(err.to_string().contains("failed to parse public key or certificate PEM"), "unexpected message: {err}");
    }

    #[test]
    fn read_evidence_payload_accepts_inline_and_file_json() {
        let inline = read_evidence_payload(r#"{"agent_version":"1.0","measurements":[]}"#)
            .expect("inline evidence should parse");
        assert_eq!(inline.agent_version.as_deref(), Some("1.0"));
        assert!(inline.measurements.is_empty());

        let evidence_file = TempFile::new("evidence.json", r#"{"measurements":[]}"#);
        let from_file = read_evidence_payload(&evidence_file.at()).expect("file evidence should parse");
        assert!(from_file.agent_version.is_none());
        assert!(from_file.measurements.is_empty());
    }

    #[test]
    fn read_evidence_payload_rejects_stdin_marker_and_invalid_json() {
        let err = read_evidence_payload("-").err().expect("stdin evidence must be rejected");
        assert!(matches!(err, CliError::InvalidArgument(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("stdin evidence input is not supported"));

        let err = read_evidence_payload("{not-json").err().expect("invalid evidence JSON must be rejected");
        assert!(matches!(err, CliError::Json(_)), "unexpected error: {err}");
    }

    #[test]
    fn read_path_file_supports_inline_text_and_reports_missing_files() {
        assert_eq!(read_path_file(" plain-token ").expect("inline value"), " plain-token ");

        let path = missing_path("value.txt");
        let err = read_path_file(&format!("@{path}")).err().expect("missing file must be rejected");
        assert!(matches!(err, CliError::Message(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("unable to read file"), "unexpected message: {err}");
    }

    #[test]
    fn load_passphrase_reads_at_file_and_rejects_unsupported_inputs() {
        assert!(load_passphrase(&None).expect("absent passphrase").is_none());

        let passphrase_file = TempFile::new("passphrase.txt", "secret-value\r\n");
        let loaded = load_passphrase(&Some(Some(passphrase_file.at()))).expect("file passphrase").expect("passphrase");
        assert_eq!(loaded.as_str(), "secret-value");

        let err = load_passphrase(&Some(Some("inline-secret".to_string()))).err().expect("inline passphrase rejected");
        assert!(matches!(err, CliError::InvalidArgument(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("must be provided as --private-key-passphrase @path"));

        let err = load_passphrase(&Some(Some(format!("@{}", missing_path("passphrase.txt")))))
            .err()
            .expect("missing passphrase file rejected");
        assert!(matches!(err, CliError::Message(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("unable to read private key passphrase file"));
    }

    #[test]
    fn load_passphrase_bytes_returns_trimmed_bytes() {
        assert!(load_passphrase_bytes(&None).expect("absent passphrase").is_none());

        let passphrase_file = TempFile::new("passphrase-bytes.txt", "byte-secret\n");
        let bytes = load_passphrase_bytes(&Some(Some(passphrase_file.at())))
            .expect("file passphrase")
            .expect("passphrase bytes");
        assert_eq!(bytes.as_slice(), b"byte-secret");
    }

    #[test]
    fn trim_line_end_strips_trailing_line_endings() {
        let mut value = "value\r\n\n".to_string();
        trim_line_end(&mut value);
        assert_eq!(value, "value");

        let mut empty = String::new();
        trim_line_end(&mut empty);
        assert!(empty.is_empty());
    }

    #[test]
    fn maybe_decrypt_resource_passes_content_through_without_private_key() {
        let session = offline_session();
        let args = get_resource_args("vault/default/secret/demo");

        let content = maybe_decrypt_resource(&session, b"plain-content", &args).expect("passthrough content");

        assert_eq!(content, b"plain-content");
    }

    #[test]
    fn maybe_decrypt_resource_decrypts_with_plain_private_key_file() {
        let key = TeeKeyPair::generate(KeyType::Ec).expect("generate ec key pair");
        let key_file = TempFile::new("private-ec.pem", key.to_private_pem().expect("export private pem"));
        let jwe = key.public_key().encrypt_jwe(b"decrypted-secret").expect("encrypt content");

        let mut args = get_resource_args("vault/default/secret/demo");
        args.private_key_file = Some(key_file.path());

        let content = maybe_decrypt_resource(&offline_session(), jwe.as_bytes(), &args).expect("decrypt content");

        assert_eq!(content, b"decrypted-secret");
    }

    #[test]
    fn maybe_decrypt_resource_decrypts_with_passphrase_file() {
        let key = TeeKeyPair::generate(KeyType::Ec).expect("generate ec key pair");
        let private_pem = key.to_private_pem().expect("export private pem");
        let pkey = PKey::private_key_from_pem(private_pem.as_bytes()).expect("parse private pem");
        let encrypted_pem =
            pkey.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"passphrase-value").expect("encrypt pem");
        let key_file = TempFile::new("private-encrypted.pem", encrypted_pem);
        let passphrase_file = TempFile::new("private-passphrase.txt", "passphrase-value\n");
        let jwe = key.public_key().encrypt_jwe(b"passphrase-secret").expect("encrypt content");

        let mut args = get_resource_args("vault/default/secret/demo");
        args.private_key_file = Some(key_file.path());
        args.private_key_passphrase = Some(Some(passphrase_file.at()));

        let content = maybe_decrypt_resource(&offline_session(), jwe.as_bytes(), &args).expect("decrypt content");

        assert_eq!(content, b"passphrase-secret");
    }

    #[test]
    fn maybe_decrypt_resource_rejects_non_utf8_content() {
        let key = TeeKeyPair::generate(KeyType::Ec).expect("generate ec key pair");
        let key_file = TempFile::new("private-ec-non-utf8.pem", key.to_private_pem().expect("export private pem"));

        let mut args = get_resource_args("vault/default/secret/demo");
        args.private_key_file = Some(key_file.path());

        let err =
            maybe_decrypt_resource(&offline_session(), &[0xff, 0xfe], &args).err().expect("binary content rejected");
        assert!(matches!(err, CliError::InvalidArgument(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("not valid UTF-8 JWE"));
    }

    #[test]
    fn maybe_decrypt_resource_with_session_key_passes_through_and_decrypts() {
        let session = offline_session();

        let plain = maybe_decrypt_resource_with_session_key(&session, b"plain-content", Some("text"))
            .expect("passthrough content");
        assert_eq!(plain, b"plain-content");

        let ephemeral_jwk = session.test_ephemeral_public_jwk_json().expect("session ephemeral jwk");
        let public_key = TeePublicKey::from_jwk_json(&ephemeral_jwk).expect("parse ephemeral jwk");
        let jwe = public_key.encrypt_jwe(b"session-secret").expect("encrypt content");

        let decrypted =
            maybe_decrypt_resource_with_session_key(&session, jwe.as_bytes(), Some("jwe")).expect("decrypt content");
        assert_eq!(decrypted, b"session-secret");

        let err = maybe_decrypt_resource_with_session_key(&session, &[0xff, 0xfe], Some("jwe"))
            .err()
            .expect("binary JWE rejected");
        assert!(err.to_string().contains("not valid UTF-8 JWE"), "unexpected message: {err}");
    }

    #[test]
    fn should_attempt_session_decrypt_rejects_binary_and_malformed_headers() {
        assert!(!should_attempt_session_decrypt(&[0xff, 0xfe], Some("text")));

        let not_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-jwe-header");
        let jwe_like = format!("{not_json}.a.b.c.d");
        assert!(!should_attempt_session_decrypt(jwe_like.as_bytes(), Some("text")));
    }

    #[test]
    fn execute_get_token_requires_attester_pubkey_without_evidence() {
        let context = offline_context("http://127.0.0.1:1");
        let args = GetTokenArgs {
            agent: AgentConfigArgs { agent_config: context.agent_config.clone() },
            attester_pubkey: None,
            attester_data: None,
            runtime_data: vec![],
            evidence: None,
        };

        let err =
            execute_action(&ClientAction::GetToken(args), &context, &ExecutionOptions::default()).err().expect("error");

        assert!(matches!(err, CliError::InvalidArgument(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("missing required attester-pubkey"));
    }

    #[test]
    fn execute_get_token_with_pubkey_requires_token_provider() {
        let context = offline_context("http://127.0.0.1:1");
        let pubkey_file = TempFile::new("get-token-pubkey.pem", ec_public_pem(Nid::X9_62_PRIME256V1));
        let args = GetTokenArgs {
            agent: AgentConfigArgs { agent_config: context.agent_config.clone() },
            attester_pubkey: Some(pubkey_file.at()),
            attester_data: None,
            runtime_data: vec!["env=test".to_string()],
            evidence: None,
        };

        let err =
            execute_action(&ClientAction::GetToken(args), &context, &ExecutionOptions::default()).err().expect("error");

        assert!(matches!(err, CliError::Rbc(RbcError::ProviderError(_))), "unexpected error: {err}");
    }

    #[test]
    fn execute_get_token_rejects_invalid_attester_data() {
        let context = offline_context("http://127.0.0.1:1");
        let pubkey_file = TempFile::new("get-token-pubkey-json.pem", ec_public_pem(Nid::X9_62_PRIME256V1));
        let args = GetTokenArgs {
            agent: AgentConfigArgs { agent_config: context.agent_config.clone() },
            attester_pubkey: Some(pubkey_file.at()),
            attester_data: Some("{not-json".to_string()),
            runtime_data: vec![],
            evidence: None,
        };

        let err =
            execute_action(&ClientAction::GetToken(args), &context, &ExecutionOptions::default()).err().expect("error");

        assert!(matches!(err, CliError::InvalidArgument(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("invalid attester-data JSON"));
    }

    #[test]
    fn execute_collect_evidence_requires_evidence_provider() {
        let context = offline_context("http://127.0.0.1:1");
        let pubkey_file = TempFile::new("collect-pubkey.pem", ec_public_pem(Nid::X9_62_PRIME256V1));
        let args = CollectEvidenceArgs {
            agent: AgentConfigArgs { agent_config: context.agent_config.clone() },
            nonce: "nonce-value".to_string(),
            attester_pubkey: pubkey_file.at(),
            attester_data: None,
            runtime_data: vec![],
        };

        let err = execute_action(&ClientAction::CollectEvidence(args), &context, &ExecutionOptions::default())
            .err()
            .expect("error");

        assert!(matches!(err, CliError::Rbc(RbcError::ProviderError(_))), "unexpected error: {err}");
    }

    #[test]
    fn execute_collect_evidence_reports_missing_nonce_file() {
        let context = offline_context("http://127.0.0.1:1");
        let pubkey_file = TempFile::new("collect-pubkey-missing-nonce.pem", ec_public_pem(Nid::X9_62_PRIME256V1));
        let args = CollectEvidenceArgs {
            agent: AgentConfigArgs { agent_config: context.agent_config.clone() },
            nonce: format!("@{}", missing_path("nonce.txt")),
            attester_pubkey: pubkey_file.at(),
            attester_data: None,
            runtime_data: vec![],
        };

        let err = execute_action(&ClientAction::CollectEvidence(args), &context, &ExecutionOptions::default())
            .err()
            .expect("error");

        assert!(matches!(err, CliError::Message(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("unable to read file"));
    }

    #[test]
    fn execute_get_resource_requires_authentication_mode() {
        let context = offline_context("http://127.0.0.1:1");
        let args = get_resource_args("vault/default/secret/demo");

        let err = execute_action(&ClientAction::GetResource(args), &context, &ExecutionOptions::default())
            .err()
            .expect("error");

        assert!(matches!(err, CliError::InvalidArgument(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("missing resource authentication mode"));
    }

    #[test]
    fn execute_get_resource_auto_flow_rejects_invalid_runtime_data() {
        let context = offline_context("http://127.0.0.1:1");
        let mut args = get_resource_args("vault/default/secret/demo");
        args.passport = true;
        args.runtime_data = vec!["missing-separator".to_string()];

        let err = execute_action(&ClientAction::GetResource(args), &context, &ExecutionOptions::default())
            .err()
            .expect("error");

        assert!(matches!(err, CliError::InvalidArgument(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("expected key=value"));
    }

    #[test]
    fn execute_passport_flow_requires_token_provider() {
        let context = offline_context("http://127.0.0.1:1");
        let mut args = get_resource_args("vault/default/secret/demo");
        args.passport = true;

        let err = execute_action(&ClientAction::GetResource(args), &context, &ExecutionOptions::default())
            .err()
            .expect("error");

        assert!(matches!(err, CliError::Rbc(RbcError::ProviderError(_))), "unexpected error: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_action_challenge_returns_nonce() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rbs/v0/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"nonce": "nonce-from-rbs"})))
            .mount(&server)
            .await;

        let context = offline_context(&server.uri());
        let output = tokio::task::spawn_blocking(move || {
            execute_action(&ClientAction::Challenge(ChallengeArgs::default()), &context, &ExecutionOptions::default())
        })
        .await
        .expect("blocking task should join")
        .expect("challenge should succeed");

        match output {
            ClientOutput::Auth(resp) => assert_eq!(resp.nonce, "nonce-from-rbs"),
            other => panic!("expected auth output, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_action_challenge_maps_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rbs/v0/challenge"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let context = offline_context(&server.uri());
        let err = tokio::task::spawn_blocking(move || {
            execute_action(&ClientAction::Challenge(ChallengeArgs::default()), &context, &ExecutionOptions::default())
        })
        .await
        .expect("blocking task should join")
        .err()
        .expect("HTTP 500 must fail");

        assert!(matches!(err, CliError::Rbc(RbcError::ServerError(_))), "unexpected error: {err}");
        assert!(err.to_string().contains("HTTP 500"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_action_get_resource_with_attest_token_returns_content() {
        let server = MockServer::start().await;
        let uri = "vault/default/secret/demo";
        Mock::given(method("GET"))
            .and(path(format!("/rbs/v0/{uri}")))
            .and(header("Authorization", "Attest attest-token-value"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uri": uri,
                "content": base64::engine::general_purpose::STANDARD.encode("hello"),
                "content_type": "text",
                "export_mode": "jwe",
            })))
            .mount(&server)
            .await;

        let context = offline_context(&server.uri());
        let mut args = get_resource_args(uri);
        args.attest_token = Some("attest-token-value".to_string());
        let output = tokio::task::spawn_blocking(move || {
            execute_action(&ClientAction::GetResource(args), &context, &ExecutionOptions::default())
        })
        .await
        .expect("blocking task should join")
        .expect("resource retrieval should succeed");

        match output {
            ClientOutput::Resource(resource) => {
                assert_eq!(resource.uri, uri);
                assert_eq!(resource.content, b"hello");
                assert_eq!(resource.content_type.as_deref(), Some("text"));
            },
            other => panic!("expected resource output, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_action_get_resource_with_evidence_posts_retrieve() {
        let server = MockServer::start().await;
        let uri = "vault/default/secret/demo";
        Mock::given(method("POST"))
            .and(path(format!("/rbs/v0/{uri}/retrieve")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uri": uri,
                "content": base64::engine::general_purpose::STANDARD.encode("evidence-hello"),
                "content_type": "text",
                "export_mode": "jwe",
            })))
            .mount(&server)
            .await;

        let context = offline_context(&server.uri());
        let evidence_file = TempFile::new("get-resource-evidence.json", r#"{"agent_version":"1.0","measurements":[]}"#);
        let mut args = get_resource_args(uri);
        args.evidence = Some(evidence_file.at());
        let output = tokio::task::spawn_blocking(move || {
            execute_action(&ClientAction::GetResource(args), &context, &ExecutionOptions::default())
        })
        .await
        .expect("blocking task should join")
        .expect("evidence retrieval should succeed");

        match output {
            ClientOutput::Resource(resource) => {
                assert_eq!(resource.uri, uri);
                assert_eq!(resource.content, b"evidence-hello");
            },
            other => panic!("expected resource output, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_action_get_resource_maps_not_found() {
        let server = MockServer::start().await;
        let uri = "vault/default/secret/missing";
        Mock::given(method("GET"))
            .and(path(format!("/rbs/v0/{uri}")))
            .respond_with(ResponseTemplate::new(404).set_body_string("resource not found"))
            .mount(&server)
            .await;

        let context = offline_context(&server.uri());
        let mut args = get_resource_args(uri);
        args.attest_token = Some("attest-token-value".to_string());
        let err = tokio::task::spawn_blocking(move || {
            execute_action(&ClientAction::GetResource(args), &context, &ExecutionOptions::default())
        })
        .await
        .expect("blocking task should join")
        .err()
        .expect("HTTP 404 must fail");

        assert!(matches!(err, CliError::Rbc(RbcError::ResourceNotFound(_))), "unexpected error: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_action_get_resource_background_flow_requires_evidence_provider() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rbs/v0/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"nonce": "nonce-from-rbs"})))
            .mount(&server)
            .await;

        let context = offline_context(&server.uri());
        let mut args = get_resource_args("vault/default/secret/demo");
        args.background = true;
        let err = tokio::task::spawn_blocking(move || {
            execute_action(&ClientAction::GetResource(args), &context, &ExecutionOptions::default())
        })
        .await
        .expect("blocking task should join")
        .err()
        .expect("background flow without an evidence provider must fail");

        assert!(matches!(err, CliError::Rbc(RbcError::ProviderError(_))), "unexpected error: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_action_get_token_with_evidence_returns_attest_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rbs/v0/attest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"token": "jwt-token-abc"})))
            .mount(&server)
            .await;

        let agent_config =
            TempFile::new("agent-config.yaml", "agent:\n  user_id: \"test-user\"\n  apikey: \"test-key\"\n");
        let evidence_file = TempFile::new("get-token-evidence.json", r#"{"agent_version":"1.0","measurements":[]}"#);
        let mut context = offline_context(&server.uri());
        context.agent_config = agent_config.path();
        context.token_provider =
            Some(vec![ProviderRawConfig { provider_type: ProviderType::Rbs, enabled: true, rest: Map::new() }]);
        let args = GetTokenArgs {
            agent: AgentConfigArgs { agent_config: context.agent_config.clone() },
            attester_pubkey: None,
            attester_data: None,
            runtime_data: vec![],
            evidence: Some(evidence_file.at()),
        };

        let output = tokio::task::spawn_blocking(move || {
            execute_action(&ClientAction::GetToken(args), &context, &ExecutionOptions::default())
        })
        .await
        .expect("blocking task should join")
        .expect("token retrieval should succeed");

        match output {
            ClientOutput::Attest(resp) => assert_eq!(resp.token, "jwt-token-abc"),
            other => panic!("expected attest output, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_action_get_token_maps_invalid_evidence() {
        let agent_config = TempFile::new("agent-config-invalid-evidence.yaml", "agent:\n  user_id: \"test-user\"\n");
        let evidence_file = TempFile::new("get-token-bad-evidence.json", r#"{"measurements":"not-a-list"}"#);
        let mut context = offline_context("http://127.0.0.1:1");
        context.agent_config = agent_config.path();
        context.token_provider =
            Some(vec![ProviderRawConfig { provider_type: ProviderType::Rbs, enabled: true, rest: Map::new() }]);
        let args = GetTokenArgs {
            agent: AgentConfigArgs { agent_config: context.agent_config.clone() },
            attester_pubkey: None,
            attester_data: None,
            runtime_data: vec![],
            evidence: Some(evidence_file.at()),
        };

        let err = tokio::task::spawn_blocking(move || {
            execute_action(&ClientAction::GetToken(args), &context, &ExecutionOptions::default())
        })
        .await
        .expect("blocking task should join")
        .err()
        .expect("malformed evidence must fail");

        assert!(matches!(err, CliError::Json(_)), "unexpected error: {err}");
    }
}

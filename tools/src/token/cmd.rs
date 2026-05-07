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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{ArgAction, Args, Subcommand, ValueEnum};
use josekit::jws::{EdDSA, JwsHeader, ES256, ES384, ES512, PS256, PS384, PS512, RS256, RS384, RS512};
use josekit::jwt::{self, JwtPayload};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer};
use serde_json::{Map, Value};
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::common::formatter::Formatter as OutputFormatter;
use crate::common::validate::validate_file_path;
use crate::config::GlobalOptions;
use crate::error::CliError;
use crate::token::Token;

const DEFAULT_ISSUER: &str = "rbs-cli";
const DEFAULT_SUBJECT: &str = "administrator";
const DEFAULT_AUDIENCE: &str = "globaltrustauthority-rbs";
const DEFAULT_ROLE: &str = "admin";
const DEFAULT_EXP_AFTER_SECONDS: u64 = 3600;
const SUPPORTED_PRIVATE_KEYS: &str =
    "supported private keys: RSA for RS*/PS*, P-256 for ES256, P-384 for ES384, P-521 for ES512, SM2 for SM2, Ed25519/Ed448 for EdDSA";

#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
pub enum TokenAlg {
    #[value(name = "RS256")]
    Rs256,
    #[value(name = "RS384")]
    Rs384,
    #[value(name = "RS512")]
    Rs512,
    #[value(name = "PS256")]
    Ps256,
    #[value(name = "PS384")]
    Ps384,
    #[value(name = "PS512")]
    Ps512,
    #[value(name = "SM2")]
    Sm2,
    #[value(name = "ES256")]
    Es256,
    #[value(name = "ES384")]
    Es384,
    #[value(name = "ES512")]
    Es512,
    #[default]
    #[value(name = "EdDSA")]
    Eddsa,
}

impl Display for TokenAlg {
    /// Formats the JWT alg value as the standard header string.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rs256 => write!(f, "RS256"),
            Self::Rs384 => write!(f, "RS384"),
            Self::Rs512 => write!(f, "RS512"),
            Self::Ps256 => write!(f, "PS256"),
            Self::Ps384 => write!(f, "PS384"),
            Self::Ps512 => write!(f, "PS512"),
            Self::Sm2 => write!(f, "SM2"),
            Self::Es256 => write!(f, "ES256"),
            Self::Es384 => write!(f, "ES384"),
            Self::Es512 => write!(f, "ES512"),
            Self::Eddsa => write!(f, "EdDSA"),
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct TokenCli {
    #[command(subcommand)]
    pub command: TokenCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TokenCommand {
    #[command(name = "gen")]
    Generate(GenerateArgs),
}

/// CLI input model for JWT generation.
///
/// This struct describes all user-supplied inputs that participate in building a
/// signed JWT:
///
/// - `private_key_file`: path to the PEM private key used to sign the final
///   `header.payload` signing input.
/// - `private_key_passphrase`: optional passphrase source for encrypted private
///   keys. `None` means the key is treated as unencrypted; `Some(None)` means
///   prompt/read from stdin; `Some(Some("@path"))` means read the passphrase
///   from a file.
/// - `iss`: JWT `iss` claim, identifying the token issuer.
/// - `sub`: JWT `sub` claim, identifying the token subject.
/// - `aud`: JWT `aud` claim. One value is serialized as a string; multiple
///   values are serialized as an array.
/// - `role`: custom business claim added to the payload so downstream services
///   can identify the caller's role.
/// - `exp`: JWT `exp` claim. When omitted, the generator uses the default
///   expiration policy defined by the CLI.
/// - `nbf`: optional JWT `nbf` claim, restricting token usage before a given
///   timestamp.
/// - `iat`: optional JWT `iat` claim, recording when the token was issued.
/// - `jti`: optional JWT `jti` claim, typically used as a unique token ID for
///   tracing, revocation, or replay protection.
/// - `alg`: optional JWA signing algorithm. If omitted, the generator infers a
///   default algorithm from the private key type and curve.
/// - `kid`: optional JWT header `kid` field so verifiers can select the correct
///   key during signature validation.
/// - `claims`: optional JSON object merged into the payload as additional custom
///   claims, as long as they do not conflict with built-in claims generated by
///   the CLI.
#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    #[arg(long, value_parser = validate_file_path)]
    pub private_key_file: Option<String>,

    #[arg(long, num_args = 0..=1, value_name = "@PATH")]
    pub private_key_passphrase: Option<Option<String>>,

    #[arg(long, default_value = DEFAULT_ISSUER)]
    pub iss: String,

    #[arg(long, default_value = DEFAULT_SUBJECT)]
    pub sub: String,

    #[arg(long, action = ArgAction::Append, default_value = DEFAULT_AUDIENCE)]
    pub aud: Vec<String>,

    #[arg(long, default_value = DEFAULT_ROLE)]
    pub role: String,

    #[arg(long)]
    pub exp: Option<u64>,

    #[arg(long)]
    pub nbf: Option<u64>,

    #[arg(long)]
    pub iat: Option<u64>,

    #[arg(long)]
    pub jti: Option<String>,

    #[arg(long, value_enum)]
    pub alg: Option<TokenAlg>,

    #[arg(long)]
    pub kid: Option<String>,

    #[arg(long)]
    pub claims: Option<String>,
}

impl Default for GenerateArgs {
    /// Builds the same defaults clap applies for token generation arguments.
    fn default() -> Self {
        Self {
            iss: DEFAULT_ISSUER.to_string(),
            sub: DEFAULT_SUBJECT.to_string(),
            aud: vec![DEFAULT_AUDIENCE.to_string()],
            role: DEFAULT_ROLE.to_string(),
            private_key_file: None,
            private_key_passphrase: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            alg: None,
            kid: None,
            claims: None,
        }
    }
}

pub struct TokenGenerate;

impl TokenGenerate {
    pub fn load_private_key(args: &GenerateArgs) -> Result<PKey<Private>, CliError> {
        let private_key_file = args
            .private_key_file
            .as_ref()
            .ok_or_else(|| CliError::Message("missing private key; specify --private-key-file".to_string()))?;
        let private_key_pem = Zeroizing::new(fs::read(private_key_file).map_err(|_| {
            CliError::FileReadError(format!(
                "unable to read private key file `{private_key_file}`. Please check that the file exists and is readable"
            ))
        })?);

        let passphrase = match &args.private_key_passphrase {
            None => None,
            Some(None) => {
                if io::stdin().is_terminal() {
                    Some(
                        rpassword::prompt_password("Private key passphrase: ")
                            .map(Zeroizing::new)
                            .map_err(|_| CliError::Message("unable to read the private key passphrase".to_string()))?,
                    )
                } else {
                    let mut passphrase = Zeroizing::new(String::new());
                    io::stdin()
                        .read_to_string(&mut passphrase)
                        .map_err(|_| CliError::Message("unable to read the private key passphrase".to_string()))?;
                    trim_line_end(&mut passphrase);
                    Some(passphrase)
                }
            },
            Some(Some(value)) => {
                let Some(path) = value.strip_prefix('@') else {
                    return Err(CliError::InvalidArgument(
                        "private key passphrase must be provided as --private-key-passphrase @path or entered interactively with --private-key-passphrase".to_string(),
                    ));
                };
                validate_file_path(path)?;
                let mut passphrase = Zeroizing::new(fs::read_to_string(path).map_err(|_| {
                    CliError::FileReadError(format!(
                        "unable to read private key passphrase file `{path}`. Please check that the file exists and is readable"
                    ))
                })?);
                trim_line_end(&mut passphrase);
                Some(passphrase)
            },
        };
        match &passphrase {
            Some(passphrase) => {
                PKey::private_key_from_pem_passphrase(&private_key_pem, passphrase.as_bytes()).map_err(|_err| {
                    CliError::InvalidArgument(format!(
                        "unable to read the encrypted private key. Please check the key format and passphrase; {SUPPORTED_PRIVATE_KEYS}"
                    ))
                })
            },
            None => {
                PKey::private_key_from_pem(&private_key_pem).map_err(|err| {
                    CliError::InvalidArgument(format!(
                        "failed to parse private key PEM: {err}; if the private key is encrypted, pass --private-key-passphrase for interactive input or
  --private-key-passphrase @path to read the passphrase from a file; {SUPPORTED_PRIVATE_KEYS}"
                    ))
                })
            }
        }
    }

    pub fn get_alg(alg: &Option<TokenAlg>, private_key: &PKey<Private>) -> Result<TokenAlg, CliError> {
        match &alg {
            Some(alg) => {
                let matched = match alg {
                    TokenAlg::Rs256
                    | TokenAlg::Rs384
                    | TokenAlg::Rs512
                    | TokenAlg::Ps256
                    | TokenAlg::Ps384
                    | TokenAlg::Ps512 => {
                        matches!(private_key.id(), Id::RSA | Id::RSA_PSS)
                    },
                    TokenAlg::Es256 => ec_curve_matches(private_key, Nid::X9_62_PRIME256V1)?,
                    TokenAlg::Es384 => ec_curve_matches(private_key, Nid::SECP384R1)?,
                    TokenAlg::Es512 => ec_curve_matches(private_key, Nid::SECP521R1)?,
                    TokenAlg::Sm2 => private_key.id() == Id::SM2 || ec_curve_matches(private_key, Nid::SM2)?,
                    TokenAlg::Eddsa => matches!(private_key.id(), Id::ED25519 | Id::ED448),
                };

                if matched {
                    Ok(alg.clone())
                } else {
                    Err(CliError::InvalidArgument(format!(
                        "private key type does not match alg `{alg}`; {SUPPORTED_PRIVATE_KEYS}"
                    )))
                }
            },
            None => Ok(infer_default_alg(&private_key)?),
        }
    }

    pub fn generate(args: &GenerateArgs) -> Result<Token, CliError> {
        let private_key = Self::load_private_key(args)?;
        let alg = Self::get_alg(&args.alg, &private_key)?;
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm(alg.to_string());
        if let Some(kid) = &args.kid {
            header.set_key_id(kid.clone());
        }

        let mut payload = Map::new();
        payload.insert("iss".to_string(), Value::String(args.iss.clone()));
        payload.insert("sub".to_string(), Value::String(args.sub.clone()));
        payload.insert("aud".to_string(), audience_value(&args.aud));
        payload.insert("role".to_string(), Value::String(args.role.clone()));
        payload.insert("exp".to_string(), Value::Number(args.exp.unwrap_or_else(default_exp).into()));

        if let Some(nbf) = args.nbf {
            payload.insert("nbf".to_string(), Value::Number(nbf.into()));
        }
        if let Some(iat) = args.iat {
            payload.insert("iat".to_string(), Value::Number(iat.into()));
        }
        if let Some(jti) = &args.jti {
            payload.insert("jti".to_string(), Value::String(jti.clone()));
        }
        if let Some(claims) = &args.claims {
            merge_claims(&mut payload, claims)?;
        }
        let payload = JwtPayload::from_map(payload).map_err(|_err| {
            CliError::InvalidArgument(format!("unable to build the token payload. Please check the token claims"))
        })?;

        let pem = Zeroizing::new(
            private_key
                .private_key_to_pem_pkcs8()
                .map_err(|_err| CliError::InvalidArgument(format!("unable to prepare the private key for signing")))?,
        );
        let token = Self::generate_token(&alg, &pem, &header, &payload)?;
        Ok(token)
    }

    fn generate_token(alg: &TokenAlg, pem: &[u8], header: &JwsHeader, payload: &JwtPayload) -> Result<Token, CliError> {
        let token = match alg {
            TokenAlg::Rs256 => {
                let signer = RS256
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with RS256. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Rs384 => {
                let signer = RS384
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with RS384. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Rs512 => {
                let signer = RS512
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with RS512. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Ps256 => {
                let signer = PS256
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with PS256. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Ps384 => {
                let signer = PS384
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with PS384. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Ps512 => {
                let signer = PS512
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with PS512. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Es256 => {
                let signer = ES256
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with ES256. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Es384 => {
                let signer = ES384
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with ES384. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Es512 => {
                let signer = ES512
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with ES512. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Eddsa => {
                let signer = EdDSA
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument(format!("unable to sign the token with EdDSA. Please check that the private key matches the selected algorithm")))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Sm2 => {
                return Self::generate_sm2_token(header, payload, pem);
            },
        }
        .map_err(|_err| CliError::InvalidArgument(format!("unable to generate the token. Please check the private key and token options")))?;
        Ok(Token { token })
    }

    fn generate_sm2_token(header: &JwsHeader, payload: &JwtPayload, pem: &[u8]) -> Result<Token, CliError> {
        let private_key = PKey::private_key_from_pem(pem)
            .map_err(|err| CliError::InvalidArgument(format!("unable to prepare the SM2 private key for signing: {err}")))?;
        let signing_input = build_signing_input(header, payload)?;
        let signature = sign(signing_input.as_bytes(), &private_key, &TokenAlg::Sm2)?;
        Ok(Token { token: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)) })
    }
}

/// Dispatches token subcommands to the corresponding implementation.
pub fn run(cli: &TokenCli, _global: &GlobalOptions) -> Result<Box<dyn OutputFormatter>, CliError> {
    match &cli.command {
        TokenCommand::Generate(args) => Ok(Box::new(TokenGenerate::generate(args)?)),
    }
}

/// Serializes JWT audience as a string for one audience or an array for multiple audiences.
fn audience_value(aud: &[String]) -> Value {
    match aud {
        [single] => Value::String(single.clone()),
        _ => Value::Array(aud.iter().cloned().map(Value::String).collect()),
    }
}

/// Merges user-provided custom claims while preventing built-in claim overrides.
fn merge_claims(payload: &mut Map<String, Value>, claims: &str) -> Result<(), CliError> {
    let value: Value = serde_json::from_str(claims)
        .map_err(|_err| CliError::InvalidArgument(format!("invalid claims JSON. Please provide a valid JSON object")))?;
    let Value::Object(claims) = value else {
        return Err(CliError::InvalidArgument("claims must be a JSON object".to_string()));
    };

    for (key, value) in claims {
        if payload.contains_key(&key) {
            return Err(CliError::InvalidArgument(format!("claim `{key}` conflicts with a built-in JWT claim")));
        }
        payload.insert(key, value);
    }
    Ok(())
}

/// Removes trailing CR/LF characters from passphrases read from files or stdin.
fn trim_line_end(value: &mut String) {
    while value.ends_with(['\r', '\n']) {
        value.pop();
    }
}

fn build_signing_input(header: &JwsHeader, payload: &JwtPayload) -> Result<String, CliError> {
    let header_json = header.to_string();
    let payload_json = payload.to_string();
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_json.as_bytes()),
        URL_SAFE_NO_PAD.encode(payload_json.as_bytes())
    ))
}

/// Infers a default JWT algorithm from the private key type and curve.
fn infer_default_alg(private_key: &PKey<Private>) -> Result<TokenAlg, CliError> {
    match private_key.id() {
        Id::RSA => Ok(TokenAlg::Rs256),
        Id::RSA_PSS => Ok(TokenAlg::Ps256),
        Id::SM2 => Ok(TokenAlg::Sm2),
        Id::ED25519 | Id::ED448 => Ok(TokenAlg::Eddsa),
        Id::EC => infer_ec_default_alg(private_key),
        _ => Err(CliError::InvalidArgument(format!(
            "unsupported private key type for JWT signing; {SUPPORTED_PRIVATE_KEYS}"
        ))),
    }
}

/// Infers a default JWT algorithm from the EC curve name.
fn infer_ec_default_alg(private_key: &PKey<Private>) -> Result<TokenAlg, CliError> {
    let ec_key = private_key.ec_key().map_err(|_err| {
        CliError::InvalidArgument(format!(
            "unable to read the EC private key details. Please check that the key is valid"
        ))
    })?;

    match ec_key.group().curve_name() {
        Some(Nid::X9_62_PRIME256V1) => Ok(TokenAlg::Es256),
        Some(Nid::SECP384R1) => Ok(TokenAlg::Es384),
        Some(Nid::SECP521R1) => Ok(TokenAlg::Es512),
        Some(Nid::SM2) => Ok(TokenAlg::Sm2),
        _ => Err(CliError::InvalidArgument(format!(
            "unsupported EC private key curve for JWT signing; {SUPPORTED_PRIVATE_KEYS}"
        ))),
    }
}

/// Checks whether an EC private key uses the expected named curve.
fn ec_curve_matches(private_key: &PKey<Private>, curve: Nid) -> Result<bool, CliError> {
    if private_key.id() != Id::EC {
        return Ok(false);
    }

    let ec_key = private_key.ec_key().map_err(|_err| {
        CliError::InvalidArgument(format!(
            "unable to read the EC private key details. Please check that the key is valid"
        ))
    })?;
    Ok(ec_key.group().curve_name() == Some(curve))
}

fn sign(signing_input: &[u8], private_key: &PKey<Private>, alg: &TokenAlg) -> Result<Vec<u8>, CliError> {
    let mut signer = match alg {
        TokenAlg::Eddsa => Signer::new_without_digest(private_key),
        TokenAlg::Sm2 => Signer::new(MessageDigest::sm3(), private_key),
        _ => Signer::new(message_digest(alg), private_key),
    }
    .map_err(|err| CliError::InvalidArgument(format!("failed to initialize signer: {err}")))?;

    match alg {
        TokenAlg::Rs256 | TokenAlg::Rs384 | TokenAlg::Rs512 => {
            signer
                .set_rsa_padding(Padding::PKCS1)
                .map_err(|err| CliError::InvalidArgument(format!("failed to configure RSA padding: {err}")))?;
        },
        TokenAlg::Ps256 | TokenAlg::Ps384 | TokenAlg::Ps512 => {
            signer
                .set_rsa_padding(Padding::PKCS1_PSS)
                .map_err(|err| CliError::InvalidArgument(format!("failed to configure RSA-PSS padding: {err}")))?;
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .map_err(|err| CliError::InvalidArgument(format!("failed to configure RSA-PSS salt length: {err}")))?;
            signer
                .set_rsa_mgf1_md(message_digest(alg))
                .map_err(|err| CliError::InvalidArgument(format!("failed to configure RSA-PSS MGF1 digest: {err}")))?;
        },
        _ => {},
    }

    let signature = if matches!(alg, TokenAlg::Eddsa) {
        signer
            .sign_oneshot_to_vec(signing_input)
            .map_err(|err| CliError::InvalidArgument(format!("failed to sign JWT: {err}")))
    } else {
        signer.update(signing_input).map_err(|err| CliError::InvalidArgument(format!("failed to sign JWT: {err}")))?;
        signer.sign_to_vec().map_err(|err| CliError::InvalidArgument(format!("failed to sign JWT: {err}")))
    }?;

    if matches!(alg, TokenAlg::Es256 | TokenAlg::Es384 | TokenAlg::Es512) {
        ecdsa_der_to_jwa(&signature, ecdsa_component_len(alg))
    } else {
        Ok(signature)
    }
}

fn message_digest(alg: &TokenAlg) -> MessageDigest {
    match alg {
        TokenAlg::Rs256 | TokenAlg::Ps256 | TokenAlg::Es256 => MessageDigest::sha256(),
        TokenAlg::Rs384 | TokenAlg::Ps384 | TokenAlg::Es384 => MessageDigest::sha384(),
        TokenAlg::Rs512 | TokenAlg::Ps512 | TokenAlg::Es512 => MessageDigest::sha512(),
        TokenAlg::Sm2 => MessageDigest::sm3(),
        TokenAlg::Eddsa => unreachable!("EdDSA uses digestless signing"),
    }
}

fn ecdsa_component_len(alg: &TokenAlg) -> usize {
    match alg {
        TokenAlg::Es256 => 32,
        TokenAlg::Es384 => 48,
        TokenAlg::Es512 => 66,
        _ => unreachable!("component length only applies to ECDSA algorithms"),
    }
}

fn ecdsa_der_to_jwa(signature: &[u8], component_len: usize) -> Result<Vec<u8>, CliError> {
    let sig = EcdsaSig::from_der(signature)
        .map_err(|err| CliError::InvalidArgument(format!("failed to parse DER ECDSA signature: {err}")))?;
    let r = sig.r().to_vec();
    let s = sig.s().to_vec();
    if r.len() > component_len || s.len() > component_len {
        return Err(CliError::InvalidArgument(
            "ECDSA signature component is larger than expected".to_string(),
        ));
    }

    let mut out = vec![0u8; component_len * 2];
    out[component_len - r.len()..component_len].copy_from_slice(&r);
    out[(component_len * 2) - s.len()..component_len * 2].copy_from_slice(&s);
    Ok(out)
}

/// Calculates the default expiration time as now plus one hour.
fn default_exp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() + DEFAULT_EXP_AFTER_SECONDS)
        .unwrap_or(DEFAULT_EXP_AFTER_SECONDS)
}

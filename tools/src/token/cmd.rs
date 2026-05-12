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

use clap::{ArgAction, Args, Subcommand, ValueEnum};
use josekit::jws::{EdDSA, JwsHeader, ES256, ES384, ES512};
use josekit::jwt::{self, JwtPayload};
use jsonwebtoken::{encode as jwt_encode, Algorithm as JwtAlgorithm, EncodingKey, Header as JwtHeader};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use serde_json::{Map, Value};
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::common::formatter::Formatter as OutputFormatter;
use crate::common::utils::read_path_file;
use crate::common::validate::{validate_file_path, validate_file_size, validate_string_max_len};
use crate::config::GlobalOptions;
use crate::error::CliError;
use crate::token::Token;

const DEFAULT_ISSUER: &str = "rbs-cli";
const DEFAULT_SUBJECT: &str = "administrator";
const DEFAULT_AUDIENCE: &str = "globaltrustauthority-rbs";
const DEFAULT_EXP_AFTER_SECONDS: u64 = 3600;
const ISS_MAX_LEN: usize = 128;
const SUB_MAX_LEN: usize = 64;
const AUD_MAX_LEN: usize = 128;
const AUD_MAX_COUNT: usize = 16;
const ROLE_MAX_LEN: usize = 64;
const JTI_MAX_LEN: usize = 128;
const KID_MAX_LEN: usize = 128;
const CLAIMS_MAX_SIZE: u64 = 64 * 1024;
const PASSPHRASE_MAX_LEN: usize = 1024;
const SUPPORTED_PRIVATE_KEYS: &str =
    "supported private keys: RSA for PS*, P-256 for ES256, P-384 for ES384, P-521 for ES512, Ed25519/Ed448 for EdDSA";

#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
pub enum TokenAlg {
    #[value(name = "PS256")]
    Ps256,
    #[value(name = "PS384")]
    Ps384,
    #[value(name = "PS512")]
    Ps512,
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
            Self::Ps256 => write!(f, "PS256"),
            Self::Ps384 => write!(f, "PS384"),
            Self::Ps512 => write!(f, "PS512"),
            Self::Es256 => write!(f, "ES256"),
            Self::Es384 => write!(f, "ES384"),
            Self::Es512 => write!(f, "ES512"),
            Self::Eddsa => write!(f, "EdDSA"),
        }
    }
}

#[derive(Args, Debug, Clone)]
#[command(about = "Generate signed JWT tokens for RBS administration and client access")]
pub struct TokenCli {
    #[command(subcommand)]
    pub command: TokenCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TokenCommand {
    #[command(name = "gen", about = "Generate a JWT from a private key and claim inputs")]
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
/// - `sub`: JWT `sub` claim, carrying the username associated with the token.
/// - `aud`: JWT `aud` claim. One value is serialized as a string; multiple
///   values are serialized as an array.
/// - `role`: optional custom business claim added to the payload so downstream
///   services can identify the caller's role.
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
#[command(
    about = "Generate a signed JWT",
    long_about = "Generate a signed JWT using a PEM private key. Standard claims such as iss, sub, aud, exp, nbf, iat, and jti can be set explicitly, and extra custom claims can be merged from JSON input."
)]
pub struct GenerateArgs {
    #[arg(long, value_parser = validate_file_path, help = "Path to the PEM private key used for signing")]
    pub private_key_file: Option<String>,

    #[arg(
        long,
        num_args = 0..=1,
        value_name = "@PATH",
        help = "Read the private key passphrase interactively or from @PATH"
    )]
    pub private_key_passphrase: Option<Option<String>>,

    #[arg(
        long,
        default_value = DEFAULT_ISSUER,
        value_parser = |value: &str| validate_string_max_len(value, ISS_MAX_LEN),
        help = "JWT issuer claim"
    )]
    pub iss: String,

    #[arg(
        long,
        default_value = DEFAULT_SUBJECT,
        value_parser = |value: &str| validate_string_max_len(value, SUB_MAX_LEN),
        help = "Username stored in the JWT sub claim"
    )]
    pub sub: String,

    #[arg(
        long,
        action = ArgAction::Append,
        default_value = DEFAULT_AUDIENCE,
        value_parser = |value: &str| validate_string_max_len(value, AUD_MAX_LEN),
        help = "JWT audience claim; repeat to add multiple audiences"
    )]
    pub aud: Vec<String>,

    #[arg(
        long,
        value_parser = |value: &str| validate_string_max_len(value, ROLE_MAX_LEN),
        help = "Optional role claim added to the token payload"
    )]
    pub role: Option<String>,

    #[arg(long, help = "JWT expiration time as a Unix timestamp in seconds")]
    pub exp: Option<u64>,

    #[arg(long, help = "JWT not-before time as a Unix timestamp in seconds")]
    pub nbf: Option<u64>,

    #[arg(long, help = "JWT issued-at time as a Unix timestamp in seconds")]
    pub iat: Option<u64>,

    #[arg(
        long,
        value_parser = |value: &str| validate_string_max_len(value, JTI_MAX_LEN),
        help = "JWT ID claim"
    )]
    pub jti: Option<String>,

    #[arg(long, value_enum, help = "Signing algorithm; defaults to a value inferred from the private key")]
    pub alg: Option<TokenAlg>,

    #[arg(
        long,
        value_parser = |value: &str| validate_string_max_len(value, KID_MAX_LEN),
        help = "JWT header key ID"
    )]
    pub kid: Option<String>,

    #[arg(long, value_parser = validate_claims_input, help = "Additional custom claims as JSON text or @file path")]
    pub claims: Option<String>,
}

impl Default for GenerateArgs {
    /// Builds the same defaults clap applies for token generation arguments.
    fn default() -> Self {
        Self {
            iss: DEFAULT_ISSUER.to_string(),
            sub: DEFAULT_SUBJECT.to_string(),
            aud: vec![DEFAULT_AUDIENCE.to_string()],
            role: None,
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
                            .map_err(|_| CliError::Message("unable to read the private key passphrase".to_string()))
                            .and_then(|value| {
                                validate_passphrase_len(&value)?;
                                Ok(value)
                            })?,
                    )
                } else {
                    let mut passphrase = Zeroizing::new(String::new());
                    io::stdin()
                        .read_to_string(&mut passphrase)
                        .map_err(|_| CliError::Message("unable to read the private key passphrase".to_string()))?;
                    trim_line_end(&mut passphrase);
                    validate_passphrase_len(&passphrase)?;
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
                validate_passphrase_len(&passphrase)?;
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
                    TokenAlg::Ps256 | TokenAlg::Ps384 | TokenAlg::Ps512 => {
                        matches!(private_key.id(), Id::RSA | Id::RSA_PSS)
                    },
                    TokenAlg::Es256 => ec_curve_matches(private_key, Nid::X9_62_PRIME256V1)?,
                    TokenAlg::Es384 => ec_curve_matches(private_key, Nid::SECP384R1)?,
                    TokenAlg::Es512 => ec_curve_matches(private_key, Nid::SECP521R1)?,
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
        validate_audience_count(&args.aud)?;
        let private_key = Self::load_private_key(args)?;
        let alg = Self::get_alg(&args.alg, &private_key)?;
        let exp = args.exp.unwrap_or_else(default_exp);
        validate_time_claims(exp, args.nbf, args.iat)?;
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
        if let Some(role) = &args.role {
            payload.insert("role".to_string(), Value::String(role.clone()));
        }
        payload.insert("exp".to_string(), Value::Number(exp.into()));

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
            let claims_data = read_path_file(claims)?;
            merge_claims(&mut payload, &claims_data)?;
        }
        let payload = JwtPayload::from_map(payload).map_err(|_err| {
            CliError::InvalidArgument("unable to build the token payload. Please check the token claims".to_string())
        })?;

        let pem =
            Zeroizing::new(private_key.private_key_to_pem_pkcs8().map_err(|_err| {
                CliError::InvalidArgument("unable to prepare the private key for signing".to_string())
            })?);
        let token = Self::generate_token(&alg, &pem, &header, &payload)?;
        Ok(token)
    }

    fn generate_token(alg: &TokenAlg, pem: &[u8], header: &JwsHeader, payload: &JwtPayload) -> Result<Token, CliError> {
        let token = match alg {
            TokenAlg::Ps256 | TokenAlg::Ps384 | TokenAlg::Ps512 => return generate_pss_token_with_jsonwebtoken(alg, pem, header, payload),
            TokenAlg::Es256 => {
                let signer = ES256
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument("unable to sign the token with ES256. Please check that the private key matches the selected algorithm".to_string()))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Es384 => {
                let signer = ES384
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument("unable to sign the token with ES384. Please check that the private key matches the selected algorithm".to_string()))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Es512 => {
                let signer = ES512
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument("unable to sign the token with ES512. Please check that the private key matches the selected algorithm".to_string()))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            },
            TokenAlg::Eddsa => {
                let signer = EdDSA
                    .signer_from_pem(pem)
                    .map_err(|_err| CliError::InvalidArgument("unable to sign the token with EdDSA. Please check that the private key matches the selected algorithm".to_string()))?;
                jwt::encode_with_signer(&payload, &header, &signer)
            }
        }
        .map_err(|_err| CliError::InvalidArgument("unable to generate the token. Please check the private key and token options".to_string()))?;
        Ok(Token { token })
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
    let value: Value = serde_json::from_str(claims).map_err(|_err| {
        CliError::InvalidArgument("invalid claims JSON. Please provide a valid JSON object".to_string())
    })?;
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

fn generate_pss_token_with_jsonwebtoken(
    alg: &TokenAlg,
    pem: &[u8],
    header: &JwsHeader,
    payload: &JwtPayload,
) -> Result<Token, CliError> {
    let jwt_alg = match alg {
        TokenAlg::Ps256 => JwtAlgorithm::PS256,
        TokenAlg::Ps384 => JwtAlgorithm::PS384,
        TokenAlg::Ps512 => JwtAlgorithm::PS512,
        _ => unreachable!("jsonwebtoken PSS path only applies to PS* algorithms"),
    };

    let mut jwt_header = JwtHeader::new(jwt_alg);
    jwt_header.typ = Some("JWT".to_string());
    jwt_header.kid = header.key_id().map(|value| value.to_string());

    let claims: Value = serde_json::from_str(&payload.to_string()).map_err(|_| {
        CliError::InvalidArgument("unable to build the token payload. Please check the token claims".to_string())
    })?;
    let encoding_key = EncodingKey::from_rsa_pem(pem).map_err(|err| {
        CliError::InvalidArgument(format!(
            "unable to load the RSA private key for {alg}. Please check that the key is a valid PEM private key: {err}"
        ))
    })?;
    let token = jwt_encode(&jwt_header, &claims, &encoding_key).map_err(|err| {
        CliError::InvalidArgument(format!(
            "unable to sign the token with {alg}. Please check that the private key matches the selected algorithm: {err}"
        ))
    })?;
    Ok(Token { token })
}

fn validate_claims_input(value: &str) -> Result<String, CliError> {
    if let Some(path) = value.strip_prefix('@') {
        validate_file_size(path, CLAIMS_MAX_SIZE)?;
        Ok(value.to_string())
    } else {
        validate_string_max_len(value, CLAIMS_MAX_SIZE as usize)
    }
}

fn validate_audience_count(values: &[String]) -> Result<(), CliError> {
    if values.len() <= AUD_MAX_COUNT {
        Ok(())
    } else {
        Err(CliError::InvalidArgument(format!("audience count must not exceed {AUD_MAX_COUNT}; got {}", values.len())))
    }
}

fn validate_passphrase_len(value: &str) -> Result<(), CliError> {
    if value.len() <= PASSPHRASE_MAX_LEN {
        Ok(())
    } else {
        Err(CliError::InvalidArgument(format!(
            "private key passphrase must not exceed {PASSPHRASE_MAX_LEN} characters; got {}",
            value.len()
        )))
    }
}

fn validate_time_claims(exp: u64, nbf: Option<u64>, iat: Option<u64>) -> Result<(), CliError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::InvalidArgument("system clock is before the Unix epoch".to_string()))?
        .as_secs();

    if exp <= now {
        return Err(CliError::InvalidArgument("exp must be a Unix timestamp later than the current time".to_string()));
    }
    if let Some(nbf) = nbf {
        if nbf >= exp {
            return Err(CliError::InvalidArgument("nbf must be earlier than exp".to_string()));
        }
    }
    if let Some(iat) = iat {
        if iat >= exp {
            return Err(CliError::InvalidArgument("iat must be earlier than exp".to_string()));
        }
    }
    Ok(())
}

/// Infers a default JWT algorithm from the private key type and curve.
fn infer_default_alg(private_key: &PKey<Private>) -> Result<TokenAlg, CliError> {
    match private_key.id() {
        Id::RSA => Ok(TokenAlg::Ps256),
        Id::RSA_PSS => Ok(TokenAlg::Ps256),
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
        CliError::InvalidArgument(
            "unable to read the EC private key details. Please check that the key is valid".to_string(),
        )
    })?;

    match ec_key.group().curve_name() {
        Some(Nid::X9_62_PRIME256V1) => Ok(TokenAlg::Es256),
        Some(Nid::SECP384R1) => Ok(TokenAlg::Es384),
        Some(Nid::SECP521R1) => Ok(TokenAlg::Es512),
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
        CliError::InvalidArgument(
            "unable to read the EC private key details. Please check that the key is valid".to_string(),
        )
    })?;
    Ok(ec_key.group().curve_name() == Some(curve))
}

/// Calculates the default expiration time as now plus one hour.
fn default_exp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() + DEFAULT_EXP_AFTER_SECONDS)
        .unwrap_or(DEFAULT_EXP_AFTER_SECONDS)
}

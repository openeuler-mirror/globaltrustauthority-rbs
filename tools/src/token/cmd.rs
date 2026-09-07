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
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl::hash::MessageDigest;
use openssl::md_ctx::MdCtx;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, PKeyRef, Private};
use openssl::sign::Signer;
use openssl_sys as ossl;
use serde_json::{Map, Value};
use base64::Engine as _;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::common::formatter::Formatter as OutputFormatter;
use crate::common::utils::read_path_file;
use crate::common::validate::{
    validate_file_path, validate_file_size, validate_passphrase_len, validate_string_max_len,
};
use crate::config::GlobalOptions;
use crate::error::CliError;
use crate::token::Token;

const DEFAULT_ISSUER: &str = "rbs-cli";
const DEFAULT_SUBJECT: &str = "Administrator";
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
    "supported private keys: RSA for PS*, P-256 for ES256, P-384 for ES384, P-521 for ES512, Ed25519/Ed448 for EdDSA, SM2 for SM2";

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
    #[value(name = "SM2")]
    Sm2,
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
            Self::Sm2 => write!(f, "SM2"),
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
    #[arg(
        long,
        required = true,
        value_parser = validate_file_path,
        help = "Path to the PEM private key used for signing"
    )]
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
                                validate_passphrase_len(&value, PASSPHRASE_MAX_LEN)?;
                                Ok(value)
                            })?,
                    )
                } else {
                    let mut passphrase = Zeroizing::new(String::new());
                    io::stdin()
                        .read_to_string(&mut passphrase)
                        .map_err(|_| CliError::Message("unable to read the private key passphrase".to_string()))?;
                    trim_line_end(&mut passphrase);
                    validate_passphrase_len(&passphrase, PASSPHRASE_MAX_LEN)?;
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
                validate_passphrase_len(&passphrase, PASSPHRASE_MAX_LEN)?;
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
                    TokenAlg::Sm2 => key_is_sm2(private_key),
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
            },
            TokenAlg::Sm2 => return generate_sm2_token(pem, header, &payload),
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

/// GM/T 0009 default SM2 user ID used for every SM2 token signature.
///
/// OpenSSL >= 3.5 (including the vendored build used here) no longer applies
/// this default implicitly: a plain `Signer::new(MessageDigest::sm3(), ..)`
/// signs with an *empty* user ID, which no standard SM2 implementation
/// accepts. Mirror of `rbs/core/src/auth/authn/sm2.rs` — keep in sync.
const SM2_USER_ID: &[u8] = b"1234567812345678";

// `openssl-sys` does not bind `EVP_PKEY_CTX_set1_id`; declare it against the
// libcrypto linked through the vendored `openssl` crate.
extern "C" {
    fn EVP_PKEY_CTX_set1_id(
        ctx: *mut ossl::EVP_PKEY_CTX,
        id: *const std::os::raw::c_void,
        id_len: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
}

/// Sign `data` with SM2 (SM3 digest) under the standard default user ID.
///
/// Uses the raw EVP interface because the safe `Signer` API cannot set the
/// SM2 user ID (see [`SM2_USER_ID`]).
fn sm2_sign(pkey: &PKeyRef<Private>, data: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    fn cvt(r: std::os::raw::c_int) -> Result<std::os::raw::c_int, openssl::error::ErrorStack> {
        if r <= 0 {
            Err(openssl::error::ErrorStack::get())
        } else {
            Ok(r)
        }
    }

    let mut md_ctx = MdCtx::new()?;
    let mut pkey_ctx: *mut ossl::EVP_PKEY_CTX = std::ptr::null_mut();
    unsafe {
        cvt(ossl::EVP_DigestSignInit(
            md_ctx.as_ptr(),
            &mut pkey_ctx,
            MessageDigest::sm3().as_ptr(),
            std::ptr::null_mut(),
            pkey.as_ptr() as *mut _,
        ))?;
        cvt(EVP_PKEY_CTX_set1_id(
            pkey_ctx,
            SM2_USER_ID.as_ptr() as *const std::os::raw::c_void,
            SM2_USER_ID.len() as std::os::raw::c_int,
        ))?;
        cvt(ossl::EVP_DigestSignUpdate(
            md_ctx.as_ptr(),
            data.as_ptr() as *const std::os::raw::c_void,
            data.len(),
        ))?;
        let mut siglen: usize = 0;
        cvt(ossl::EVP_DigestSignFinal(
            md_ctx.as_ptr(),
            std::ptr::null_mut(),
            &mut siglen,
        ))?;
        let mut sig = vec![0u8; siglen];
        cvt(ossl::EVP_DigestSignFinal(
            md_ctx.as_ptr(),
            sig.as_mut_ptr(),
            &mut siglen,
        ))?;
        sig.truncate(siglen);
        Ok(sig)
    }
}

/// Build an SM2-signed compact JWS (alg "SM2") using OpenSSL directly.
///
/// `jsonwebtoken` and `josekit` lack SM2 support, so the compact JWS is
/// assembled manually: `base64url(header).base64url(payload).base64url(sig)`,
/// where the signature is SM2 ECDSA over the SM3 digest of the signing input.
/// `header` (a josekit `JwsHeader`) is re-serialized to JSON to preserve `kid`
/// and `typ`; only `alg` is overridden to `"SM2"`.
fn generate_sm2_token(
    pem: &[u8],
    header: &JwsHeader,
    payload: &JwtPayload,
) -> Result<Token, CliError> {
    let pkey = PKey::private_key_from_pem(pem).map_err(|err| {
        CliError::InvalidArgument(format!(
            "unable to load the SM2 private key: {err}; please check that the key is a valid PEM private key"
        ))
    })?;

    // Build the JWS header JSON, forcing alg = "SM2" (josekit does not recognize it).
    let mut header_map: Map<String, Value> = header.as_ref().clone();
    header_map.insert("alg".to_string(), Value::String("SM2".to_string()));

    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header_map).map_err(|_err| {
            CliError::InvalidArgument("unable to serialize the token header".to_string())
        })?);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(payload.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature = sm2_sign(&pkey, signing_input.as_bytes()).map_err(|err| {
        CliError::InvalidArgument(format!(
            "unable to sign the token with SM2: {err}; the private key does not match alg `SM2`; {SUPPORTED_PRIVATE_KEYS}"
        ))
    })?;
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

    Ok(Token {
        token: format!("{}.{}", signing_input, sig_b64),
    })
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
        _ => {
            // OpenSSL 3.x reports a re-parsed SM2 private key's id as -1, so it
            // does not match any known arm above. Confirm it is an SM2 key
            // (SM2+SM3 signer constructs only for SM2 keys among the unsupported
            // set) and default to SM2.
            if key_is_sm2(private_key) {
                Ok(TokenAlg::Sm2)
            } else {
                Err(CliError::InvalidArgument(format!(
                    "unsupported private key type for JWT signing; {SUPPORTED_PRIVATE_KEYS}"
                )))
            }
        }
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

/// Detect an SM2 private key.
///
/// OpenSSL 3.x reports a re-parsed SM2 private key's id as -1 (`Id::SM2` is only
/// seen for in-memory keys built via `from_ec_key`), and `ec_key()` is then
/// unavailable, so the key cannot be classified by id or curve lookup. An SM2
/// key is identifiable here as one whose id is `SM2` (in-memory case), or — among
/// keys whose id is not a recognized non-SM2 type — one for which an SM2+SM3
/// signer constructs.
fn key_is_sm2(private_key: &PKey<Private>) -> bool {
    match private_key.id() {
        Id::SM2 => true,
        Id::RSA | Id::RSA_PSS | Id::EC | Id::ED25519 | Id::ED448 => false,
        // id -1 (re-parsed SM2) or any other unrecognized id: probe with SM2+SM3.
        _ => Signer::new(MessageDigest::sm3(), private_key).is_ok(),
    }
}

/// Calculates the default expiration time as now plus one hour.
fn default_exp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() + DEFAULT_EXP_AFTER_SECONDS)
        .unwrap_or(DEFAULT_EXP_AFTER_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cover JWT string claim lengths at max-1, normal, max, and max+1.
    #[test]
    fn token_claim_length_matrix() {
        assert!(validate_string_max_len(&"i".repeat(ISS_MAX_LEN - 1), ISS_MAX_LEN).is_ok());
        assert!(validate_string_max_len("issuer", ISS_MAX_LEN).is_ok());
        assert!(validate_string_max_len(&"i".repeat(ISS_MAX_LEN), ISS_MAX_LEN).is_ok());
        assert!(validate_string_max_len(&"i".repeat(ISS_MAX_LEN + 1), ISS_MAX_LEN).is_err());
        assert!(validate_string_max_len(&"s".repeat(SUB_MAX_LEN), SUB_MAX_LEN).is_ok());
        assert!(validate_string_max_len(&"s".repeat(SUB_MAX_LEN + 1), SUB_MAX_LEN).is_err());
        assert!(validate_string_max_len(&"r".repeat(ROLE_MAX_LEN), ROLE_MAX_LEN).is_ok());
        assert!(validate_string_max_len(&"r".repeat(ROLE_MAX_LEN + 1), ROLE_MAX_LEN).is_err());
        assert!(validate_string_max_len(&"k".repeat(KID_MAX_LEN), KID_MAX_LEN).is_ok());
        assert!(validate_string_max_len(&"k".repeat(KID_MAX_LEN + 1), KID_MAX_LEN).is_err());
    }

    // Enforce the claims payload size boundary and JSON shape validation.
    #[test]
    fn token_claims_input_and_merge_matrix() {
        assert!(validate_claims_input("").is_ok());
        assert!(validate_claims_input("{}").is_ok());
        assert!(validate_claims_input(&"x".repeat(CLAIMS_MAX_SIZE as usize - 1)).is_ok());
        assert!(validate_claims_input(&"x".repeat(CLAIMS_MAX_SIZE as usize)).is_ok());
        assert!(validate_claims_input(&"x".repeat(CLAIMS_MAX_SIZE as usize + 1)).is_err());

        let mut payload = Map::new();
        payload.insert("iss".to_string(), Value::String("issuer".to_string()));
        merge_claims(&mut payload, r#"{"custom":true}"#).expect("custom claims should merge");
        assert_eq!(payload["custom"], Value::Bool(true));
        assert!(merge_claims(&mut payload, r#"{"iss":"override"}"#).is_err());
        assert!(merge_claims(&mut payload, "[]").is_err());
        assert!(merge_claims(&mut payload, "not-json").is_err());
    }

    // Verify audience count accepts max-1, normal, and max but rejects max+1.
    #[test]
    fn token_audience_count_matrix() {
        assert!(validate_audience_count(&vec!["a".to_string(); AUD_MAX_COUNT - 1]).is_ok());
        assert!(validate_audience_count(&["a".to_string()]).is_ok());
        assert!(validate_audience_count(&vec!["a".to_string(); AUD_MAX_COUNT]).is_ok());
        assert!(validate_audience_count(&vec!["a".to_string(); AUD_MAX_COUNT + 1]).is_err());
    }

    // Validate exp/nbf/iat ordering, including the equality boundary.
    #[test]
    fn token_time_claim_matrix() {
        let now = default_exp();
        assert!(validate_time_claims(now, Some(now - 2), Some(now - 1)).is_ok());
        assert!(validate_time_claims(now, Some(now), None).is_err());
        assert!(validate_time_claims(now, None, Some(now)).is_err());
        assert!(validate_time_claims(now - DEFAULT_EXP_AFTER_SECONDS - 1, None, None).is_err());
    }

    /// SM2 token generation round-trips: the produced compact JWS has three
    /// segments and the SM2+SM3 signature verifies against the matching public key.
    #[test]
    fn sm2_token_generation_round_trips() {
        let group = openssl::ec::EcGroup::from_curve_name(Nid::SM2).expect("SM2 group");
        let ec = openssl::ec::EcKey::generate(&group).expect("generate SM2 EC key");
        let pkey = PKey::from_ec_key(ec).expect("PKey from SM2 EC key");
        let priv_pem = Zeroizing::new(pkey.private_key_to_pem_pkcs8().expect("priv pem"));
        let pub_pem = pkey.public_key_to_pem().expect("pub pem");

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_algorithm("SM2");
        let mut payload = Map::new();
        payload.insert("iss".to_string(), Value::String("rbs-cli".to_string()));
        payload.insert("sub".to_string(), Value::String("sm2-admin".to_string()));
        payload.insert("aud".to_string(), Value::String("globaltrustauthority-rbs".to_string()));
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        payload.insert("exp".to_string(), Value::Number(exp.into()));
        let payload = JwtPayload::from_map(payload).expect("payload");

        let token = generate_sm2_token(&priv_pem, &header, &payload).expect("sign SM2 token");
        let parts: Vec<&str> = token.token.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS must have 3 segments");

        // Verify the signature with the public key under the standard user ID
        // (test-only mirror of the rbs-core SM2 verifier).
        let pub_key = PKey::public_key_from_pem(&pub_pem).expect("parse pub");
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("decode sig");

        let mut md_ctx = openssl::md_ctx::MdCtx::new().expect("md ctx");
        let mut pkey_ctx: *mut ossl::EVP_PKEY_CTX = std::ptr::null_mut();
        let verified = unsafe {
            assert!(
                ossl::EVP_DigestVerifyInit(
                    md_ctx.as_ptr(),
                    &mut pkey_ctx,
                    MessageDigest::sm3().as_ptr(),
                    std::ptr::null_mut(),
                    pub_key.as_ptr() as *mut _,
                ) > 0
            );
            assert!(
                super::EVP_PKEY_CTX_set1_id(
                    pkey_ctx,
                    super::SM2_USER_ID.as_ptr() as *const std::os::raw::c_void,
                    super::SM2_USER_ID.len() as std::os::raw::c_int,
                ) > 0
            );
            assert!(
                ossl::EVP_DigestVerifyUpdate(
                    md_ctx.as_ptr(),
                    signing_input.as_ptr() as *const std::os::raw::c_void,
                    signing_input.len(),
                ) > 0
            );
            ossl::EVP_DigestVerifyFinal(md_ctx.as_ptr(), signature.as_ptr(), signature.len()) == 1
        };
        assert!(verified, "SM2 signature must verify under the standard user ID");
    }
}

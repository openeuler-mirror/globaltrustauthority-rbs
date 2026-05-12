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

use clap::Parser;
use josekit::jws::{EdDSA, ES256, ES384, ES512};
use josekit::jwt;
use jsonwebtoken::{
    decode as jwt_decode, decode_header as jwt_decode_header, Algorithm as JwtAlgorithm, DecodingKey, Validation,
};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use rbs_cli::config::{Cli, Command};
use rbs_cli::token::cmd::{GenerateArgs, TokenAlg, TokenGenerate};
use rbs_cli::token::cmd::{TokenCli, TokenCommand};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(prefix: &str, contents: &[u8]) -> Self {
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("system time before unix epoch").as_nanos();
        let path = std::env::temp_dir().join(format!("rbs-cli-{prefix}-{nanos}-{unique}.pem"));
        fs::write(&path, contents).expect("failed to write temporary key file");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn base_generate_args(private_key_file: &Path, alg: TokenAlg) -> GenerateArgs {
    GenerateArgs {
        private_key_file: Some(private_key_file.display().to_string()),
        alg: Some(alg),
        iss: "test-issuer".to_string(),
        sub: "test-subject".to_string(),
        aud: vec!["aud-1".to_string(), "aud-2".to_string()],
        role: Some("operator".to_string()),
        exp: Some(1_900_000_000),
        nbf: Some(1_800_000_000),
        iat: Some(1_800_000_100),
        jti: Some("token-id-1".to_string()),
        kid: Some("kid-1".to_string()),
        claims: Some(json!({"cluster": "test", "enabled": true}).to_string()),
        ..GenerateArgs::default()
    }
}

fn parse_generate_args(arguments: Vec<String>) -> Result<GenerateArgs, clap::Error> {
    let cli = Cli::try_parse_from(arguments)?;
    match cli.command {
        Some(Command::Token(TokenCli { command: TokenCommand::Generate(args) })) => Ok(args),
        _ => panic!("expected token gen command"),
    }
}

fn token_gen_args_with(flag: &str, value: String) -> Vec<String> {
    vec![
        "rbs-cli".to_string(),
        "token".to_string(),
        "gen".to_string(),
        "--private-key-file".to_string(),
        "token-key.pem".to_string(),
        flag.to_string(),
        value,
    ]
}

fn generate_ed25519_private_key_file(prefix: &str) -> TempFile {
    let private_key = PKey::generate_ed25519().expect("failed to generate Ed25519 key");
    let private_pem = private_key.private_key_to_pem_pkcs8().expect("failed to export Ed25519 private key");
    TempFile::new(prefix, &private_pem)
}

fn assert_common_claims(token: &str, expected_alg: &str, verifier: &dyn josekit::jws::JwsVerifier) {
    let (payload, header) = jwt::decode_with_verifier(token, verifier).expect("failed to verify generated token");

    assert_eq!(header.algorithm(), Some(expected_alg));
    assert_eq!(header.token_type(), Some("JWT"));
    assert_eq!(header.key_id(), Some("kid-1"));

    assert_eq!(payload.claim("iss"), Some(&json!("test-issuer")));
    assert_eq!(payload.claim("sub"), Some(&json!("test-subject")));
    assert_eq!(payload.claim("aud"), Some(&json!(["aud-1", "aud-2"])));
    assert_eq!(payload.claim("role"), Some(&json!("operator")));
    assert_eq!(payload.claim("exp"), Some(&json!(1_900_000_000u64)));
    assert_eq!(payload.claim("nbf"), Some(&json!(1_800_000_000u64)));
    assert_eq!(payload.claim("iat"), Some(&json!(1_800_000_100u64)));
    assert_eq!(payload.claim("jti"), Some(&json!("token-id-1")));
    assert_eq!(payload.claim("cluster"), Some(&json!("test")));
    assert_eq!(payload.claim("enabled"), Some(&json!(true)));
}

fn assert_common_claims_with_jsonwebtoken_pss(token: &str, expected_alg: JwtAlgorithm, public_key: &[u8]) {
    let decoding_key = DecodingKey::from_rsa_pem(public_key).expect("failed to build RSA decoding key");
    let mut validation = Validation::new(expected_alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let header = jwt_decode_header(token).expect("failed to decode JWT header");
    let token_data = jwt_decode::<Value>(token, &decoding_key, &validation).expect("failed to verify JWT token");
    let claims = token_data.claims;

    assert_eq!(header.alg, expected_alg);
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    assert_eq!(header.kid.as_deref(), Some("kid-1"));

    assert_eq!(claims.get("iss"), Some(&json!("test-issuer")));
    assert_eq!(claims.get("sub"), Some(&json!("test-subject")));
    assert_eq!(claims.get("aud"), Some(&json!(["aud-1", "aud-2"])));
    assert_eq!(claims.get("role"), Some(&json!("operator")));
    assert_eq!(claims.get("exp"), Some(&json!(1_900_000_000u64)));
    assert_eq!(claims.get("nbf"), Some(&json!(1_800_000_000u64)));
    assert_eq!(claims.get("iat"), Some(&json!(1_800_000_100u64)));
    assert_eq!(claims.get("jti"), Some(&json!("token-id-1")));
    assert_eq!(claims.get("cluster"), Some(&json!("test")));
    assert_eq!(claims.get("enabled"), Some(&json!(true)));
}

fn generate_rsa_pem(prefix: &str) -> (TempFile, Vec<u8>) {
    let rsa = Rsa::generate(2048).expect("failed to generate RSA key");
    let private_key = PKey::from_rsa(rsa).expect("failed to convert RSA key");
    let private_pem = private_key.private_key_to_pem_pkcs8().expect("failed to export RSA private key");
    let public_pem = private_key.public_key_to_pem().expect("failed to export RSA public key");
    let private_file = TempFile::new(prefix, &private_pem);

    (private_file, public_pem)
}

#[test]
fn generate_token_with_ps256() {
    let (private_file, public_pem) = generate_rsa_pem("ps256-private");
    let args = base_generate_args(private_file.path(), TokenAlg::Ps256);
    let token = TokenGenerate::generate(&args).expect("failed to generate PS256 token");
    assert_common_claims_with_jsonwebtoken_pss(&token.token, JwtAlgorithm::PS256, &public_pem);
}

#[test]
fn generate_token_with_ps384() {
    let (private_file, public_pem) = generate_rsa_pem("ps384-private");
    let args = base_generate_args(private_file.path(), TokenAlg::Ps384);
    let token = TokenGenerate::generate(&args).expect("failed to generate PS384 token");
    assert_common_claims_with_jsonwebtoken_pss(&token.token, JwtAlgorithm::PS384, &public_pem);
}

#[test]
fn generate_token_with_ps512() {
    let (private_file, public_pem) = generate_rsa_pem("ps512-private");
    let args = base_generate_args(private_file.path(), TokenAlg::Ps512);
    let token = TokenGenerate::generate(&args).expect("failed to generate PS512 token");
    assert_common_claims_with_jsonwebtoken_pss(&token.token, JwtAlgorithm::PS512, &public_pem);
}

#[test]
fn generate_token_with_es256() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("failed to load P-256 group");
    let ec_key = EcKey::generate(&group).expect("failed to generate P-256 key");
    let private_key = PKey::from_ec_key(ec_key).expect("failed to convert P-256 private key");
    let private_pem = private_key.private_key_to_pem_pkcs8().expect("failed to export P-256 private key");
    let public_pem = private_key.public_key_to_pem().expect("failed to export P-256 public key");
    let private_file = TempFile::new("es256-private", &private_pem);

    let args = base_generate_args(private_file.path(), TokenAlg::Es256);
    let token = TokenGenerate::generate(&args).expect("failed to generate ES256 token");
    let verifier = ES256.verifier_from_pem(&public_pem).expect("failed to build ES256 verifier");

    assert_common_claims(&token.token, "ES256", &verifier);
}

#[test]
fn generate_token_with_es384() {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("failed to load P-384 group");
    let ec_key = EcKey::generate(&group).expect("failed to generate P-384 key");
    let private_key = PKey::from_ec_key(ec_key).expect("failed to convert P-384 private key");
    let private_pem = private_key.private_key_to_pem_pkcs8().expect("failed to export P-384 private key");
    let public_pem = private_key.public_key_to_pem().expect("failed to export P-384 public key");
    let private_file = TempFile::new("es384-private", &private_pem);

    let args = base_generate_args(private_file.path(), TokenAlg::Es384);
    let token = TokenGenerate::generate(&args).expect("failed to generate ES384 token");
    let verifier = ES384.verifier_from_pem(&public_pem).expect("failed to build ES384 verifier");

    assert_common_claims(&token.token, "ES384", &verifier);
}

#[test]
fn generate_token_with_es512() {
    let group = EcGroup::from_curve_name(Nid::SECP521R1).expect("failed to load P-521 group");
    let ec_key = EcKey::generate(&group).expect("failed to generate P-521 key");
    let private_key = PKey::from_ec_key(ec_key).expect("failed to convert P-521 private key");
    let private_pem = private_key.private_key_to_pem_pkcs8().expect("failed to export P-521 private key");
    let public_pem = private_key.public_key_to_pem().expect("failed to export P-521 public key");
    let private_file = TempFile::new("es512-private", &private_pem);

    let args = base_generate_args(private_file.path(), TokenAlg::Es512);
    let token = TokenGenerate::generate(&args).expect("failed to generate ES512 token");
    let verifier = ES512.verifier_from_pem(&public_pem).expect("failed to build ES512 verifier");

    assert_common_claims(&token.token, "ES512", &verifier);
}

#[test]
fn generate_token_with_eddsa() {
    let private_key = PKey::generate_ed25519().expect("failed to generate Ed25519 key");
    let private_pem = private_key.private_key_to_pem_pkcs8().expect("failed to export Ed25519 private key");
    let public_pem = private_key.public_key_to_pem().expect("failed to export Ed25519 public key");
    let private_file = TempFile::new("eddsa-private", &private_pem);

    let args = base_generate_args(private_file.path(), TokenAlg::Eddsa);
    let token = TokenGenerate::generate(&args).expect("failed to generate EdDSA token");
    let verifier = EdDSA.verifier_from_pem(&public_pem).expect("failed to build EdDSA verifier");

    assert_common_claims(&token.token, "EdDSA", &verifier);
}

#[test]
fn token_gen_clap_accepts_max_length_string_fields() {
    for (flag, max_len) in
        [("--iss", 128usize), ("--sub", 64), ("--aud", 128), ("--role", 64), ("--jti", 128), ("--kid", 128)]
    {
        let args = token_gen_args_with(flag, "a".repeat(max_len));
        let parsed = parse_generate_args(args).expect("expected clap to accept boundary length");
        let parsed_value = match flag {
            "--iss" => parsed.iss,
            "--sub" => parsed.sub,
            "--aud" => parsed.aud.into_iter().next().expect("missing audience"),
            "--role" => parsed.role.expect("missing role"),
            "--jti" => parsed.jti.expect("missing jti"),
            "--kid" => parsed.kid.expect("missing kid"),
            _ => unreachable!("unsupported flag"),
        };
        assert_eq!(parsed_value.len(), max_len, "unexpected parsed length for {flag}");
    }
}

#[test]
fn token_gen_clap_rejects_oversized_string_fields() {
    for (flag, max_len) in
        [("--iss", 128usize), ("--sub", 64), ("--aud", 128), ("--role", 64), ("--jti", 128), ("--kid", 128)]
    {
        let args = token_gen_args_with(flag, "a".repeat(max_len + 1));
        let err = parse_generate_args(args).expect_err("expected clap to reject oversized input");
        let err_text = err.to_string();
        assert!(err_text.contains(&format!("value length must not exceed {max_len} characters")), "{err_text}");
    }
}

#[test]
fn token_gen_clap_rejects_oversized_inline_claims() {
    let args = token_gen_args_with("--claims", "a".repeat(65_537));
    let err = parse_generate_args(args).expect_err("expected clap to reject oversized claims JSON input");
    let err_text = err.to_string();
    assert!(err_text.contains("value length must not exceed 65536 characters"), "{err_text}");
}

#[test]
fn token_gen_clap_rejects_too_many_audiences() {
    let mut args = vec![
        "rbs-cli".to_string(),
        "token".to_string(),
        "gen".to_string(),
        "--private-key-file".to_string(),
        "token-key.pem".to_string(),
    ];
    for idx in 0..17 {
        args.push("--aud".to_string());
        args.push(format!("aud-{idx}"));
    }

    let parsed = parse_generate_args(args).expect("expected clap parsing to succeed before runtime validation");
    let err = TokenGenerate::generate(&parsed).expect_err("expected runtime validation to reject too many audiences");
    let err_text = err.to_string();
    assert!(err_text.contains("audience count must not exceed 16; got 17"), "{err_text}");
}

#[test]
fn token_gen_rejects_oversized_passphrase_file() {
    let private_key_file = generate_ed25519_private_key_file("passphrase-len-private");
    let passphrase_file = TempFile::new("passphrase-len", "a".repeat(1025).as_bytes());
    let args = GenerateArgs {
        private_key_file: Some(private_key_file.path().display().to_string()),
        private_key_passphrase: Some(Some(format!("@{}", passphrase_file.path().display()))),
        alg: Some(TokenAlg::Eddsa),
        ..GenerateArgs::default()
    };

    let err = TokenGenerate::generate(&args).expect_err("expected oversized passphrase file to be rejected");
    let err_text = err.to_string();
    assert!(err_text.contains("private key passphrase must not exceed 1024 characters"), "{err_text}");
}

#[test]
fn token_gen_rejects_invalid_time_claim_order() {
    let private_key_file = generate_ed25519_private_key_file("time-claims-private");
    let mut args = base_generate_args(private_key_file.path(), TokenAlg::Eddsa);
    args.exp = Some(1_900_000_000);
    args.nbf = Some(1_900_000_000);

    let err = TokenGenerate::generate(&args).expect_err("expected invalid nbf/exp ordering to be rejected");
    let err_text = err.to_string();
    assert!(err_text.contains("nbf must be earlier than exp"), "{err_text}");

    args.nbf = Some(1_800_000_000);
    args.iat = Some(1_900_000_000);
    let err = TokenGenerate::generate(&args).expect_err("expected invalid iat/exp ordering to be rejected");
    let err_text = err.to_string();
    assert!(err_text.contains("iat must be earlier than exp"), "{err_text}");
}

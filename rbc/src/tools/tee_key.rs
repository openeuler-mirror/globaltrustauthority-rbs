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

//! TEE ephemeral key pair management.
//!
//! Supports EC (P-256, ECDH-ES+A256KW) and RSA (4096-bit, RSA-OAEP) key pairs for
//! JWE envelope encryption/decryption in the RBS attestation flow.

use josekit::jwk::alg::ec::EcCurve;
use josekit::jwk::alg::ec::EcKeyPair;
use josekit::jwk::alg::rsa::RsaKeyPair;
use josekit::jwk::Jwk;
use josekit::jwe::{self, JweHeader};
use josekit::jwk::KeyPair;
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use base64::Engine as _;

use crate::error::RbcError;

/// Please refer to the docs for the algorithms supported by josekit: josekit/README.md
const DEFAULT_RSA_ENC_ALGORITHM: &str = "RSA-OAEP-256";
const DEFAULT_RSA_KEY_BYTE_SIZE: u32 = 512;
const DEFAULT_EC_ENC_ALGORITHM: &str = "ECDH-ES+A256KW";
const DEFAULT_EC_CURVE: EcCurve = EcCurve::P256;
const DEFAULT_CONTENT_ENCRYPTION_KEY: &str = "A256GCM";

/// Caller-supplied tee_pubkey validation allowlists.
const RSA_ALLOWED_ALGS: &[&str] = &["RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512"];
// ECDH-ES (direct key agreement) and weaker key-wrap variants are excluded.
const EC_ALLOWED_ALGS: &[&str] = &["ECDH-ES+A256KW"];
// P-256, P-384, P-521 are supported; secp256k1 and weaker curves excluded.
const EC_ALLOWED_CURVES: &[&str] = &["P-256", "P-384", "P-521"];

/// Supported key type for TEE key pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Rsa,
    Ec,
}

impl Default for KeyType {
    fn default() -> Self {
        Self::Rsa
    }
}

/// TEE key pair (private + public). Used by the client to generate ephemeral keys
/// and decrypt JWE envelopes returned by RBS.
pub struct TeeKeyPair {
    key_type: KeyType,
    /// Curve for EC keys; None for RSA.
    ec_curve: Option<EcCurve>,
    /// PKCS#8 DER-encoded private key, zeroed on drop.
    private_der: Zeroizing<Vec<u8>>,
    /// Public-only JWK (no private key fields).
    public_jwk: Jwk,
}

/// TEE public key only. Used by the server to encrypt JWE envelopes.
pub struct TeePublicKey {
    key_type: KeyType,
    public_jwk: Jwk,
}

fn ec_curve_from_jwk(jwk: &Jwk) -> Result<EcCurve, RbcError> {
    match jwk.parameter("crv").and_then(|v| v.as_str()) {
        Some("P-256") => Ok(EcCurve::P256),
        Some("P-384") => Ok(EcCurve::P384),
        Some("P-521") => Ok(EcCurve::P521),
        Some(c) => Err(RbcError::KeyGenError(format!("unsupported EC curve: {c}"))),
        None => Err(RbcError::KeyGenError("EC JWK missing 'crv' field".into())),
    }
}

impl TeeKeyPair {
    /// Generate an ephemeral key pair.
    ///
    /// - `Rsa`: RSA-4096
    /// - `Ec`: P-256
    pub fn generate(key_type: KeyType) -> Result<Self, RbcError> {
        match key_type {
            KeyType::Rsa => {
                let mut kp = RsaKeyPair::generate(DEFAULT_RSA_KEY_BYTE_SIZE * 8)
                    .map_err(|e| RbcError::KeyGenError(format!("RSA-4096 keygen: {e}")))?;
                kp.set_algorithm(Some(DEFAULT_RSA_ENC_ALGORITHM));
                let private_der = Zeroizing::new(kp.to_der_private_key());
                let public_jwk = kp.to_jwk_public_key();
                Ok(Self { key_type, ec_curve: None, private_der, public_jwk })
            }
            KeyType::Ec => {
                let mut kp = EcKeyPair::generate(DEFAULT_EC_CURVE)
                    .map_err(|e| RbcError::KeyGenError(format!("EC {} keygen: {e}", DEFAULT_EC_CURVE.name())))?;
                kp.set_algorithm(Some(DEFAULT_EC_ENC_ALGORITHM));
                let private_der = Zeroizing::new(kp.to_der_private_key());
                let public_jwk = kp.to_jwk_public_key();
                Ok(Self { key_type, ec_curve: Some(DEFAULT_EC_CURVE), private_der, public_jwk })
            }
        }
    }

    /// Load a key pair from a PEM-encoded private key.
    ///
    /// `passphrase` — required when the PEM is encrypted; caller is responsible for
    /// zeroizing this slice after the call returns.
    pub fn from_private_pem(
        key_type: KeyType,
        pem: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<Self, RbcError> {
        let plain_pem_buf: Option<Zeroizing<Vec<u8>>> = if let Some(pw) = passphrase {
            let pkey = PKey::private_key_from_pem_passphrase(pem.as_bytes(), pw)
                .map_err(|e| RbcError::KeyGenError(format!("PEM decrypt: {e}")))?;
            Some(Zeroizing::new(
                pkey.private_key_to_pem_pkcs8()
                    .map_err(|e| RbcError::KeyGenError(format!("PEM export: {e}")))?
            ))
        } else {
            None
        };

        let pem_bytes: &[u8] = match &plain_pem_buf {
            Some(buf) => buf.as_slice(),
            None      => pem.as_bytes(),
        };

        match key_type {
            KeyType::Rsa => {
                let kp = RsaKeyPair::from_pem(pem_bytes)
                    .map_err(|e| RbcError::KeyGenError(format!("RSA PEM parse: {e}")))?;
                let private_der = Zeroizing::new(kp.to_der_private_key());
                let public_jwk = kp.to_jwk_public_key();
                Ok(Self { key_type, ec_curve: None, private_der, public_jwk })
            }
            KeyType::Ec => {
                let kp = EcKeyPair::from_pem(pem_bytes, None)
                    .map_err(|e| RbcError::KeyGenError(format!("EC PEM parse: {e}")))?;
                let private_der = Zeroizing::new(kp.to_der_private_key());
                let public_jwk = kp.to_jwk_public_key();
                let ec_curve = Some(ec_curve_from_jwk(&public_jwk)?);
                Ok(Self { key_type, ec_curve, private_der, public_jwk })
            }
        }
    }

    /// Serialize the public key as a JWK JSON string.
    pub fn public_jwk_json(&self) -> Result<String, RbcError> {
        serde_json::to_string(&self.public_jwk.as_ref())
            .map_err(|e| RbcError::JsonError(e))
    }

    /// Extract the public key portion.
    pub fn public_key(&self) -> TeePublicKey {
        TeePublicKey { key_type: self.key_type, public_jwk: self.public_jwk.clone() }
    }

    /// Decrypt a JWE compact-serialization token.
    pub fn decrypt_jwe(&self, jwe_compact: &str) -> Result<Vec<u8>, RbcError> {
        match self.key_type {
            KeyType::Rsa => {
                let kp = RsaKeyPair::from_der(&*self.private_der)
                    .map_err(|e| RbcError::DecryptError(format!("load RSA private key: {e}")))?;
                let private_jwk = kp.to_jwk_key_pair();
                let decrypter = jwe::RSA_OAEP_256.decrypter_from_jwk(&private_jwk)
                    .map_err(|e| RbcError::DecryptError(format!("RSA decrypter: {e}")))?;
                let (payload, _header) = jwe::deserialize_compact(jwe_compact, &decrypter)
                    .map_err(|e| RbcError::DecryptError(format!("JWE decrypt: {e}")))?;
                Ok(payload)
            }
            KeyType::Ec => {
                let curve = self.ec_curve.ok_or_else(|| RbcError::DecryptError("EC curve not set".into()))?;
                let kp = EcKeyPair::from_der(&*self.private_der, Some(curve))
                    .map_err(|e| RbcError::DecryptError(format!("load EC private key: {e}")))?;
                let private_jwk = kp.to_jwk_key_pair();
                let decrypter = jwe::ECDH_ES_A256KW.decrypter_from_jwk(&private_jwk)
                    .map_err(|e| RbcError::DecryptError(format!("EC decrypter: {e}")))?;
                let (payload, _header) = jwe::deserialize_compact(jwe_compact, &decrypter)
                    .map_err(|e| RbcError::DecryptError(format!("JWE decrypt: {e}")))?;
                Ok(payload)
            }
        }
    }

    /// Export private key as PEM (for testing and caller-managed key round-trip).
    pub fn to_private_pem(&self) -> Result<String, RbcError> {
        match self.key_type {
            KeyType::Rsa => {
                let kp = RsaKeyPair::from_der(&*self.private_der)
                    .map_err(|e| RbcError::KeyGenError(format!("load RSA DER: {e}")))?;
                Ok(String::from_utf8_lossy(&kp.to_pem_private_key()).to_string())
            }
            KeyType::Ec => {
                let curve = self.ec_curve.ok_or_else(|| RbcError::KeyGenError("EC curve not set".into()))?;
                let kp = EcKeyPair::from_der(&*self.private_der, Some(curve))
                    .map_err(|e| RbcError::KeyGenError(format!("load EC DER: {e}")))?;
                Ok(String::from_utf8_lossy(&kp.to_pem_private_key()).to_string())
            }
        }
    }

}

impl TeePublicKey {
    /// Deserialize from a JWK JSON string.
    /// Infers key_type from the `kty` field.
    pub fn from_jwk_json(json: &str) -> Result<Self, RbcError> {
        let jwk = Jwk::from_bytes(json.as_bytes())
            .map_err(|e| RbcError::InvalidInput(format!("invalid JWK: {e}")))?;
        let key_type = match jwk.key_type() {
            "RSA" => KeyType::Rsa,
            "EC" => KeyType::Ec,
            other => return Err(RbcError::InvalidInput(
                format!("unsupported JWK kty: {other}")
            )),
        };
        Ok(Self { key_type, public_jwk: jwk })
    }

    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Validate JWK structure, required parameters, key strength, and algorithm allowlist.
    pub fn validate_params(&self) -> Result<(), RbcError> {
        match self.key_type {
            KeyType::Rsa => self.validate_rsa_params(),
            KeyType::Ec => self.validate_ec_params(),
        }
    }

    fn validate_rsa_params(&self) -> Result<(), RbcError> {
        let invalid = |msg: &str| Err(RbcError::InvalidInput(format!("invalid tee_pubkey: {msg}")));
        let n_b64 = match self.public_jwk.parameter("n").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return invalid("RSA key missing or invalid parameter 'n'"),
        };
        let n_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(n_b64)
            .map_err(|_| RbcError::InvalidInput("invalid tee_pubkey: RSA 'n' is not valid base64url".into()))?
            .len();
        if n_len < DEFAULT_RSA_KEY_BYTE_SIZE as usize {
            return invalid(&format!(
                "RSA key is {} bits, minimum required is {} bits",
                n_len.saturating_mul(8),
                DEFAULT_RSA_KEY_BYTE_SIZE.saturating_mul(8)
            ));
        }
        if self.public_jwk.parameter("e").and_then(|v| v.as_str()).is_none() {
            return invalid("RSA key missing or invalid parameter 'e'");
        }
        if let Some(alg) = self.public_jwk.algorithm() {
            if !RSA_ALLOWED_ALGS.contains(&alg) {
                return invalid(&format!(
                    "RSA algorithm '{alg}' is not allowed; allowed: {RSA_ALLOWED_ALGS:?}"
                ));
            }
        }
        Ok(())
    }

    fn validate_ec_params(&self) -> Result<(), RbcError> {
        let invalid = |msg: &str| Err(RbcError::InvalidInput(format!("invalid tee_pubkey: {msg}")));
        let crv = match self.public_jwk.parameter("crv").and_then(|v| v.as_str()) {
            Some(c) if EC_ALLOWED_CURVES.contains(&c) => c,
            Some(c) => return invalid(&format!("unsupported EC curve '{c}'; allowed: {EC_ALLOWED_CURVES:?}")),
            None => return invalid("EC key missing parameter 'crv'"),
        };
        // Expected coordinate byte length per curve (FIPS 186-4 table).
        let expected_coord_len: usize = match crv {
            "P-256" => 32,
            "P-384" => 48,
            "P-521" => 66,
            _ => unreachable!(),
        };
        self.validate_ec_coordinate("x", crv, expected_coord_len)?;
        self.validate_ec_coordinate("y", crv, expected_coord_len)?;
        if let Some(alg) = self.public_jwk.algorithm() {
            if !EC_ALLOWED_ALGS.contains(&alg) {
                return invalid(&format!(
                    "EC algorithm '{alg}' is not allowed; allowed: {EC_ALLOWED_ALGS:?}"
                ));
            }
        }
        Ok(())
    }

    fn validate_ec_coordinate(&self, coord: &str, crv: &str, expected_len: usize) -> Result<(), RbcError> {
        let invalid = |msg: &str| Err(RbcError::InvalidInput(format!("invalid tee_pubkey: {msg}")));
        let b64 = match self.public_jwk.parameter(coord).and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return invalid(&format!("EC key missing or invalid parameter '{coord}'")),
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| RbcError::InvalidInput(
                format!("invalid tee_pubkey: EC '{coord}' is not valid base64url")
            ))?;
        if bytes.len() != expected_len {
            return invalid(&format!(
                "EC '{coord}' length {} bytes does not match curve {crv} (expected {expected_len} bytes)",
                bytes.len()
            ));
        }
        Ok(())
    }

    /// Encrypt plaintext into a JWE compact-serialization token.
    pub fn encrypt_jwe(&self, plaintext: &[u8]) -> Result<String, RbcError> {
        let mut header = JweHeader::new();
        header.set_content_encryption(DEFAULT_CONTENT_ENCRYPTION_KEY);

        match self.key_type {
            KeyType::Rsa => {
                let encrypter = jwe::RSA_OAEP_256.encrypter_from_jwk(&self.public_jwk)
                    .map_err(|e| RbcError::EncryptError(format!("RSA encrypter: {e}")))?;
                jwe::serialize_compact(plaintext, &header, &encrypter)
                    .map_err(|e| RbcError::EncryptError(format!("JWE encrypt: {e}")))
            }
            KeyType::Ec => {
                let encrypter = jwe::ECDH_ES_A256KW.encrypter_from_jwk(&self.public_jwk)
                    .map_err(|e| RbcError::EncryptError(format!("EC encrypter: {e}")))?;
                jwe::serialize_compact(plaintext, &header, &encrypter)
                    .map_err(|e| RbcError::EncryptError(format!("JWE encrypt: {e}")))
            }
        }
    }
}
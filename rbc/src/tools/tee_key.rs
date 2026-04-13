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
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::RbcError;

/// Please refer to the docs for the algorithms supported by josekit: josekit/README.md
const RSA_ENCRYPTION_ALGORITHM: &str = "RSA-OAEP-256";
const RSA_KEY_LENGTH: u32 = 4096;
const EC_ENCRYPTION_ALGORITHM: &str = "ECDH-ES+A256KW";
const DEFAULT_EC_CURVE: EcCurve = EcCurve::P256;
const CONTENT_ENCRYPTION_KEY: &str = "A256GCM";


/// Supported key algorithms for TEE key pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyAlgorithm {
    Rsa,
    Ec,
}

impl Default for KeyAlgorithm {
    fn default() -> Self {
        Self::Rsa
    }
}

/// TEE key pair (private + public). Used by the client to generate ephemeral keys
/// and decrypt JWE envelopes returned by RBS.
pub struct TeeKeyPair {
    algorithm: KeyAlgorithm,
    /// PKCS#8 DER-encoded private key, zeroed on drop.
    private_der: Zeroizing<Vec<u8>>,
    /// Public-only JWK (no private key fields).
    public_jwk: Jwk,
}

/// TEE public key only. Used by the server to encrypt JWE envelopes.
pub struct TeePublicKey {
    algorithm: KeyAlgorithm,
    public_jwk: Jwk,
}

impl TeeKeyPair {
    /// Generate an ephemeral key pair.
    ///
    /// - `Rsa`: RSA-4096
    /// - `Ec`: P-256
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self, RbcError> {
        match algorithm {
            KeyAlgorithm::Rsa => {
                let mut kp = RsaKeyPair::generate(RSA_KEY_LENGTH)
                    .map_err(|e| RbcError::KeyGenError(format!("RSA-4096 keygen: {e}")))?;
                kp.set_algorithm(Some(RSA_ENCRYPTION_ALGORITHM));
                let private_der = Zeroizing::new(kp.to_der_private_key());
                let public_jwk = kp.to_jwk_public_key();
                Ok(Self { algorithm, private_der, public_jwk })
            }
            KeyAlgorithm::Ec => {
                let mut kp = EcKeyPair::generate(DEFAULT_EC_CURVE)
                    .map_err(|e| RbcError::KeyGenError(format!("EC {} keygen: {e}", DEFAULT_EC_CURVE.name())))?;
                kp.set_algorithm(Some(EC_ENCRYPTION_ALGORITHM));
                let private_der = Zeroizing::new(kp.to_der_private_key());
                let public_jwk = kp.to_jwk_public_key();
                Ok(Self { algorithm, private_der, public_jwk })
            }
        }
    }

    /// Load a key pair from a PEM-encoded private key.
    pub fn from_private_pem(algorithm: KeyAlgorithm, pem: &str) -> Result<Self, RbcError> {
        match algorithm {
            KeyAlgorithm::Rsa => {
                let kp = RsaKeyPair::from_pem(pem.as_bytes())
                    .map_err(|e| RbcError::KeyGenError(format!("RSA PEM parse: {e}")))?;
                let private_der = Zeroizing::new(kp.to_der_private_key());
                let public_jwk = kp.to_jwk_public_key();
                Ok(Self { algorithm, private_der, public_jwk })
            }
            KeyAlgorithm::Ec => {
                let kp = EcKeyPair::from_pem(pem.as_bytes(), Some(EcCurve::P256))
                    .map_err(|e| RbcError::KeyGenError(format!("EC PEM parse: {e}")))?;
                let private_der = Zeroizing::new(kp.to_der_private_key());
                let public_jwk = kp.to_jwk_public_key();
                Ok(Self { algorithm, private_der, public_jwk })
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
        TeePublicKey {
            algorithm: self.algorithm,
            public_jwk: self.public_jwk.clone(),
        }
    }

    /// Decrypt a JWE compact-serialization token.
    pub fn decrypt_jwe(&self, jwe_compact: &str) -> Result<Vec<u8>, RbcError> {
        match self.algorithm {
            KeyAlgorithm::Rsa => {
                let kp = RsaKeyPair::from_der(&*self.private_der)
                    .map_err(|e| RbcError::DecryptError(format!("load RSA private key: {e}")))?;
                let private_jwk = kp.to_jwk_key_pair();
                let decrypter = jwe::RSA_OAEP_256.decrypter_from_jwk(&private_jwk)
                    .map_err(|e| RbcError::DecryptError(format!("RSA decrypter: {e}")))?;
                let (payload, _header) = jwe::deserialize_compact(jwe_compact, &decrypter)
                    .map_err(|e| RbcError::DecryptError(format!("JWE decrypt: {e}")))?;
                Ok(payload)
            }
            KeyAlgorithm::Ec => {
                let kp = EcKeyPair::from_der(&*self.private_der, Some(EcCurve::P256))
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
        match self.algorithm {
            KeyAlgorithm::Rsa => {
                let kp = RsaKeyPair::from_der(&*self.private_der)
                    .map_err(|e| RbcError::KeyGenError(format!("load RSA DER: {e}")))?;
                Ok(String::from_utf8_lossy(&kp.to_pem_private_key()).to_string())
            }
            KeyAlgorithm::Ec => {
                let kp = EcKeyPair::from_der(&*self.private_der, Some(EcCurve::P256))
                    .map_err(|e| RbcError::KeyGenError(format!("load EC DER: {e}")))?;
                Ok(String::from_utf8_lossy(&kp.to_pem_private_key()).to_string())
            }
        }
    }

}

impl TeePublicKey {
    /// Deserialize from a JWK JSON string.
    /// Infers algorithm from the `kty` field.
    pub fn from_jwk_json(json: &str) -> Result<Self, RbcError> {
        let jwk = Jwk::from_bytes(json.as_bytes())
            .map_err(|e| RbcError::KeyGenError(format!("JWK parse: {e}")))?;
        let algorithm = match jwk.key_type() {
            "RSA" => KeyAlgorithm::Rsa,
            "EC" => KeyAlgorithm::Ec,
            other => return Err(RbcError::KeyGenError(
                format!("unsupported JWK kty: {other}")
            )),
        };
        Ok(Self { algorithm, public_jwk: jwk })
    }

    /// Encrypt plaintext into a JWE compact-serialization token.
    pub fn encrypt_jwe(&self, plaintext: &[u8]) -> Result<String, RbcError> {
        let mut header = JweHeader::new();
        header.set_content_encryption(CONTENT_ENCRYPTION_KEY);

        match self.algorithm {
            KeyAlgorithm::Rsa => {
                let encrypter = jwe::RSA_OAEP_256.encrypter_from_jwk(&self.public_jwk)
                    .map_err(|e| RbcError::EncryptError(format!("RSA encrypter: {e}")))?;
                jwe::serialize_compact(plaintext, &header, &encrypter)
                    .map_err(|e| RbcError::EncryptError(format!("JWE encrypt: {e}")))
            }
            KeyAlgorithm::Ec => {
                let encrypter = jwe::ECDH_ES_A256KW.encrypter_from_jwk(&self.public_jwk)
                    .map_err(|e| RbcError::EncryptError(format!("EC encrypter: {e}")))?;
                jwe::serialize_compact(plaintext, &header, &encrypter)
                    .map_err(|e| RbcError::EncryptError(format!("JWE encrypt: {e}")))
            }
        }
    }
}
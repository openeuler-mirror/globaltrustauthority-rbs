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

//! AttestToken verification module.

use crate::auth::{AttestContext, AuthError, TokenType};
use base64::Engine;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use rbs_api_types::config::AttestTokenVerificationConfig;
use serde_json::Value;
use std::fs;
use chrono::Utc;

/// AttestToken verifier
#[derive(Debug, Clone)]
pub struct AttestTokenVerifier {
    config: AttestTokenVerificationConfig,
    /// Public key for verification
    public_key: PKey<Public>,
}

impl AttestTokenVerifier {
    /// Create a new AttestTokenVerifier from config
    pub fn new(config: AttestTokenVerificationConfig) -> Self {
        let public_key_pem = fs::read(&config.public_key_path)
            .expect("Failed to read AttestToken public key file");

        // Load public key from PEM
        let rsa = Rsa::public_key_from_pem(&public_key_pem)
            .expect("Failed to parse RSA public key");
        let public_key = PKey::from_rsa(rsa)
            .expect("Failed to create PKey from RSA");

        Self { config, public_key }
    }

    /// Verify AttestToken and return AttestContext
    pub async fn verify(&self, token: &str) -> Result<AttestContext, AuthError> {
        // Parse JWT-like token format (same as Bearer JWT)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::TokenInvalid { reason: "invalid token format".to_string() });
        }

        let header = parts[0];
        let payload = parts[1];
        let signature = parts[2];

        // Decode header
        let header_bytes = decode_jwt_part(header)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to decode header: {}", e) })?;

        let header_json: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to parse header: {}", e) })?;

        // Get algorithm
        let alg = header_json.get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing alg in header".to_string() })?;

        // Decode payload
        let payload_bytes = decode_jwt_part(payload)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to decode payload: {}", e) })?;

        let claims: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to parse claims: {}", e) })?;

        // Decode signature
        let signature_bytes = decode_jwt_part(signature)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to decode signature: {}", e) })?;

        // Verify signature
        self.verify_signature(alg, header, payload, &signature_bytes)?;

        // Extract standard claims
        let iss = claims.get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::TokenInvalid { reason: "missing iss claim".to_string() })?
            .to_string();

        let exp = claims.get("exp")
            .and_then(|v| v.as_i64());

        // Verify issuer
        if iss != self.config.issuer {
            return Err(AuthError::TokenInvalid { reason: format!("issuer mismatch: expected '{}'", self.config.issuer) });
        }

        // Verify expiration if present
        if let Some(exp) = exp {
            let now = Utc::now().timestamp();
            if exp < now {
                return Err(AuthError::TokenExpired);
            }
        }

        Ok(AttestContext {
            claims,
            token_type: TokenType::Attest,
        })
    }

    /// Verify signature based on algorithm
    fn verify_signature(&self, alg: &str, header: &str, payload: &str, signature: &[u8]) -> Result<(), AuthError> {
        let message = format!("{}.{}", header, payload);

        match alg {
            // RSA PKCS#1 v1.5 signatures (only RSA-4096 supported)
            "RS256" => self.verify_rsa_signature(MessageDigest::sha256(), &message, signature, false),
            "RS384" => self.verify_rsa_signature(MessageDigest::sha384(), &message, signature, false),
            "RS512" => self.verify_rsa_signature(MessageDigest::sha512(), &message, signature, false),
            // RSA-PSS signatures (only RSA-4096 supported)
            "PS256" => self.verify_rsa_signature(MessageDigest::sha256(), &message, signature, true),
            "PS384" => self.verify_rsa_signature(MessageDigest::sha384(), &message, signature, true),
            "PS512" => self.verify_rsa_signature(MessageDigest::sha512(), &message, signature, true),
            // ECDSA signatures
            "ES256" => self.verify_signature_common(MessageDigest::sha256(), &message, signature),
            "ES384" => self.verify_signature_common(MessageDigest::sha384(), &message, signature),
            "ES512" => self.verify_signature_common(MessageDigest::sha512(), &message, signature),
            // EdDSA (Ed25519) - no digest needed
            "EdDSA" => self.verify_signature_no_digest(&message, signature),
            // SM2 signature (uses SM3 hash)
            "SM2" => self.verify_signature_common(MessageDigest::sm3(), &message, signature),
            _ => Err(AuthError::TokenInvalid { reason: format!("unsupported algorithm: {}", alg) }),
        }
    }

    /// Verify RSA signature (PKCS#1 v1.5 or PSS)
    fn verify_rsa_signature(&self, md: MessageDigest, message: &str, signature: &[u8], pss: bool) -> Result<(), AuthError> {
        let rsa = self.public_key.rsa()
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to get RSA key: {}", e) })?;

        // RSA-4096 size is 512 bytes (4096 / 8)
        let key_size = rsa.size();
        if key_size != 512 {
            return Err(AuthError::TokenInvalid { reason: format!("RSA key size must be 4096 bits, got {} bits", key_size * 8) });
        }

        let mut verifier = Verifier::new(md, &self.public_key)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create verifier: {}", e) })?;

        if pss {
            verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
                .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to set RSA padding: {}", e) })?;
        }

        verifier.update(message.as_bytes())
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to update verifier: {}", e) })?;

        let valid = verifier.verify(signature)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("signature verification failed: {}", e) })?;

        if !valid {
            return Err(AuthError::TokenInvalid { reason: "invalid signature".to_string() });
        }
        Ok(())
    }

    /// Verify signature with digest (ECDSA, SM2)
    fn verify_signature_common(&self, md: MessageDigest, message: &str, signature: &[u8]) -> Result<(), AuthError> {
        let mut verifier = Verifier::new(md, &self.public_key)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create verifier: {}", e) })?;

        verifier.update(message.as_bytes())
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to update verifier: {}", e) })?;

        let valid = verifier.verify(signature)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("signature verification failed: {}", e) })?;

        if !valid {
            return Err(AuthError::TokenInvalid { reason: "invalid signature".to_string() });
        }
        Ok(())
    }

    /// Verify signature without digest (EdDSA)
    fn verify_signature_no_digest(&self, message: &str, signature: &[u8]) -> Result<(), AuthError> {
        let mut verifier = Verifier::new_without_digest(&self.public_key)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create verifier: {}", e) })?;

        verifier.update(message.as_bytes())
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to update verifier: {}", e) })?;

        let valid = verifier.verify(signature)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("signature verification failed: {}", e) })?;

        if !valid {
            return Err(AuthError::TokenInvalid { reason: "invalid signature".to_string() });
        }
        Ok(())
    }
}

fn decode_jwt_part(part: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // JWT uses base64url encoding
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    engine.decode(part)
}

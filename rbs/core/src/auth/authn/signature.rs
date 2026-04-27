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

//! JWT signature verification utilities.

use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;

use crate::auth::error::AuthError;

/// ECDSA signature size for a given curve (bytes for R or S component)
/// P-256: 32, P-384: 48, P-521: 66
pub fn ecdsa_key_size_for_alg(alg: &str) -> Option<usize> {
    match alg {
        "ES256" | "SM2" => Some(32),
        "ES384" => Some(48),
        "ES512" => Some(66),
        _ => None,
    }
}

/// Convert ECDSA signature from R||S (JWT/JWS format) to DER (OpenSSL format).
pub fn ecdsa_sig_rs_to_der(sig: &[u8], key_size: usize) -> Result<Vec<u8>, AuthError> {
    let expected_len = key_size * 2;
    if sig.len() != expected_len {
        return Err(AuthError::TokenInvalid {
            reason: format!(
                "invalid ECDSA signature length: expected {} bytes for R||S, got {}",
                expected_len,
                sig.len()
            ),
        });
    }

    let r = &sig[..key_size];
    let s = &sig[key_size..];

    let mut r_der = vec![0x02];
    let r_len = encode_der_length(key_size);
    r_der.extend_from_slice(&r_len);
    r_der.extend_from_slice(r);

    let mut s_der = vec![0x02];
    let s_len = encode_der_length(key_size);
    s_der.extend_from_slice(&s_len);
    s_der.extend_from_slice(s);

    let mut seq = vec![0x30];
    let seq_len = r_der.len() + s_der.len();
    let der_len = encode_der_length(seq_len);
    seq.extend_from_slice(&der_len);
    seq.extend_from_slice(&r_der);
    seq.extend_from_slice(&s_der);

    Ok(seq)
}

fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        let num_bytes = bytes.len();
        vec![0x80 | num_bytes as u8]
            .into_iter()
            .chain(bytes.into_iter())
            .collect()
    }
}

/// Decode a base64url-encoded JWT part (header, payload, or signature)
pub fn decode_jwt_part(part: &str) -> Result<Vec<u8>, AuthError> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    engine.decode(part).map_err(|e| AuthError::TokenInvalid {
        reason: format!("base64 decode error: {}", e),
    })
}

/// Verify JWT signature
pub fn verify_jwt_signature(
    alg: &str,
    header: &str,
    payload: &str,
    signature: &[u8],
    public_key: &PKey<Public>,
) -> Result<(), AuthError> {
    let message = format!("{}.{}", header, payload);

    match alg {
        // RSA PKCS#1 v1.5 signatures
        "RS256" => verify_rsa_signature(MessageDigest::sha256(), &message, signature, false, public_key),
        "RS384" => verify_rsa_signature(MessageDigest::sha384(), &message, signature, false, public_key),
        "RS512" => verify_rsa_signature(MessageDigest::sha512(), &message, signature, false, public_key),
        // RSA-PSS signatures
        "PS256" => verify_rsa_signature(MessageDigest::sha256(), &message, signature, true, public_key),
        "PS384" => verify_rsa_signature(MessageDigest::sha384(), &message, signature, true, public_key),
        "PS512" => verify_rsa_signature(MessageDigest::sha512(), &message, signature, true, public_key),
        // ECDSA signatures - convert R||S to DER format
        "ES256" => {
            let key_size = ecdsa_key_size_for_alg(alg).unwrap();
            let der_sig = ecdsa_sig_rs_to_der(signature, key_size)?;
            verify_signature_with_digest(MessageDigest::sha256(), &message, &der_sig, public_key)
        }
        "ES384" => {
            let key_size = ecdsa_key_size_for_alg(alg).unwrap();
            let der_sig = ecdsa_sig_rs_to_der(signature, key_size)?;
            verify_signature_with_digest(MessageDigest::sha384(), &message, &der_sig, public_key)
        }
        "ES512" => {
            let key_size = ecdsa_key_size_for_alg(alg).unwrap();
            let der_sig = ecdsa_sig_rs_to_der(signature, key_size)?;
            verify_signature_with_digest(MessageDigest::sha512(), &message, &der_sig, public_key)
        }
        // EdDSA (Ed25519) - no digest needed
        "EdDSA" => verify_signature_no_digest(&message, signature, public_key),
        // SM2 signature (uses SM3 hash) - convert R||S to DER format
        "SM2" => {
            let key_size = ecdsa_key_size_for_alg(alg).unwrap();
            let der_sig = ecdsa_sig_rs_to_der(signature, key_size)?;
            verify_signature_with_digest(MessageDigest::sm3(), &message, &der_sig, public_key)
        }
        _ => Err(AuthError::TokenInvalid { reason: format!("unsupported algorithm: {}", alg) }),
    }
}

/// Verify RSA signature (PKCS#1 v1.5 or PSS)
fn verify_rsa_signature(
    md: MessageDigest,
    message: &str,
    signature: &[u8],
    pss: bool,
    public_key: &PKey<Public>,
) -> Result<(), AuthError> {
    let mut verifier = Verifier::new(md, public_key)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create verifier: {}", e) })?;

    if pss {
        verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to set RSA padding: {}", e) })?;
    }

    let valid = verifier.verify_oneshot(signature, message.as_bytes())
        .map_err(|e| AuthError::TokenInvalid { reason: format!("signature verification failed: {}", e) })?;

    if !valid {
        return Err(AuthError::TokenInvalid { reason: "invalid signature".to_string() });
    }
    Ok(())
}

/// Verify signature with digest (ECDSA, SM2)
fn verify_signature_with_digest(
    md: MessageDigest,
    message: &str,
    signature: &[u8],
    public_key: &PKey<Public>,
) -> Result<(), AuthError> {
    let mut verifier = Verifier::new(md, public_key)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create verifier: {}", e) })?;

    let valid = verifier.verify_oneshot(signature, message.as_bytes())
        .map_err(|e| AuthError::TokenInvalid { reason: format!("signature verification failed: {}", e) })?;

    if !valid {
        return Err(AuthError::TokenInvalid { reason: "invalid signature".to_string() });
    }
    Ok(())
}

/// Verify signature without digest (EdDSA)
fn verify_signature_no_digest(message: &str, signature: &[u8], public_key: &PKey<Public>) -> Result<(), AuthError> {
    let mut verifier = Verifier::new_without_digest(public_key)
        .map_err(|e| AuthError::TokenInvalid { reason: format!("failed to create verifier: {}", e) })?;

    let valid = verifier.verify_oneshot(signature, message.as_bytes())
        .map_err(|e| AuthError::TokenInvalid { reason: format!("signature verification failed: {}", e) })?;

    if !valid {
        return Err(AuthError::TokenInvalid { reason: "invalid signature".to_string() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_jwt_part_valid() {
        let result = decode_jwt_part("SGVsbG8");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    #[test]
    fn test_decode_jwt_part_invalid() {
        let result = decode_jwt_part("!!!invalid");
        assert!(result.is_err());
    }
}

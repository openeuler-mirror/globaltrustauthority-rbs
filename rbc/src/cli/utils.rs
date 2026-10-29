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

//! Shared private-key loading helpers for RBC and RBS CLI resource decryption.

use std::fs;

use openssl::pkey::PKey;
use zeroize::Zeroizing;

use crate::RbcError;

/// Read a PEM private key, decrypt it when `passphrase` is supplied, and return
/// an unencrypted PKCS#8 PEM held in zeroizing memory.
pub fn load_private_key_pem(path: &str, passphrase: Option<&[u8]>) -> Result<Zeroizing<String>, RbcError> {
    let source_pem = Zeroizing::new(
        fs::read(path).map_err(|err| RbcError::InvalidInput(format!("read private key file `{path}`: {err}")))?,
    );
    let private_key = match passphrase {
        Some(passphrase) => PKey::private_key_from_pem_passphrase(&source_pem, passphrase)
            .map_err(|err| RbcError::InvalidInput(format!("parse encrypted private key PEM: {err}")))?,
        // Never allow OpenSSL's default password callback to read from the terminal. Interactive
        // prompting belongs to the CLI argument layer; this loader must return immediately when an
        // encrypted PEM reaches it without a passphrase.
        None => PKey::private_key_from_pem_callback(&source_pem, |_| Ok(0))
            .map_err(|err| RbcError::InvalidInput(format!("parse private key PEM: {err}")))?,
    };

    let exported_pem = Zeroizing::new(
        private_key
            .private_key_to_pem_pkcs8()
            .map_err(|err| RbcError::KeyGenError(format!("export private key PEM: {err}")))?,
    );
    let pem = std::str::from_utf8(&exported_pem)
        .map_err(|err| RbcError::KeyGenError(format!("exported private key PEM is not UTF-8: {err}")))?;
    Ok(Zeroizing::new(pem.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::tee_key::{KeyType, TeeKeyPair};
    use openssl::symm::Cipher;
    use std::path::PathBuf;

    /// Unique temporary file path; the crate has no `tempfile` dev-dependency.
    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rbc-cli-utils-{}-{name}", std::process::id()))
    }

    fn write_file(path: &PathBuf, contents: &[u8]) {
        fs::write(path, contents).expect("write temp file");
    }

    #[test]
    fn loads_unencrypted_private_key_and_returns_pkcs8_pem() {
        let kp = TeeKeyPair::generate(KeyType::Ec).expect("ec keygen");
        let path = temp_file("plain.pem");
        write_file(&path, kp.to_private_pem().expect("private pem").as_bytes());

        let pem = load_private_key_pem(path.to_str().expect("utf8 path"), None).expect("load plain pem");
        assert!(pem.contains("BEGIN PRIVATE KEY"), "expected PKCS#8 PEM, got: {}", *pem);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn loads_passphrase_encrypted_private_key() {
        let kp = TeeKeyPair::generate(KeyType::Ec).expect("ec keygen");
        let pkey = openssl::pkey::PKey::private_key_from_pem(kp.to_private_pem().expect("private pem").as_bytes())
            .expect("parse pem");
        let encrypted = pkey
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"correct passphrase")
            .expect("encrypt pem");

        let path = temp_file("encrypted.pem");
        write_file(&path, &encrypted);

        let pem = load_private_key_pem(path.to_str().expect("utf8 path"), Some(b"correct passphrase"))
            .expect("load encrypted pem");
        assert!(pem.contains("BEGIN PRIVATE KEY"), "expected decrypted PKCS#8 PEM, got: {}", *pem);
        assert!(!pem.contains("ENCRYPTED"), "output must not stay encrypted");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn missing_private_key_file_returns_invalid_input() {
        let path = temp_file("absent.pem");
        let err = load_private_key_pem(path.to_str().expect("utf8 path"), None).expect_err("missing file");
        assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
        assert!(err.to_string().contains("read private key file"), "unexpected message: {err}");
    }

    #[test]
    fn malformed_private_key_returns_invalid_input() {
        let path = temp_file("garbage.pem");
        write_file(&path, b"not a private key at all\n");

        let err = load_private_key_pem(path.to_str().expect("utf8 path"), None).expect_err("malformed pem");
        assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
        assert!(err.to_string().contains("parse private key PEM"), "unexpected message: {err}");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn encrypted_private_key_without_passphrase_returns_invalid_input() {
        let kp = TeeKeyPair::generate(KeyType::Ec).expect("ec keygen");
        let pkey = openssl::pkey::PKey::private_key_from_pem(kp.to_private_pem().expect("private pem").as_bytes())
            .expect("parse pem");
        let encrypted = pkey
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"secret")
            .expect("encrypt pem");

        let path = temp_file("encrypted-no-pass.pem");
        write_file(&path, &encrypted);

        // The non-interactive callback must fail immediately instead of prompting.
        let err = load_private_key_pem(path.to_str().expect("utf8 path"), None).expect_err("needs passphrase");
        assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
        assert!(err.to_string().contains("parse private key PEM"), "unexpected message: {err}");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn encrypted_private_key_with_wrong_passphrase_returns_invalid_input() {
        let kp = TeeKeyPair::generate(KeyType::Ec).expect("ec keygen");
        let pkey = openssl::pkey::PKey::private_key_from_pem(kp.to_private_pem().expect("private pem").as_bytes())
            .expect("parse pem");
        let encrypted = pkey
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"correct")
            .expect("encrypt pem");

        let path = temp_file("encrypted-wrong-pass.pem");
        write_file(&path, &encrypted);

        let err = load_private_key_pem(path.to_str().expect("utf8 path"), Some(b"wrong"))
            .expect_err("wrong passphrase");
        assert!(matches!(err, RbcError::InvalidInput(_)), "expected InvalidInput, got {err:?}");
        assert!(err.to_string().contains("parse encrypted private key PEM"), "unexpected message: {err}");

        let _ = fs::remove_file(path);
    }
}

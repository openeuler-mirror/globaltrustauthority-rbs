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
        None => PKey::private_key_from_pem(&source_pem)
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

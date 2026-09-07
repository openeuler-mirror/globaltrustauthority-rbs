/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! SM2 (SM3 digest) signing and verification with the standard user ID pinned.
//!
//! SM2 signatures (GM/T 0003.2) hash the message as `SM3(Z || M)`, where `Z`
//! is derived from the signer's user ID. The standard default user ID is
//! `"1234567812345678"` (GM/T 0009). OpenSSL up to and including 3.4 applied
//! this default implicitly; from OpenSSL 3.5 on, the provider-based SM2
//! signature context starts with an *empty* user ID (`SM2_DEFAULT_USERID` is
//! no longer referenced anywhere in the library). A plain
//! `Signer::new(MessageDigest::sm3(), ..)` / `Verifier::new(..)` pair therefore
//! produces and expects empty-ID signatures that no standard SM2
//! implementation (OpenSSL <= 3.4, GmSSL, Tongsuo, hardware SM2 modules,
//! BouncyCastle, ...) interoperates with.
//!
//! Every RBS SM2 operation goes through this module, which calls
//! `EVP_PKEY_CTX_set1_id()` with [`SM2_USER_ID`] right after
//! `EVP_Digest{Sign,Verify}Init`: tokens signed by RBS verify everywhere, and
//! tokens signed by standard implementations verify here.
//!
//! `openssl-sys` does not bind `EVP_PKEY_CTX_set1_id`, so it is declared
//! directly against the libcrypto that `openssl-sys` links.

use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::md_ctx::MdCtx;
use openssl::pkey::{HasPrivate, HasPublic, PKeyRef};
use openssl_sys as ffi;
use std::os::raw::{c_int, c_void};
use std::ptr;

/// GM/T 0009 default SM2 user ID, fixed for cross-implementation interop.
pub const SM2_USER_ID: &[u8] = b"1234567812345678";

// Not bound by `openssl-sys`; declared against the linked libcrypto
// (vendored OpenSSL 3.6.2 exports it from crypto/evp/pmeth_lib.c).
extern "C" {
    fn EVP_PKEY_CTX_set1_id(ctx: *mut ffi::EVP_PKEY_CTX, id: *const c_void, len: c_int) -> c_int;
}

fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn set_user_id(pkey_ctx: *mut ffi::EVP_PKEY_CTX, user_id: &[u8]) -> Result<(), ErrorStack> {
    unsafe {
        cvt(EVP_PKEY_CTX_set1_id(
            pkey_ctx,
            user_id.as_ptr() as *const c_void,
            user_id.len() as c_int,
        ))
    }
    .map(|_| ())
}

/// Sign `data` with SM2 (SM3 digest) under the standard default user ID.
pub fn sign(pkey: &PKeyRef<impl HasPrivate>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    sign_with_id(pkey, data, SM2_USER_ID)
}

/// Sign with an explicit SM2 user ID (test/verification use only; production
/// code must use [`sign`]).
pub(crate) fn sign_with_id(
    pkey: &PKeyRef<impl HasPrivate>,
    data: &[u8],
    user_id: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut md_ctx = MdCtx::new()?;
    let mut pkey_ctx: *mut ffi::EVP_PKEY_CTX = ptr::null_mut();
    unsafe {
        cvt(ffi::EVP_DigestSignInit(
            md_ctx.as_ptr(),
            &mut pkey_ctx,
            MessageDigest::sm3().as_ptr(),
            ptr::null_mut(),
            pkey.as_ptr() as *mut _,
        ))?;
        set_user_id(pkey_ctx, user_id)?;
        cvt(ffi::EVP_DigestSignUpdate(
            md_ctx.as_ptr(),
            data.as_ptr() as *const c_void,
            data.len(),
        ))?;
        let mut siglen: usize = 0;
        cvt(ffi::EVP_DigestSignFinal(
            md_ctx.as_ptr(),
            ptr::null_mut(),
            &mut siglen,
        ))?;
        let mut sig = vec![0u8; siglen];
        cvt(ffi::EVP_DigestSignFinal(
            md_ctx.as_ptr(),
            sig.as_mut_ptr(),
            &mut siglen,
        ))?;
        sig.truncate(siglen);
        Ok(sig)
    }
}

/// Verify an SM2 (SM3 digest) signature under the standard default user ID.
///
/// Returns `Ok(false)` for an invalid signature and `Err` for library errors,
/// mirroring `openssl::sign::Verifier::verify`.
pub fn verify(
    pkey: &PKeyRef<impl HasPublic>,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, ErrorStack> {
    verify_with_id(pkey, data, signature, SM2_USER_ID)
}

/// Verify with an explicit SM2 user ID (test/verification use only).
pub(crate) fn verify_with_id(
    pkey: &PKeyRef<impl HasPublic>,
    data: &[u8],
    signature: &[u8],
    user_id: &[u8],
) -> Result<bool, ErrorStack> {
    let mut md_ctx = MdCtx::new()?;
    let mut pkey_ctx: *mut ffi::EVP_PKEY_CTX = ptr::null_mut();
    unsafe {
        cvt(ffi::EVP_DigestVerifyInit(
            md_ctx.as_ptr(),
            &mut pkey_ctx,
            MessageDigest::sm3().as_ptr(),
            ptr::null_mut(),
            pkey.as_ptr() as *mut _,
        ))?;
        set_user_id(pkey_ctx, user_id)?;
        cvt(ffi::EVP_DigestVerifyUpdate(
            md_ctx.as_ptr(),
            data.as_ptr() as *const c_void,
            data.len(),
        ))?;
        // 1 = valid, 0 = invalid signature, < 0 = library error.
        let r = ffi::EVP_DigestVerifyFinal(md_ctx.as_ptr(), signature.as_ptr(), signature.len());
        if r < 0 {
            return Err(ErrorStack::get());
        }
        if r == 0 {
            // OpenSSL 3.x records an error even for ordinary mismatches.
            ffi::ERR_clear_error();
        }
        Ok(r == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private, Public};

    fn generate_keypair() -> (PKey<Public>, PKey<Private>) {
        let group = EcGroup::from_curve_name(Nid::SM2).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec).unwrap();
        let priv_pem = pkey.private_key_to_pem_pkcs8().unwrap();
        let pub_pem = pkey.public_key_to_pem().unwrap();
        (
            PKey::public_key_from_pem(&pub_pem).unwrap(),
            PKey::private_key_from_pem(&priv_pem).unwrap(),
        )
    }

    fn der_signature(r_hex: &str, s_hex: &str) -> Vec<u8> {
        fn der_int(bytes: &[u8]) -> Vec<u8> {
            let mut v = bytes;
            while !v.is_empty() && v[0] == 0 {
                v = &v[1..];
            }
            if v.is_empty() {
                v = &[0];
            }
            let mut out = vec![0x02, v.len() as u8];
            if v[0] & 0x80 != 0 {
                out[1] += 1;
                out.push(0);
            }
            out.extend_from_slice(v);
            out
        }

        let r = BigNum::from_hex_str(r_hex).unwrap().to_vec();
        let s = BigNum::from_hex_str(s_hex).unwrap().to_vec();
        let mut body = der_int(&r);
        body.extend(der_int(&s));
        let mut out = vec![0x30, body.len() as u8];
        out.extend(body);
        out
    }

    #[test]
    fn round_trip_with_standard_user_id() {
        let (public, private) = generate_keypair();
        let data = b"sm2-round-trip";
        let sig = sign(&private, data).expect("sign");
        assert!(verify(&public, data, &sig).expect("verify"));
    }

    /// Signatures made under any non-standard user ID must not verify: this
    /// pins the ID instead of relying on the OpenSSL default (empty on >= 3.5,
    /// "1234567812345678" on <= 3.4).
    #[test]
    fn rejects_non_standard_user_id_signatures() {
        let (public, private) = generate_keypair();
        let data = b"sm2-user-id-pinning";
        let standard = sign(&private, data).expect("sign");
        assert!(verify(&public, data, &standard).expect("verify"));

        for wrong_id in [b"" as &[u8], b"rbs", b"1234567812345679"] {
            let sig = sign_with_id(&private, data, wrong_id)
                .unwrap_or_else(|e| panic!("sign with id {wrong_id:?}: {e}"));
            assert!(
                !verify(&public, data, &sig).expect("verify"),
                "signature with user ID {wrong_id:?} must not verify"
            );
        }
    }

    /// GB/T 32918.2-2012 (GM/T 0003.2) appendix A.2 signature example: message
    /// "message digest", default user ID "1234567812345678". Ground truth for
    /// standard-compliant verification, cross-checked against an independent
    /// pure-Python GM/T 0003.2 implementation and the system OpenSSL CLI.
    #[test]
    fn verifies_official_gbt32918_signature() {
        let group = EcGroup::from_curve_name(Nid::SM2).unwrap();
        let x = BigNum::from_hex_str(
            "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020",
        )
        .unwrap();
        let y = BigNum::from_hex_str(
            "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13",
        )
        .unwrap();
        let ec = EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();
        let public = PKey::from_ec_key(ec).unwrap();

        let sig = der_signature(
            "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3",
            "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA",
        );
        assert!(
            verify(&public, b"message digest", &sig).expect("verify"),
            "official GB/T 32918.2-2012 test vector must verify"
        );
    }
}

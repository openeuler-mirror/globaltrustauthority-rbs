/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Key handling tests — request-level validation for various key types.
//!
//! Note: actual key parsing (validate_and_derive_alg, jwk_to_pem) is in the
//! private `admin::key` module and is tested through AdminManager (requires DB).
//! These tests validate the request-level key pair validation.

use validator::Validate;

use super::common::*;

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Key_001 — 公钥处理-正常场景(各算法等价类)
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Key_001
/// RSA PEM public key request passes validation.
#[test]
fn test_user_key_001_rsa_pem_validation() {
    let req = create_req_with_pk("rsauser", &generate_rsa_pem_b64());
    assert!(Validate::validate(&req).is_ok());
    assert!(req.validate_key_pair().is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Key_001
/// EC P-256 PEM public key request passes validation.
#[test]
fn test_user_key_001_ec_p256_pem_validation() {
    let req = create_req_with_pk("ecp256user", &generate_ec_p256_pem_b64());
    assert!(Validate::validate(&req).is_ok());
    assert!(req.validate_key_pair().is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Key_001
/// Ed25519 PEM public key request passes validation.
#[test]
fn test_user_key_001_ed25519_pem_validation() {
    let req = create_req_with_pk("ed25519user", &generate_ed25519_pem_b64());
    assert!(Validate::validate(&req).is_ok());
    assert!(req.validate_key_pair().is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Key_001
/// RSA JWK request passes validation.
#[test]
fn test_user_key_001_rsa_jwk_validation() {
    let req = create_req_with_jwk("rsajwkuser", rsa_jwk());
    assert!(Validate::validate(&req).is_ok());
    assert!(req.validate_key_pair().is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Key_001
/// EC P-256 JWK request passes validation.
#[test]
fn test_user_key_001_ec_p256_jwk_validation() {
    let req = create_req_with_jwk("ecjwkuser", ec_p256_jwk());
    assert!(Validate::validate(&req).is_ok());
    assert!(req.validate_key_pair().is_ok());
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Key_002 — 公钥处理-异常场景(不支持类型等价类)
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Key_002
/// Unsupported EC curve PEM request passes request validation
/// (actual key parsing rejection happens in AdminManager at DB level).
#[test]
fn test_user_key_002_unsupported_ec_curve_request() {
    let req = create_req_with_pk("badcurveuser", &generate_unsupported_ec_pem_b64());
    assert!(Validate::validate(&req).is_ok());
    assert!(req.validate_key_pair().is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Key_002
/// Ed25519 JWK request passes request validation
/// (actual key type rejection happens in AdminManager at DB level).
#[test]
fn test_user_key_002_ed25519_jwk_request() {
    let req = create_req_with_jwk("edjwkuser", ed25519_jwk());
    assert!(Validate::validate(&req).is_ok());
    assert!(req.validate_key_pair().is_ok());
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Key_002
/// Oct JWK request passes request validation
/// (actual key type rejection happens in AdminManager at DB level).
#[test]
fn test_user_key_002_oct_jwk_request() {
    let req = create_req_with_jwk("octjwkuser", oct_jwk());
    assert!(Validate::validate(&req).is_ok());
    assert!(req.validate_key_pair().is_ok());
}

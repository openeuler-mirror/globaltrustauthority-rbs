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

//! Tests for auth/authn/common.rs — public helpers: decode_token_header, is_es512, validate_algorithm, SUPPORTED_ALGORITHMS.

use rbs_core::auth::authn::common::{
    decode_token_header, is_es512, validate_algorithm, SUPPORTED_ALGORITHMS,
};

#[test]
fn test_supported_algorithms_contains_all() {
    for alg in ["PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"] {
        assert!(
            SUPPORTED_ALGORITHMS.contains(&alg),
            "SUPPORTED_ALGORITHMS should contain {}",
            alg
        );
    }
}

#[test]
fn test_supported_algorithms_count() {
    assert_eq!(SUPPORTED_ALGORITHMS.len(), 7);
}

#[test]
fn test_is_es512_true_for_es512() {
    assert!(is_es512("ES512"));
}

#[test]
fn test_is_es512_false_for_others() {
    assert!(!is_es512("PS256"));
    assert!(!is_es512("PS384"));
    assert!(!is_es512("PS512"));
    assert!(!is_es512("RS256"));
    assert!(!is_es512("ES256"));
    assert!(!is_es512("ES384"));
    assert!(!is_es512("EdDSA"));
    assert!(!is_es512(""));
    assert!(!is_es512("ES512X"));
}

#[test]
fn test_validate_algorithm_all_supported() {
    for alg in SUPPORTED_ALGORITHMS.iter() {
        let result = validate_algorithm(alg);
        assert!(result.is_ok(), "validate_algorithm({}) should succeed", alg);
    }
}

#[test]
fn test_validate_algorithm_unsupported() {
    let result = validate_algorithm("NOTREAL");
    assert!(result.is_err());
}

#[test]
fn test_validate_algorithm_empty() {
    let result = validate_algorithm("");
    assert!(result.is_err());
}

#[test]
fn test_decode_token_header_valid_ps256() {
    // Base64URL: {"alg":"PS256","typ":"JWT"}
    let token = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
    let result = decode_token_header(token);
    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.alg, "PS256");
    assert_eq!(header.kid, None);
}

#[test]
fn test_decode_token_header_with_kid() {
    // Base64URL: {"alg":"ES512","kid":"my-key","typ":"JWT"}
    let token = "eyJhbGciOiJFUzUxMiIsImtpZCI6Im15LWtleSIsInR5cCI6IkpXVCJ9.payload.signature";
    let result = decode_token_header(token);
    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.alg, "ES512");
    assert_eq!(header.kid, Some("my-key".to_string()));
}


#[test]
fn test_decode_token_header_malformed_base64() {
    let token = "not!valid!base64.payload.signature";
    let result = decode_token_header(token);
    assert!(result.is_err());
}

#[test]
fn test_decode_token_header_wrong_part_count_one() {
    let token = "justone";
    let result = decode_token_header(token);
    assert!(result.is_err());
}

#[test]
fn test_decode_token_header_wrong_part_count_two() {
    let token = "only.two";
    let result = decode_token_header(token);
    assert!(result.is_err());
}

#[test]
fn test_decode_token_header_wrong_part_count_four() {
    let token = "a.b.c.d";
    let result = decode_token_header(token);
    assert!(result.is_err());
}

#[test]
fn test_decode_token_header_valid_rs384() {
    // Base64URL: {"alg":"RS384","typ":"JWT"}
    let token = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.payload.signature";
    let result = decode_token_header(token);
    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.alg, "RS384");
}
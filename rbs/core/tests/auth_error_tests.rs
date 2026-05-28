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

//! Unit tests for `AuthError` -- Display and clone.

use rbs_core::auth::error::AuthError;

// ===========================================================================
// Display
// ===========================================================================

#[test]
fn test_token_missing_display() {
    let err = AuthError::TokenMissing;
    assert_eq!(err.to_string(), "token is missing");
}

#[test]
fn test_token_invalid_display() {
    let err = AuthError::TokenInvalid { reason: "signature mismatch".to_string() };
    assert_eq!(err.to_string(), "token is invalid: signature mismatch");
}

#[test]
fn test_token_expired_display() {
    let err = AuthError::TokenExpired;
    assert_eq!(err.to_string(), "token has expired");
}

#[test]
fn test_token_not_yet_valid_display() {
    let err = AuthError::TokenNotYetValid;
    assert_eq!(err.to_string(), "token is not yet valid");
}

#[test]
fn test_token_unknown_display() {
    let err = AuthError::TokenUnknown;
    assert_eq!(err.to_string(), "token issuer is unknown");
}

#[test]
fn test_user_disabled_display() {
    let err = AuthError::UserDisabled;
    assert_eq!(err.to_string(), "user is disabled");
}

#[test]
fn test_provider_not_found_display() {
    let err = AuthError::ProviderNotFound { provider: "gta".to_string() };
    assert_eq!(err.to_string(), "provider not found: gta");
}

// ===========================================================================
// Clone
// ===========================================================================

#[test]
fn test_clone_token_invalid() {
    let err = AuthError::TokenInvalid { reason: "test".to_string() };
    let cloned = err.clone();
    assert_eq!(cloned.to_string(), err.to_string());
}

#[test]
fn test_clone_provider_not_found() {
    let err = AuthError::ProviderNotFound { provider: "gta".to_string() };
    let cloned = err.clone();
    assert_eq!(cloned.to_string(), err.to_string());
}
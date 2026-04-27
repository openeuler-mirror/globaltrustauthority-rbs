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

//! Authentication context types.

use serde_json::Value;

/// Token type enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    Bearer,
    Attest,
}

/// Bearer JWT context after successful verification
#[derive(Debug, Clone)]
pub struct BearerContext {
    /// Issuer
    pub iss: String,
    /// Subject (user identifier)
    pub sub: String,
    /// User role
    pub role: String,
    /// Original claims
    pub claims: Value,
    /// Token type
    pub token_type: TokenType,
}

/// AttestToken context after successful verification
#[derive(Debug, Clone)]
pub struct AttestContext {
    /// Original claims
    pub claims: Value,
    /// Token type
    pub token_type: TokenType,
}

/// Unified authentication context
#[derive(Debug, Clone)]
pub enum AuthContext {
    Bearer(BearerContext),
    Attest(AttestContext),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_type_equality() {
        assert_eq!(TokenType::Bearer, TokenType::Bearer);
        assert_eq!(TokenType::Attest, TokenType::Attest);
        assert_ne!(TokenType::Bearer, TokenType::Attest);
    }

    #[test]
    fn test_bearer_context_clone() {
        let ctx = BearerContext {
            iss: "https://auth.example.com".to_string(),
            sub: "user123".to_string(),
            role: "admin".to_string(),
            claims: serde_json::json!({"custom": "claim"}),
            token_type: TokenType::Bearer,
        };

        let cloned = ctx.clone();
        assert_eq!(ctx.iss, cloned.iss);
        assert_eq!(ctx.sub, cloned.sub);
        assert_eq!(ctx.role, cloned.role);
        assert_eq!(ctx.token_type, cloned.token_type);
    }

    #[test]
    fn test_attest_context_clone() {
        let claims = serde_json::json!({
            "tee_pubkey": "test_pubkey",
            "nonce": "test_nonce",
            "evidence": "test_evidence"
        });
        let ctx = AttestContext {
            claims: claims.clone(),
            token_type: TokenType::Attest,
        };

        let cloned = ctx.clone();
        assert_eq!(ctx.token_type, cloned.token_type);
        assert_eq!(ctx.claims, cloned.claims);
    }

    #[test]
    fn test_auth_context_bearer() {
        let bearer_ctx = BearerContext {
            iss: "https://auth.example.com".to_string(),
            sub: "user123".to_string(),
            role: "user".to_string(),
            claims: serde_json::Value::Null,
            token_type: TokenType::Bearer,
        };

        let auth_ctx = AuthContext::Bearer(bearer_ctx);
        match auth_ctx {
            AuthContext::Bearer(ctx) => {
                assert_eq!(ctx.sub, "user123");
                assert_eq!(ctx.token_type, TokenType::Bearer);
            }
            _ => panic!("Expected Bearer variant"),
        }
    }

    #[test]
    fn test_auth_context_attest() {
        let attest_ctx = AttestContext {
            claims: serde_json::json!({"test": "claims"}),
            token_type: TokenType::Attest,
        };

        let auth_ctx = AuthContext::Attest(attest_ctx);
        match auth_ctx {
            AuthContext::Attest(ctx) => {
                assert_eq!(ctx.token_type, TokenType::Attest);
            }
            _ => panic!("Expected Attest variant"),
        }
    }

    #[test]
    fn test_bearer_context_all_fields() {
        let ctx = BearerContext {
            iss: "https://auth.example.com".to_string(),
            sub: "user123".to_string(),
            role: "admin".to_string(),
            claims: serde_json::json!({"custom_field": "value"}),
            token_type: TokenType::Bearer,
        };

        assert_eq!(ctx.iss, "https://auth.example.com");
        assert_eq!(ctx.sub, "user123");
        assert_eq!(ctx.role, "admin");
        assert_eq!(ctx.token_type, TokenType::Bearer);
    }

    #[test]
    fn test_attest_context_raw_claims() {
        let claims = serde_json::json!({
            "tee_pubkey": "0x1234...",
            "nonce": "random-nonce-value",
            "tee_evidence": {
                "quote": "base64-quote-data"
            }
        });

        let ctx = AttestContext {
            claims: claims.clone(),
            token_type: TokenType::Attest,
        };

        assert_eq!(ctx.claims["tee_pubkey"], "0x1234...");
        assert_eq!(ctx.claims["nonce"], "random-nonce-value");
        assert!(ctx.claims["tee_evidence"].is_object());
    }
}

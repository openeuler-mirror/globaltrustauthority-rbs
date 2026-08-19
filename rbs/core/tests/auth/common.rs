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

//! Shared test helpers for auth integration tests.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use rbs_api_types::config::{
    AdminConfig, AdminKeyConfig, AttestationBackendConfig, AttestationBackendMode,
    AttestationBuiltinConfig, AttestationConfig, AttestationCredentials, AttestationRestConfig,
    AuthConfig, BearerTokenVerificationConfig, AttestTokenVerificationConfig, LoggingConfig,
    PolicyLimitsConfig, RbsConfig, Sensitive,
};
use rbs_core::auth::{BearerTokenVerifier, LockoutTracker, UserKeyProvider};
use rbs_core::AuthError;

// ---------------------------------------------------------------------------
// RSA key pair generation
// ---------------------------------------------------------------------------

pub(crate) fn generate_rsa_keypair() -> (String, String) {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let pub_pem = String::from_utf8(pkey.public_key_to_pem().unwrap()).unwrap();
    let priv_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (pub_pem, priv_pem)
}

// ---------------------------------------------------------------------------
// Stub UserKeyProvider
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct StubKeyProvider(pub String);

#[async_trait]
impl UserKeyProvider for StubKeyProvider {
    async fn get_public_key(&self, _sub: &str) -> Result<String, AuthError> {
        Ok(self.0.clone())
    }
}

/// Key provider that returns errors for subs in `nonexistent_subs`,
/// and a valid PEM for all other subs.
#[derive(Debug)]
pub(crate) struct SelectiveStubKeyProvider {
    pub pem: String,
    pub nonexistent_subs: Vec<String>,
}

#[async_trait]
impl UserKeyProvider for SelectiveStubKeyProvider {
    async fn get_public_key(&self, sub: &str) -> Result<String, AuthError> {
        if self.nonexistent_subs.contains(&sub.to_string()) {
            Err(AuthError::TokenInvalid { reason: "user not found".to_string() })
        } else {
            Ok(self.pem.clone())
        }
    }
}

// ---------------------------------------------------------------------------
// BearerTokenVerifier builder
// ---------------------------------------------------------------------------

pub(crate) fn make_bearer_verifier(
    pub_pem: &str,
    issuer: &str,
    audience: &str,
    tracker: Arc<LockoutTracker>,
) -> BearerTokenVerifier {
    let config = BearerTokenVerificationConfig {
        issuer: issuer.to_string(),
        audience: audience.to_string(),
    };
    let key_provider: Arc<dyn UserKeyProvider> = Arc::new(StubKeyProvider(pub_pem.to_string()));
    BearerTokenVerifier::new(config, key_provider, tracker)
}

// ---------------------------------------------------------------------------
// JWT signing helper
// ---------------------------------------------------------------------------

pub(crate) fn sign_ps256_jwt(priv_pem: &str, claims: Value) -> String {
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap();
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
    jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap()
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------------------
// AttestTokenVerifier builder (writes public key to a temp file)
// ---------------------------------------------------------------------------

pub(crate) fn make_attest_verifier(
    pub_pem: &str,
    issuer: &str,
    audience: Option<&str>,
) -> rbs_core::auth::AttestTokenVerifier {
    use std::io::Write;
    let mut temp_file = tempfile::NamedTempFile::new().unwrap();
    temp_file.write_all(pub_pem.as_bytes()).unwrap();
    temp_file.flush().unwrap();
    let path = temp_file.path().to_string_lossy().to_string();
    let config = AttestTokenVerificationConfig {
        public_key_path: Some(path),
        jwks_file: None,
        issuer: issuer.to_string(),
        audience: audience.map(|s| s.to_string()),
    };
    let verifier = rbs_core::auth::AttestTokenVerifier::new(config).unwrap();
    std::mem::forget(temp_file);
    verifier
}

// ---------------------------------------------------------------------------
// Valid RbsConfig builder (for config validation tests)
// ---------------------------------------------------------------------------

pub(crate) fn make_valid_rbs_config() -> RbsConfig {
    let mut backends = HashMap::new();
    backends.insert(
        "gta".to_string(),
        AttestationBackendConfig {
            mode: AttestationBackendMode::Rest,
            rest: AttestationRestConfig {
                base_url: "https://gta.example.com".to_string(),
                timeout_secs: 30,
                retries: 3,
                tls_verify: true,
                ca_file: String::new(),
                client_cert_path: String::new(),
                client_key_path: String::new(),
                credentials: AttestationCredentials {
                    user_id: "valid-user-1".to_string(),
                    api_key_auth: false,
                    main_api_key: Sensitive::new(String::new()),
                    sub_api_key: Sensitive::new(String::new()),
                },
            },
            builtin: AttestationBuiltinConfig::default(),
        },
    );

    RbsConfig {
        rest: None,
        logging: LoggingConfig::default(),
        storage: None,
        attestation: AttestationConfig {
            default_as_provider: "gta".to_string(),
            backends,
        },
        auth: AuthConfig {
            attest_token: AttestTokenVerificationConfig {
                public_key_path: Some("/tmp/dummy_attest.pem".to_string()),
                jwks_file: None,
                issuer: "Global Trust Authority".to_string(),
                audience: Some("rbs".to_string()),
            },
            bearer_token: BearerTokenVerificationConfig {
                issuer: "Global Trust Authority".to_string(),
                audience: "rbs".to_string(),
            },
        },
        admin: AdminConfig {
            max_users: 10,
            admin_key: AdminKeyConfig {
                public_key_path: Some("/tmp/dummy_admin.pem".to_string()),
                jwks_file: None,
            },
        },
        policy: PolicyLimitsConfig::default(),
        resource: None,
    }
}

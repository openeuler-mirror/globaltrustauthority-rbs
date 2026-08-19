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

//! Shared test helpers for admin integration tests.

use std::sync::{Arc, Once};

#[allow(unused_imports)]
use base64::Engine as _;
use serde_json::{json, Value};

use rbs_api_types::config::{AdminConfig, AdminKeyConfig, Database};
use rbs_api_types::{AuthType, Role, UserCreateRequest};
use rbs_core::auth::authz::AuthzFacade;
use rbs_core::policy_engine::RealPolicyEngine;
use rbs_core::AdminManager;

// ---------------------------------------------------------------------------
// DB pool initialization (once per test binary)
// ---------------------------------------------------------------------------

static INIT: Once = Once::new();

pub(crate) async fn ensure_db() {
    INIT.call_once(|| {
        std::thread::spawn(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let config = Database {
                    db_type: "sqlite".to_string(),
                    url: "sqlite::memory:".to_string(),
                    max_connections: 1,
                    timeout: 30,
                    sql_file_path: String::new(),
                };
                let db = rbs_core::rdb::init_pool(&config).await.expect("init pool");
                use sea_orm::ConnectionTrait;
                let backend = db.get_database_backend();
                for stmt in [
                    "CREATE TABLE IF NOT EXISTS t_user_info (user_id TEXT NOT NULL, username TEXT PRIMARY KEY NOT NULL, role TEXT NOT NULL DEFAULT 'user', auth_type TEXT NOT NULL DEFAULT 'jwt', auth_value TEXT NOT NULL, auth_alg TEXT NOT NULL, status INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
                    "CREATE TABLE IF NOT EXISTS t_res_policy (policy_id TEXT PRIMARY KEY, username TEXT NOT NULL, policy_name TEXT NOT NULL, policy_version INTEGER NOT NULL DEFAULT 1, policy_content TEXT NOT NULL, content_type TEXT NOT NULL DEFAULT 'base64', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
                    "CREATE TABLE IF NOT EXISTS t_res_info (username TEXT NOT NULL, provider_name TEXT NOT NULL, repo_name TEXT NOT NULL, res_type TEXT NOT NULL, res_name TEXT NOT NULL, res_info TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, content_type TEXT, export_mode TEXT NOT NULL DEFAULT 'jwe', policy_id TEXT NOT NULL, PRIMARY KEY (username, provider_name, repo_name, res_type, res_name))",
                ] {
                    db.execute(sea_orm::Statement::from_string(backend, stmt)).await.expect("create table");
                }
            });
        }).join().expect("db init thread");
    });
}

// ---------------------------------------------------------------------------
// AdminManager builder
// ---------------------------------------------------------------------------

pub(crate) fn make_manager(max_users: u32) -> AdminManager {
    use std::sync::OnceLock;
    static ADMIN_PEM: OnceLock<String> = OnceLock::new();
    let path = ADMIN_PEM.get_or_init(|| {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        let pem = pkey.public_key_to_pem().unwrap();
        let p = std::env::temp_dir().join("rbs_test_admin_key.pem");
        std::fs::write(&p, &pem).unwrap();
        p.to_string_lossy().to_string()
    });
    let config = AdminConfig {
        max_users,
        admin_key: AdminKeyConfig {
            public_key_path: Some(path.clone()),
            jwks_file: None,
        },
    };
    let engine = Arc::new(RealPolicyEngine);
    let authz = AuthzFacade::new(engine);
    AdminManager::new(config, authz)
}

// ---------------------------------------------------------------------------
// Key generation helpers
// ---------------------------------------------------------------------------

pub(crate) fn generate_rsa_pem_b64() -> String {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let pem = pkey.public_key_to_pem().unwrap();
    base64::engine::general_purpose::STANDARD.encode(&pem)
}

pub(crate) fn generate_ec_p256_pem_b64() -> String {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let key = openssl::ec::EcKey::generate(&group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(key).unwrap();
    let pem = pkey.public_key_to_pem().unwrap();
    base64::engine::general_purpose::STANDARD.encode(&pem)
}

pub(crate) fn generate_ed25519_pem_b64() -> String {
    let key = openssl::pkey::PKey::generate_ed25519().unwrap();
    let pem = key.public_key_to_pem().unwrap();
    base64::engine::general_purpose::STANDARD.encode(&pem)
}

pub(crate) fn generate_unsupported_ec_pem_b64() -> String {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1).unwrap();
    let key = openssl::ec::EcKey::generate(&group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(key).unwrap();
    let pem = pkey.public_key_to_pem().unwrap();
    base64::engine::general_purpose::STANDARD.encode(&pem)
}

pub(crate) fn rsa_jwk() -> Value {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
    json!({"kty": "RSA", "n": n, "e": e})
}

pub(crate) fn ec_p256_jwk() -> Value {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let key = openssl::ec::EcKey::generate(&group).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let mut x = openssl::bn::BigNum::new().unwrap();
    let mut y = openssl::bn::BigNum::new().unwrap();
    key.public_key().affine_coordinates(&group, &mut x, &mut y, &mut ctx).unwrap();
    json!({
        "kty": "EC", "crv": "P-256",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x.to_vec()),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y.to_vec())
    })
}

pub(crate) fn ed25519_jwk() -> Value {
    let key = openssl::pkey::PKey::generate_ed25519().unwrap();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.raw_public_key().unwrap());
    json!({"kty": "OKP", "crv": "Ed25519", "x": x})
}

pub(crate) fn oct_jwk() -> Value {
    json!({"kty": "oct", "k": "A228ztpSnwyxAQ"})
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

pub(crate) fn create_req_with_pk(username: &str, pk_b64: &str) -> UserCreateRequest {
    UserCreateRequest {
        username: username.to_string(),
        role: None,
        enabled: None,
        auth_type: AuthType::Jwt,
        public_key: Some(pk_b64.to_string()),
        jwk: None,
    }
}

pub(crate) fn create_req_with_jwk(username: &str, jwk: Value) -> UserCreateRequest {
    UserCreateRequest {
        username: username.to_string(),
        role: None,
        enabled: None,
        auth_type: AuthType::Jwt,
        public_key: None,
        jwk: Some(jwk),
    }
}

pub(crate) fn create_req_role_admin(username: &str, pk_b64: &str) -> UserCreateRequest {
    UserCreateRequest {
        username: username.to_string(),
        role: Some(Role::Admin),
        enabled: None,
        auth_type: AuthType::Jwt,
        public_key: Some(pk_b64.to_string()),
        jwk: None,
    }
}
#[allow(unused_imports)]
use base64::Engine as _b64;

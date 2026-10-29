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

//! Bootstrap integration tests for `AdminManager`.
//!
//! This file is a dedicated test binary: `bootstrap_admin` behaves differently
//! on an empty store, so it must not race with other tests that insert users
//! into the same process-global in-memory database.

use std::sync::Arc;

use rbs_api_types::config::{AdminConfig, AdminKeyConfig, Database};
use rbs_api_types::Role;
use rbs_core::auth::authz::AuthzFacade;
use rbs_core::auth::{AuthContext, BearerContext, TokenType};
use rbs_core::policy_engine::RealPolicyEngine;
use rbs_core::AdminManager;

fn admin_ctx() -> AuthContext {
    AuthContext::Bearer(BearerContext {
        iss: "test-issuer".to_string(),
        sub: "Administrator".to_string(),
        role: "admin".to_string(),
        claims: serde_json::Value::Null,
        token_type: TokenType::Bearer,
    })
}

#[tokio::test]
async fn bootstrap_admin_creates_administrator_only_once() {
    // The pool is initialized on a fresh OS thread so the global `OnceCell`
    // can be set even though this test already runs inside a tokio runtime.
    let db_path = std::env::temp_dir().join("rbs_core_admin_bootstrap.sqlite");
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", db_path.to_string_lossy(), suffix));
    }
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let config = Database {
                db_type: "sqlite".to_string(),
                url: db_url,
                max_connections: 1,
                timeout: 30,
                sql_file_path: String::new(),
            };
            let db = rbs_core::rdb::init_pool(&config).await.expect("init pool");
            rbs_core::rdb::migrate_core_tables(&db).await.expect("migrate core tables");
        });
    })
    .join()
    .expect("db init thread");

    let pem_dir = tempfile::tempdir().expect("tempdir");
    let pem_path = pem_dir.path().join("admin_pub.pem");
    let rsa = openssl::rsa::Rsa::generate(2048).expect("generate rsa key");
    let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("pkey from rsa");
    std::fs::write(&pem_path, pkey.public_key_to_pem().expect("public pem")).expect("write pem");

    let manager = AdminManager::new(
        AdminConfig {
            max_users: 5,
            admin_key: AdminKeyConfig {
                public_key_path: Some(pem_path.to_string_lossy().to_string()),
                jwks_file: None,
            },
        },
        AuthzFacade::new(Arc::new(RealPolicyEngine)),
    );

    manager.bootstrap_admin().await.expect("first bootstrap");
    let admin = manager
        .get_user("Administrator", &admin_ctx())
        .await
        .expect("get bootstrapped admin")
        .expect("administrator must exist");
    assert_eq!(admin.username, "Administrator");
    assert_eq!(admin.role, Role::Admin);
    assert!(admin.enabled);

    // A second bootstrap observes the existing user and is a no-op.
    manager.bootstrap_admin().await.expect("second bootstrap");
    let users = manager
        .list_users(
            &rbs_api_types::UserListQuery { limit: Some(100), offset: Some(0), role: None, enabled: None },
            &admin_ctx(),
        )
        .await
        .expect("list users");
    assert_eq!(users.users.len(), 1);
    assert_eq!(users.users[0].username, "Administrator");
}

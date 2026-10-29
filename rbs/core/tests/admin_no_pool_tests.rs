/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
 * PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! `AdminManager` behaviour with an **uninitialized** global connection pool.
//!
//! This is a dedicated test binary: `rbs_core::rdb::init_pool` must never be
//! called here, because the pool is a process-global `OnceCell` and every test
//! in this binary depends on it staying empty. `AdminManager` construction does
//! not touch the database, so the assertions below can build a manager freely.

use std::sync::Arc;

use rbs_api_types::config::{AdminConfig, AdminKeyConfig};
use rbs_core::auth::authz::AuthzFacade;
use rbs_core::policy_engine::RealPolicyEngine;
use rbs_core::{AdminManager, AuthError, RbsError, UserAuthProvider};

fn manager() -> AdminManager {
    // The configured key path is irrelevant: the pool lookup fails before the
    // key material is ever read.
    AdminManager::new(
        AdminConfig {
            max_users: 5,
            admin_key: AdminKeyConfig {
                public_key_path: Some("/nonexistent/admin_pub.pem".to_string()),
                jwks_file: None,
            },
        },
        AuthzFacade::new(Arc::new(RealPolicyEngine)),
    )
}

#[tokio::test]
async fn bootstrap_admin_reports_an_uninitialized_pool() {
    let err = manager().bootstrap_admin().await.expect_err("bootstrap must fail without a pool");
    match err {
        RbsError::InternalUnexpected { context } => {
            assert!(context.contains("not initialized"), "unexpected context: {context}");
        },
        other => panic!("expected InternalUnexpected, got: {other:?}"),
    }
}

#[tokio::test]
async fn get_user_auth_reports_an_uninitialized_pool() {
    // The authentication lookup must fail closed with the generic
    // `TokenInvalid` reason, never with a datasource detail that could leak
    // into an HTTP response.
    let err = manager().get_user_auth("any-user").await.expect_err("lookup must fail without a pool");
    match err {
        AuthError::TokenInvalid { reason } => assert_eq!(reason, "invalid token"),
        other => panic!("expected TokenInvalid, got: {other:?}"),
    }
}

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

//! User lifecycle integration tests for `AdminManager`.
//!
//! All tests share the process-global in-memory SQLite pool initialized by
//! [`common::ensure_db`], so usernames are unique per test and list assertions
//! look for the users they created instead of assuming an empty store.

use rbs_api_types::{Role, UserListQuery, UserUpdateRequest};
use rbs_core::RbsError;

use super::common::{
    bearer_ctx, create_req_with_pk, ensure_db, generate_ec_p256_pem_b64, generate_rsa_pem_b64, make_manager,
    seed_disabled_user, seed_enabled_user,
};

const ADMIN: &str = "Administrator";

async fn ensure_admin() {
    ensure_db().await;
    seed_enabled_user(ADMIN, "admin").await;
}

fn update_req() -> UserUpdateRequest {
    UserUpdateRequest { role: None, enabled: None, auth_type: None, public_key: None, jwk: None }
}

#[tokio::test]
async fn create_user_persists_and_get_user_returns_record() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    let req = create_req_with_pk("lifecycle_create_alice", &generate_rsa_pem_b64());
    let created = manager.create_user(&req, &admin).await.expect("create user");
    assert_eq!(created.username, "lifecycle_create_alice");
    assert_eq!(created.role, Role::User);
    assert!(created.enabled);
    assert!(!created.id.is_empty());

    let fetched = manager.get_user("lifecycle_create_alice", &admin).await.expect("get user");
    let fetched = fetched.expect("user must exist");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.username, created.username);

    // A non-admin may read its own record.
    let self_ctx = bearer_ctx("lifecycle_create_alice", "user");
    let own = manager.get_user("lifecycle_create_alice", &self_ctx).await.expect("self get");
    assert!(own.is_some());

    // ...but not another user's record.
    let denied = manager.get_user(ADMIN, &self_ctx).await.expect_err("cross-user get must fail");
    assert!(matches!(denied, RbsError::AuthzInsufficientPermissions), "got: {denied:?}");

    // A missing user is reported as `None`, not an error.
    let missing = manager.get_user("lifecycle_create_missing", &admin).await.expect("get missing");
    assert!(missing.is_none());
}

#[tokio::test]
async fn create_user_rejects_duplicates_invalid_key_material_and_admin_role() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    let req = create_req_with_pk("lifecycle_duplicate_bob", &generate_rsa_pem_b64());
    manager.create_user(&req, &admin).await.expect("first create");

    let duplicate = manager.create_user(&req, &admin).await.expect_err("duplicate must fail");
    assert!(matches!(duplicate, RbsError::ResourceConflict), "got: {duplicate:?}");

    // Missing key material is rejected before touching the database.
    let mut no_key = create_req_with_pk("lifecycle_no_key", "");
    no_key.public_key = None;
    let err = manager.create_user(&no_key, &admin).await.expect_err("missing key must fail");
    assert!(matches!(err, RbsError::InvalidParameter(_)), "got: {err:?}");

    // Invalid base64 key material is rejected.
    let mut bad_key = create_req_with_pk("lifecycle_bad_key", "not-base64!!");
    bad_key.public_key = Some("not-base64!!".to_string());
    let err = manager.create_user(&bad_key, &admin).await.expect_err("bad key must fail");
    assert!(matches!(err, RbsError::InvalidParameter(_)), "got: {err:?}");

    // Invalid usernames fail request validation.
    let mut bad_name = create_req_with_pk("bad name!", &generate_rsa_pem_b64());
    bad_name.username = "bad name!".to_string();
    let err = manager.create_user(&bad_name, &admin).await.expect_err("bad username must fail");
    assert!(matches!(err, RbsError::InvalidParameter(_)), "got: {err:?}");

    // The admin role cannot be assigned through the API.
    let mut admin_role = create_req_with_pk("lifecycle_admin_role", &generate_rsa_pem_b64());
    admin_role.role = Some(Role::Admin);
    let err = manager.create_user(&admin_role, &admin).await.expect_err("admin role must fail");
    assert!(matches!(err, RbsError::InvalidParameter(_)), "got: {err:?}");

    // Disabled users are persisted in the disabled state.
    let mut disabled = create_req_with_pk("lifecycle_disabled_carol", &generate_ec_p256_pem_b64());
    disabled.enabled = Some(false);
    let created = manager.create_user(&disabled, &admin).await.expect("create disabled user");
    assert!(!created.enabled);
}

#[tokio::test]
async fn create_user_enforces_max_users_quota() {
    ensure_admin().await;
    let normal = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");
    normal
        .create_user(&create_req_with_pk("lifecycle_quota_dave", &generate_rsa_pem_b64()), &admin)
        .await
        .expect("seed regular user");

    // max_users counts regular users only; the store already holds at least one,
    // so a quota of 0 rejects every create with the dedicated quota error.
    let limited = make_manager(0);
    let err = limited
        .create_user(&create_req_with_pk("lifecycle_quota_erin", &generate_rsa_pem_b64()), &admin)
        .await
        .expect_err("quota must fail");
    assert!(matches!(err, RbsError::ResourceQuotaExceeded), "got: {err:?}");
}

#[tokio::test]
async fn list_users_supports_pagination_and_filters() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    manager
        .create_user(&create_req_with_pk("lifecycle_list_frank", &generate_rsa_pem_b64()), &admin)
        .await
        .expect("create frank");
    let mut grace = create_req_with_pk("lifecycle_list_grace", &generate_rsa_pem_b64());
    grace.enabled = Some(false);
    manager.create_user(&grace, &admin).await.expect("create grace");

    let all = UserListQuery { limit: Some(100), offset: Some(0), role: None, enabled: None };
    let page = manager.list_users(&all, &admin).await.expect("list users");
    assert!(page.users.iter().any(|u| u.username == "lifecycle_list_frank"));
    assert!(page.users.iter().any(|u| u.username == "lifecycle_list_grace"));
    assert!(page.total_count >= page.users.len() as i64);

    // Defaults are applied when limit/offset are omitted.
    let defaults = UserListQuery { limit: None, offset: None, role: None, enabled: None };
    let page = manager.list_users(&defaults, &admin).await.expect("list with defaults");
    assert_eq!(page.limit, 10);
    assert_eq!(page.offset, 0);
    assert!(page.users.len() <= 10);

    // Role filter only returns users (the seeded admin is excluded).
    let only_users = UserListQuery { limit: Some(100), offset: Some(0), role: Some(Role::User), enabled: None };
    let page = manager.list_users(&only_users, &admin).await.expect("list role filter");
    assert!(page.users.iter().all(|u| u.role == Role::User));

    // Enabled/disabled filter.
    let disabled = UserListQuery { limit: Some(100), offset: Some(0), role: None, enabled: Some(false) };
    let page = manager.list_users(&disabled, &admin).await.expect("list disabled");
    assert!(page.users.iter().any(|u| u.username == "lifecycle_list_grace"));
    assert!(page.users.iter().all(|u| !u.enabled));

    let page = manager
        .list_users(&UserListQuery { limit: Some(1), offset: Some(0), role: None, enabled: None }, &admin)
        .await
        .expect("list page");
    assert_eq!(page.users.len(), 1);
    assert_eq!(page.limit, 1);

    // Disabled callers are rejected before the query runs.
    seed_disabled_user("lifecycle_list_disabled", "user").await;
    let err = manager
        .list_users(&all, &bearer_ctx("lifecycle_list_disabled", "admin"))
        .await
        .expect_err("disabled caller must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");

    // Non-admin callers are rejected.
    let err =
        manager.list_users(&all, &bearer_ctx("lifecycle_list_frank", "user")).await.expect_err("non-admin must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");
}

#[tokio::test]
async fn update_user_rotates_key_and_enforces_field_policies() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    manager
        .create_user(&create_req_with_pk("lifecycle_update_henry", &generate_rsa_pem_b64()), &admin)
        .await
        .expect("create henry");

    let mut rotate = update_req();
    rotate.public_key = Some(generate_ec_p256_pem_b64());
    let updated = manager.update_user("lifecycle_update_henry", &rotate, &admin).await.expect("rotate key");
    assert_eq!(updated.username, "lifecycle_update_henry");

    // A non-admin may rotate its own key...
    let mut self_rotate = update_req();
    self_rotate.public_key = Some(generate_rsa_pem_b64());
    manager
        .update_user("lifecycle_update_henry", &self_rotate, &bearer_ctx("lifecycle_update_henry", "user"))
        .await
        .expect("self key rotation");

    // ...but may not change its role or disable itself.
    let mut self_role = update_req();
    self_role.role = Some(Role::Admin);
    let err = manager
        .update_user("lifecycle_update_henry", &self_role, &bearer_ctx("lifecycle_update_henry", "user"))
        .await
        .expect_err("self role change must fail");
    assert!(matches!(err, RbsError::SelfUpdateFieldRestricted { field: "role" }), "got: {err:?}");

    let mut self_disable = update_req();
    self_disable.enabled = Some(false);
    let err = manager
        .update_user("lifecycle_update_henry", &self_disable, &bearer_ctx("lifecycle_update_henry", "user"))
        .await
        .expect_err("self disable must fail");
    assert!(matches!(err, RbsError::SelfUpdateFieldRestricted { field: "enabled" }), "got: {err:?}");

    // A non-admin cannot update another user at all.
    let err = manager
        .update_user("lifecycle_update_henry", &self_rotate, &bearer_ctx(ADMIN, "user"))
        .await
        .expect_err("cross-user update must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");

    // Empty updates are rejected by cross-field validation.
    let err = manager.update_user("lifecycle_update_henry", &update_req(), &admin).await.expect_err("empty update");
    assert!(matches!(err, RbsError::InvalidParameter(_)), "got: {err:?}");

    // Missing targets surface as not found.
    let err = manager
        .update_user("lifecycle_update_missing", &self_rotate, &admin)
        .await
        .expect_err("missing update must fail");
    assert!(matches!(err, RbsError::ResourceNotFound), "got: {err:?}");

    // The built-in administrator may keep the admin role (no-op)...
    let mut keep_admin = update_req();
    keep_admin.role = Some(Role::Admin);
    manager.update_user(ADMIN, &keep_admin, &admin).await.expect("admin no-op role");

    // ...but cannot be demoted, disabled, or promoted via API.
    let mut demote = update_req();
    demote.role = Some(Role::User);
    let err = manager.update_user(ADMIN, &demote, &admin).await.expect_err("demote admin must fail");
    assert!(matches!(err, RbsError::BuiltInAdminProtected { field: "role" }), "got: {err:?}");

    let mut disable_admin = update_req();
    disable_admin.enabled = Some(false);
    let err = manager.update_user(ADMIN, &disable_admin, &admin).await.expect_err("disable admin must fail");
    assert!(matches!(err, RbsError::BuiltInAdminProtected { field: "enabled" }), "got: {err:?}");

    manager
        .create_user(&create_req_with_pk("lifecycle_update_iris", &generate_rsa_pem_b64()), &admin)
        .await
        .expect("create iris");
    let mut promote = update_req();
    promote.role = Some(Role::Admin);
    let err = manager.update_user("lifecycle_update_iris", &promote, &admin).await.expect_err("promote must fail");
    assert!(matches!(err, RbsError::AdminRoleNotAssignable), "got: {err:?}");

    // Admin can disable another user.
    let mut disable = update_req();
    disable.enabled = Some(false);
    let updated = manager.update_user("lifecycle_update_henry", &disable, &admin).await.expect("disable user");
    assert!(!updated.enabled);

    // A disabled target cannot authenticate, so updates are rejected.
    seed_disabled_user("lifecycle_update_disabled", "user").await;
    let err = manager
        .update_user("lifecycle_update_disabled", &self_rotate, &bearer_ctx("lifecycle_update_disabled", "user"))
        .await
        .expect_err("disabled caller must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");
}

#[tokio::test]
async fn delete_user_removes_row_and_guards_dependents() {
    ensure_admin().await;
    let manager = make_manager(20);
    let admin = bearer_ctx(ADMIN, "admin");

    manager
        .create_user(&create_req_with_pk("lifecycle_delete_jack", &generate_rsa_pem_b64()), &admin)
        .await
        .expect("create jack");

    // Admins cannot delete themselves.
    let err = manager.delete_user(ADMIN, &admin).await.expect_err("self delete must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");

    // Missing users are reported as not found.
    let err = manager.delete_user("lifecycle_delete_missing", &admin).await.expect_err("missing delete");
    assert!(matches!(err, RbsError::ResourceNotFound), "got: {err:?}");

    manager.delete_user("lifecycle_delete_jack", &admin).await.expect("delete jack");
    assert!(manager.get_user("lifecycle_delete_jack", &admin).await.expect("get after delete").is_none());

    // Non-admin callers are rejected.
    let err = manager
        .delete_user("lifecycle_delete_jack", &bearer_ctx("lifecycle_delete_jack", "user"))
        .await
        .expect_err("non-admin delete must fail");
    assert!(matches!(err, RbsError::AuthzInsufficientPermissions), "got: {err:?}");

    // A user owning a policy cannot be deleted.
    manager
        .create_user(&create_req_with_pk("lifecycle_delete_owner", &generate_rsa_pem_b64()), &admin)
        .await
        .expect("create owner");
    insert_policy_owned_by("lifecycle_delete_owner").await;
    let err = manager.delete_user("lifecycle_delete_owner", &admin).await.expect_err("dependents must block");
    match err {
        RbsError::UserHasDependents { policies, resources } => {
            assert_eq!(policies, 1);
            assert_eq!(resources, 0);
        },
        other => panic!("expected UserHasDependents, got: {other:?}"),
    }
}

async fn insert_policy_owned_by(username: &str) {
    use sea_orm::ConnectionTrait;
    let db = rbs_core::rdb::get_connection_from_pool().expect("db pool");
    let backend = db.get_database_backend();
    let sql = format!(
        "INSERT INTO t_res_policy (policy_id, username, policy_name, policy_version, policy_content, content_type, created_at, updated_at) \
         VALUES ('lifecycle-policy-{username}', '{username}', 'p', 1, 'c', 'base64', 0, 0)"
    );
    db.execute(sea_orm::Statement::from_string(backend, sql)).await.expect("insert policy");
}

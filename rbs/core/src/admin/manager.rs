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

//! `AdminManager` — user lifecycle operations: list, create, get, update, delete,
//! plus bootstrap of the pre-configured administrator on first start.

use std::fs;

use chrono::Timelike;
use rbs_api_types::error::RbsError;
use rbs_api_types::{
    AdminConfig, Role, UserCreateRequest, UserListQuery, UserListResponse, UserResponse, UserUpdateRequest,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Select, Set, TransactionTrait};
use serde_json::Value;

use crate::auth::{Action, AuthContext, AuthzError, AuthzFacade, RequiredRole};
use crate::infra::rdb::get_connection_from_pool;

use super::entity::{
    ActiveModel as UserActiveModel, Column as UserColumn, DbAuthType, DbRole, Entity as UserEntity, Model as UserModel,
    UserStatus,
};
use super::key::{jwk_to_pem, validate_and_derive_alg};

const ADMIN_USERNAME: &str = "Administrator";
const ROLE_ADMIN: &str = "admin";

type Result<T> = std::result::Result<T, RbsError>;

/// Admin / user management manager.
pub struct AdminManager {
    config: AdminConfig,
    authz: AuthzFacade,
}

impl std::fmt::Debug for AdminManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminManager").finish()
    }
}

impl AdminManager {
    /// Create a new AdminManager from config and an authorization facade.
    #[must_use]
    pub fn new(config: AdminConfig, authz: AuthzFacade) -> Self {
        Self { config, authz }
    }

    /// Bootstrap: if no users exist, create the Administrator from config.
    pub async fn bootstrap_admin(&self) -> Result<()> {
        let db = get_connection_from_pool().map_err(|e| {
            log::error!("Failed to get DB connection during admin bootstrap: {}", e);
            internal_err(e)
        })?;
        let count = UserEntity::find().count(&*db).await.map_err(|e| {
            log::error!("Failed to count users during admin bootstrap: {}", e);
            internal_err(e)
        })?;

        if count > 0 {
            log::debug!("Admin bootstrap skipped: {} user(s) already exist", count);
            return Ok(());
        }

        log::info!("Admin bootstrap: no users found, creating '{}' from config", ADMIN_USERNAME);

        let (auth_value, auth_alg) = self.read_admin_key()?;
        let user_id = generate_uuid();
        let now = now_without_nanos();

        let model = UserActiveModel {
            user_id: Set(user_id.clone()),
            username: Set(ADMIN_USERNAME.to_string()),
            role: Set(DbRole::Admin),
            auth_type: Set(DbAuthType::Jwt),
            auth_value: Set(auth_value),
            auth_alg: Set(auth_alg),
            status: Set(UserStatus::Enabled),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        model.insert(&*db).await.map_err(|e| {
            log::error!("Failed to insert admin user during bootstrap: {}", e);
            RbsError::InternalUnexpected { context: format!("Failed to create admin user: {}", e) }
        })?;

        log::info!("Admin user '{}' (id={}) bootstrapped successfully", ADMIN_USERNAME, user_id);
        Ok(())
    }

    /// List users (admin only).
    pub async fn list_users(&self, params: &UserListQuery, auth_ctx: &AuthContext) -> Result<UserListResponse> {
        log::info!("list_users called: limit={:?}, offset={:?}, role={:?}, enabled={:?}",
            params.limit, params.offset, params.role, params.enabled);

        let bearer = match self.require_enabled_admin(auth_ctx).await {
            Ok(b) => {
                log::info!("require_enabled_admin succeeded: sub={}, role={}", b.sub, b.role);
                b
            }
            Err(e) => {
                log::error!("require_enabled_admin failed: {:?}", e);
                return Err(e);
            }
        };

        let limit = params.limit.unwrap_or(10);
        let offset = params.offset.unwrap_or(0);

        log::info!("Listing users (limit={}, offset={}) by '{}'", limit, offset, bearer.sub);

        let db = get_connection_from_pool().map_err(|e| {
            log::error!("Failed to get DB connection for list_users: {}", e);
            internal_err(e)
        })?;

        let total_count = Self::build_filtered_query(params)
            .count(&*db)
            .await
            .map_err(|e| {
                log::error!("Failed to count users: {}", e);
                internal_err(e)
            })? as i64;

        let models = Self::build_filtered_query(params)
            .order_by_asc(UserColumn::Username)
            .limit(Some(limit as u64))
            .offset(Some(offset as u64))
            .all(&*db)
            .await
            .map_err(|e| {
                log::error!("Failed to list users: {}", e);
                internal_err(e)
            })?;

        let users = models.into_iter().map(|m| model_to_response(&m)).collect();

        log::info!("list_users completed: count={}, user='{}'", total_count, bearer.sub);
        Ok(UserListResponse { users, total_count, limit, offset })
    }

    /// Create a user (admin only).
    pub async fn create_user(&self, req: &UserCreateRequest, auth_ctx: &AuthContext) -> Result<UserResponse> {
        let bearer = self.require_enabled_admin(auth_ctx).await?;

        validator::Validate::validate(req).map_err(|e| RbsError::InvalidParameter(e.to_string()))?;
        req.validate_key_pair()?;
        let (auth_value, auth_alg) = AdminManager::extract_auth_material(req)?;
        let db = get_connection_from_pool().map_err(|e| {
            log::error!("Failed to get DB connection for create_user: {}", e);
            internal_err(e)
        })?;

        let inserted = Self::insert_user_in_txn(
            &db, req, &auth_value, &auth_alg, self.config.max_users,
        ).await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("duplicate") {
                log::error!("User creation failed: duplicate username '{}'", req.username);
                return RbsError::ResourceConflict;
            }
            if msg.contains("max_users") {
                log::error!(
                    "User creation by '{}' rejected: max_users limit ({}) reached",
                    bearer.sub, self.config.max_users
                );
                return RbsError::ResourceQuotaExceeded;
            }
            log::error!("Failed to insert user '{}': {}", req.username, e);
            internal_err(e)
        })?;

        log::info!("User '{}' (id={}, role={:?}) created by '{}'",
            req.username,
            inserted.user_id,
            inserted.role,
            bearer.sub,
        );
        Ok(model_to_response(&inserted))
    }

    /// Get a user (admin or self).
    pub async fn get_user(&self, username: &str, auth_ctx: &AuthContext) -> Result<Option<UserResponse>> {
        log::info!("get_user requested: username={}, user={}", username, auth_ctx.sub());
        let bearer = self.require_enabled_bearer(auth_ctx).await?;

        if bearer.role != ROLE_ADMIN && bearer.sub != username {
            log::error!("get_user denied: user '{}' rejected for '{}': not admin and not self", username, bearer.sub);
            return Err(RbsError::AuthzInsufficientPermissions);
        }

        let db = get_connection_from_pool().map_err(|e| {
            log::error!("Failed to get DB connection for get_user: {}", e);
            internal_err(e)
        })?;
        let model = UserEntity::find_by_id(username)
            .one(&*db)
            .await
            .map_err(|e| {
                log::error!("Failed to query user '{}': {}", username, e);
                internal_err(e)
            })?;

        if let Some(ref _m) = model {
            log::info!("get_user completed: username='{}', found=true", username);
        } else {
            log::info!("get_user completed: username='{}', found=false", username);
        }
        Ok(model.as_ref().map(|m| model_to_response(m)))
    }

    /// Update a user (admin or self with field whitelist).
    pub async fn update_user(
        &self,
        username: &str,
        req: &UserUpdateRequest,
        auth_ctx: &AuthContext,
    ) -> Result<UserResponse> {
        let bearer = self.require_enabled_bearer(auth_ctx).await?;

        let is_admin = bearer.role == ROLE_ADMIN;
        let is_self = bearer.sub == username;

        if !is_admin && !is_self {
            log::error!("Update user '{}' rejected for '{}': not admin and not self", username, bearer.sub);
            return Err(RbsError::AuthzInsufficientPermissions);
        }

        validator::Validate::validate(req).map_err(|e| RbsError::InvalidParameter(e.to_string()))?;
        req.validate_cross_fields()?;

        if username == ADMIN_USERNAME {
            if let Some(ref role) = req.role {
                if *role != Role::Admin {
                    log::error!("Update '{}' rejected: cannot change role of the built-in administrator", username);
                    return Err(RbsError::InvalidParameter("Cannot change role of the built-in administrator".to_string()));
                }
            }
            if let Some(enabled) = req.enabled {
                if !enabled {
                    log::error!("Update '{}' rejected: cannot disable the built-in administrator", username);
                    return Err(RbsError::InvalidParameter("Cannot disable the built-in administrator".to_string()));
                }
            }
        }

        if !is_admin {
            AdminManager::enforce_whitelist(req, username)?;
        }

        let key_material = AdminManager::extract_update_key_material(req)?;

        let db = get_connection_from_pool().map_err(|e| {
            log::error!("Failed to get DB connection for update_user: {}", e);
            internal_err(e)
        })?;

        let updated = Self::apply_user_update(&db, username, req, &key_material)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("not_found") {
                    log::error!("Update user '{}' rejected: not found", username);
                    return RbsError::ResourceNotFound;
                }
                log::error!("Failed to update user '{}': {}", username, e);
                internal_err(e)
            })?;

        log::info!("User '{}' updated by '{}'", username, bearer.sub);
        Ok(model_to_response(&updated))
    }

    /// Delete a user (admin only, cannot delete self).
    pub async fn delete_user(&self, username: &str, auth_ctx: &AuthContext) -> Result<()> {
        let bearer = self.require_enabled_admin(auth_ctx).await?;

        if bearer.sub == username {
            log::error!("Delete user '{}' rejected: admin attempted self-deletion", username);
            return Err(RbsError::AuthzInsufficientPermissions);
        }

        let db = get_connection_from_pool().map_err(|e| {
            log::error!("Failed to get DB connection for delete_user: {}", e);
            internal_err(e)
        })?;
        let result = UserEntity::delete_by_id(username)
            .exec(&*db)
            .await
            .map_err(|e| {
                log::error!("Failed to delete user '{}': {}", username, e);
                internal_err(e)
            })?;

        if result.rows_affected == 0 {
            log::error!("Delete user '{}' rejected: not found", username);
            return Err(RbsError::ResourceNotFound);
        }

        log::info!("User '{}' deleted by '{}'", username, bearer.sub);
        Ok(())
    }

    // ── Key material ──

    /// Extract key material from a validated `UserCreateRequest`.
    /// Assumes `req.validate()` has already been called.
    fn extract_auth_material(req: &UserCreateRequest) -> Result<(String, String)> {
        let auth_value = if let Some(pk) = req.public_key.as_deref().filter(|s| !s.is_empty()) {
            let pem = crate::admin::key::decode_base64_input(pk, "public_key")?;
            validate_and_derive_alg(&pem)?;
            pem
        } else if let Some(jwk) = &req.jwk {
            jwk_to_pem(jwk)?
        } else {
            // validate() guarantees this branch is unreachable
            return Err(RbsError::InvalidParameter("No key material".to_string()));
        };
        let auth_alg = validate_and_derive_alg(&auth_value)?;
        Ok((auth_value, auth_alg))
    }

    /// Extract optional key material from a validated `UserUpdateRequest`.
    fn extract_update_key_material(req: &UserUpdateRequest) -> Result<Option<(String, String)>> {
        if let Some(pk) = req.public_key.as_deref().filter(|s| !s.is_empty()) {
            let pem = crate::admin::key::decode_base64_input(pk, "public_key")?;
            let alg = validate_and_derive_alg(&pem)?;
            Ok(Some((pem, alg)))
        } else if let Some(jwk) = &req.jwk {
            let pem = jwk_to_pem(jwk)?;
            let alg = validate_and_derive_alg(&pem)?;
            Ok(Some((pem, alg)))
        } else {
            Ok(None)
        }
    }

    /// Insert a user atomically: check limit + duplicate within a transaction.
    async fn insert_user_in_txn(
        db: &sea_orm::DatabaseConnection,
        req: &UserCreateRequest,
        auth_value: &str,
        auth_alg: &str,
        max_users: u32,
    ) -> std::result::Result<UserModel, sea_orm::TransactionError<sea_orm::DbErr>> {
        let user_id = generate_uuid();
        let now = now_without_nanos();
        let role: DbRole = req.role.unwrap_or(Role::User).into();
        let status = if req.enabled.unwrap_or(true) { UserStatus::Enabled } else { UserStatus::Disabled };
        let username = req.username.clone();
        let auth_value = auth_value.to_string();
        let auth_alg = auth_alg.to_string();

        db.transaction(|txn| {
            let username = username.clone();
            let auth_value = auth_value.clone();
            let auth_alg = auth_alg.clone();
            let role = role.clone();

            Box::pin(async move {
                let regular_count = UserEntity::find()
                    .filter(UserColumn::Role.ne(DbRole::Admin))
                    .count(txn)
                    .await?;

                if regular_count >= max_users as u64 {
                    return Err(sea_orm::DbErr::Custom("max_users".to_string()));
                }

                let existing = UserEntity::find_by_id(&username).one(txn).await?;
                if existing.is_some() {
                    return Err(sea_orm::DbErr::Custom("duplicate".to_string()));
                }

                let model = UserActiveModel {
                    user_id: Set(user_id),
                    username: Set(username),
                    role: Set(role),
                    auth_type: Set(DbAuthType::Jwt),
                    auth_value: Set(auth_value),
                    auth_alg: Set(auth_alg),
                    status: Set(status),
                    created_at: Set(now),
                    updated_at: Set(now),
                    ..Default::default()
                };

                model.insert(txn).await
            })
        })
        .await
    }

    /// Build a filtered `Select<UserEntity>` from query parameters.
    /// Called once for count and once for data so both queries apply the same filters.
    fn build_filtered_query(params: &UserListQuery) -> Select<UserEntity> {
        let mut query = UserEntity::find();
        if let Some(ref role) = params.role {
            query = query.filter(UserColumn::Role.eq(DbRole::from(*role)));
        }
        if let Some(enabled) = params.enabled {
            query = query.filter(UserColumn::Status.eq(if enabled { UserStatus::Enabled } else { UserStatus::Disabled }));
        }
        query
    }

    // ── Update helpers ──

    /// Non-admin users may only update their own key material.
    fn enforce_whitelist(req: &UserUpdateRequest, username: &str) -> Result<()> {
        if req.role.is_some() {
            log::error!("Self-update by '{}' rejected: attempted to change role", username);
            return Err(RbsError::AuthzInsufficientPermissions);
        }
        if req.enabled.is_some() {
            log::error!("Self-update by '{}' rejected: attempted to change enabled", username);
            return Err(RbsError::AuthzInsufficientPermissions);
        }
        Ok(())
    }

    /// Apply field changes to a user within a transaction (SELECT → modify → UPDATE).
    async fn apply_user_update(
        db: &sea_orm::DatabaseConnection,
        username: &str,
        req: &UserUpdateRequest,
        key_material: &Option<(String, String)>,
    ) -> std::result::Result<UserModel, sea_orm::TransactionError<sea_orm::DbErr>> {
        let username = username.to_string();
        let role = req.role.clone();
        let enabled = req.enabled;
        let auth_type = req.auth_type.clone();
        let key_material = key_material.clone();

        db.transaction(|txn| {
            let username = username.clone();
            let role = role.clone();
            let auth_type = auth_type.clone();
            let key_material = key_material.clone();

            Box::pin(async move {
                let existing = UserEntity::find_by_id(&username).one(txn).await?;
                let mut active: UserActiveModel = existing
                    .ok_or_else(|| sea_orm::DbErr::Custom("not_found".to_string()))?
                    .into();

                if let Some((ref auth_value, ref auth_alg)) = key_material {
                    active.auth_value = Set(auth_value.clone());
                    active.auth_alg = Set(auth_alg.clone());
                }
                if let Some(role) = role {
                    active.role = Set(DbRole::from(role));
                }
                if let Some(enabled) = enabled {
                    active.status = Set(if enabled { UserStatus::Enabled } else { UserStatus::Disabled });
                }
                if let Some(auth_type) = auth_type {
                    active.auth_type = Set(DbAuthType::from(auth_type));
                }

                active.updated_at = Set(now_without_nanos());
                active.update(txn).await
            })
        })
        .await
    }

    // ── AuthZ helpers ──

    /// Authorize with `AdminOnly`, check enabled, return `BearerContext`.
    async fn require_enabled_admin<'a>(&self, auth_ctx: &'a AuthContext) -> Result<&'a crate::auth::BearerContext> {
        log::info!("require_enabled_admin: starting authz check");

        let result = self.authz
            .check(auth_ctx)
            .action(Action::List)
            .required_role(RequiredRole::AdminOnly)
            .ensure_allowed()
            .await;

        match result {
            Ok(_) => log::info!("require_enabled_admin: authz check passed"),
            Err(e) => {
                return Err(map_authz_err(e, auth_ctx));
            }
        }

        let bearer = extract_bearer(auth_ctx)?;
        log::info!("require_enabled_admin: extract_bearer succeeded, sub={}", bearer.sub);

        self.ensure_enabled(&bearer.sub).await?;
        log::info!("require_enabled_admin: ensure_enabled passed");

        Ok(bearer)
    }

    /// Authorize with `UserScoped`, check enabled, return `BearerContext`.
    async fn require_enabled_bearer<'a>(&self, auth_ctx: &'a AuthContext) -> Result<&'a crate::auth::BearerContext> {
        log::info!("require_enabled_bearer: starting authz check");
        let result = self.authz
            .check(auth_ctx)
            .action(Action::Get)
            .required_role(RequiredRole::UserScoped)
            .ensure_allowed()
            .await;

        match result {
            Ok(_) => log::info!("require_enabled_bearer: authz check passed"),
            Err(e) => {
                return Err(map_authz_err(e, auth_ctx));
            }
        }

        let bearer = extract_bearer(auth_ctx)?;
        log::info!("require_enabled_bearer: extract_bearer succeeded, sub={}", bearer.sub);

        self.ensure_enabled(&bearer.sub).await?;
        log::info!("require_enabled_bearer: ensure_enabled passed");

        Ok(bearer)
    }

    /// Verify the calling user is enabled.
    async fn ensure_enabled(&self, username: &str) -> Result<()> {
        log::info!("ensure_enabled: checking username={}", username);

        let db = get_connection_from_pool().map_err(|e| {
            log::error!("ensure_enabled: get_connection_from_pool failed: {}", e);
            internal_err(e)
        })?;
        log::info!("ensure_enabled: got DB connection");

        let model = UserEntity::find_by_id(username)
            .one(&*db)
            .await
            .map_err(|e| {
                log::error!("ensure_enabled: query failed: {}", e);
                internal_err(e)
            })?;
        log::info!("ensure_enabled: query succeeded, model={:?}", model.as_ref().map(|m| (&m.username, m.status)));

        match model {
            Some(m) if m.status == UserStatus::Disabled => {
                log::error!("Operation rejected: user '{}' is disabled", username);
                Err(RbsError::AuthzInsufficientPermissions)
            }
            Some(_) => Ok(()),
            None => {
                log::error!("Operation rejected: user '{}' not found", username);
                Err(RbsError::AuthzInsufficientPermissions)
            }
        }
    }

    /// Read the admin public key from config file and derive algorithm.
    fn read_admin_key(&self) -> Result<(String, String)> {
        let key_config = &self.config.admin_key;
        let has_pem = key_config.public_key_path.as_ref().map_or(false, |s| !s.is_empty());
        let has_jwk = key_config.jwks_file.as_ref().map_or(false, |s| !s.is_empty());

        match (has_pem, has_jwk) {
            (true, true) => {
                log::error!("Admin key config error: public_key_path and jwks_file are mutually exclusive");
                Err(RbsError::InternalUnexpected {
                    context: "admin_key: public_key_path and jwks_file are mutually exclusive".to_string(),
                })
            }
            (false, false) => {
                log::error!("Admin key config error: neither public_key_path nor jwks_file configured");
                Err(RbsError::InternalUnexpected {
                    context: "admin_key: either public_key_path or jwks_file must be configured".to_string(),
                })
            }
            (true, false) => {
                let Some(path) = key_config.public_key_path.as_deref() else {
                    log::error!("Admin key config internal error: public_key_path missing in (true, false) arm");
                    return Err(RbsError::InternalUnexpected {
                        context: "admin_key internal error".to_string(),
                    });
                };
                let pem = fs::read_to_string(path).map_err(|e| {
                    log::error!("Failed to read admin public key file '{}': {}", path, e);
                    RbsError::InternalUnexpected {
                        context: format!("Failed to read public key file ({}): {}", path, e),
                    }
                })?;
                let alg = validate_and_derive_alg(&pem).inspect_err(|e| {
                    log::error!("Admin public key invalid: {}", e);
                })?;
                log::debug!("Admin public key loaded from '{}' (alg={})", path, alg);
                Ok((pem, alg))
            }
            (false, true) => {
                let Some(path) = key_config.jwks_file.as_deref() else {
                    log::error!("Admin key config internal error: jwks_file missing in (false, true) arm");
                    return Err(RbsError::InternalUnexpected {
                        context: "admin_key internal error".to_string(),
                    });
                };
                let content = fs::read_to_string(path).map_err(|e| {
                    log::error!("Failed to read admin JWK file '{}': {}", path, e);
                    RbsError::InternalUnexpected {
                        context: format!("Failed to read JWK file ({}): {}", path, e),
                    }
                })?;
                let jwk: Value = serde_json::from_str(&content).map_err(|e| {
                    log::error!("Failed to parse admin JWK file '{}': {}", path, e);
                    RbsError::InternalUnexpected {
                        context: format!("Failed to parse JWK file ({}): {}", path, e),
                    }
                })?;
                let pem = jwk_to_pem(&jwk).inspect_err(|e| {
                    log::error!("Failed to convert admin JWK to PEM: {}", e);
                })?;
                let alg = validate_and_derive_alg(&pem)?;
                log::debug!("Admin JWK key loaded from '{}' (alg={})", path, alg);
                Ok((pem, alg))
            }
        }
    }
}

#[async_trait::async_trait]
impl crate::auth::UserKeyProvider for AdminManager {
    async fn get_public_key(&self, sub: &str) -> std::result::Result<String, crate::auth::AuthError> {
        let db = get_connection_from_pool().map_err(|e| {
            log::error!("Failed to get DB connection for public key lookup: {}", e);
            crate::auth::AuthError::TokenInvalid { reason: "database error".to_string() }
        })?;

        let model = UserEntity::find_by_id(sub)
            .one(&*db)
            .await
            .map_err(|e| {
                log::error!("Failed to query user '{}' for public key: {}", sub, e);
                crate::auth::AuthError::TokenInvalid { reason: "database error".to_string() }
            })?
            .ok_or_else(|| {
                log::error!("BearerToken verification failed: user '{}' not found", sub);
                crate::auth::AuthError::TokenInvalid {
                    reason: format!("user '{}' not found", sub),
                }
            })?;

        Ok(model.auth_value)
    }
}

// ── Free functions ──

/// Extract `BearerContext` from `AuthContext`; reject `Attest`.
fn extract_bearer(ctx: &AuthContext) -> Result<&crate::auth::BearerContext> {
    match ctx {
        AuthContext::Bearer(b) => Ok(b),
        AuthContext::Attest(_) => {
            log::error!("Admin operation rejected: AttestToken used");
            Err(RbsError::AuthnInvalidToken)
        }
    }
}

/// Map `AuthzError` to `RbsError`, logging appropriately.
fn map_authz_err(e: AuthzError, ctx: &AuthContext) -> RbsError {
    match ctx {
        AuthContext::Bearer(b) => {
            log::error!("Authz denied for '{}' (role={}): {:?}", b.sub, b.role, e);
        }
        AuthContext::Attest(_) => {
            log::error!("Authz denied for AttestToken: {:?}", e);
        }
    }
    match e {
        AuthzError::Denied => RbsError::AuthzInsufficientPermissions,
        _ => RbsError::InternalUnexpected { context: format!("Authz error: {:?}", e) },
    }
}

/// Get current timestamp without nanoseconds.
fn now_without_nanos() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now().with_nanosecond(0).unwrap()
}

/// Convert a database model to API response.
fn model_to_response(m: &UserModel) -> UserResponse {
    UserResponse {
        id: m.user_id.clone(),
        username: m.username.clone(),
        role: m.role.into(),
        enabled: m.status == UserStatus::Enabled,
        created_at: m.created_at.to_rfc3339(),
        updated_at: m.updated_at.to_rfc3339(),
    }
}

/// Generate a UUID v4 string.
fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn internal_err(e: impl std::fmt::Display) -> RbsError {
    RbsError::InternalUnexpected { context: e.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use rbs_api_types::{AuthType, Role};

    // Generate a fresh RSA key pair for each test to avoid hard-coded keys.
    fn generate_test_public_key() -> String {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        let pem = pkey.public_key_to_pem().unwrap();
        String::from_utf8(pem).unwrap()
    }

    #[test]
    fn uuid_generation_returns_valid_format() {
        let uuid = generate_uuid();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn timestamp_generation_has_zero_nanoseconds() {
        let ts = now_without_nanos();
        assert_eq!(ts.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn extract_auth_material_returns_value_with_valid_public_key() {
        let public_key = generate_test_public_key();
        let req = UserCreateRequest {
            username: "test".to_string(),
            role: None,
            enabled: None,
            auth_type: AuthType::Jwt,
            public_key: Some(base64::engine::general_purpose::STANDARD.encode(&public_key)),
            jwk: None,
        };
        let result = AdminManager::extract_auth_material(&req);
        assert!(result.is_ok());
        let (auth_value, auth_alg) = result.unwrap();
        assert!(auth_value.contains("BEGIN PUBLIC KEY"));
        assert_eq!(auth_alg, "RSA");
    }

    #[test]
    fn extract_auth_material_fails_without_key_material() {
        let req = UserCreateRequest {
            username: "test".to_string(),
            role: None,
            enabled: None,
            auth_type: AuthType::Jwt,
            public_key: None,
            jwk: None,
        };
        let result = AdminManager::extract_auth_material(&req);
        assert!(result.is_err());
    }

    #[test]
    fn extract_update_key_material_returns_value_with_public_key() {
        let public_key = generate_test_public_key();
        let req = UserUpdateRequest {
            role: None,
            enabled: None,
            auth_type: Some(AuthType::Jwt),
            public_key: Some(base64::engine::general_purpose::STANDARD.encode(&public_key)),
            jwk: None,
        };
        let result = AdminManager::extract_update_key_material(&req);
        assert!(result.is_ok());
        let material = result.unwrap();
        assert!(material.is_some());
        let (auth_value, auth_alg) = material.unwrap();
        assert!(auth_value.contains("BEGIN PUBLIC KEY"));
        assert_eq!(auth_alg, "RSA");
    }

    #[test]
    fn extract_update_key_material_returns_none_without_key() {
        let req = UserUpdateRequest {
            role: Some(Role::User),
            enabled: None,
            auth_type: None,
            public_key: None,
            jwk: None,
        };
        let result = AdminManager::extract_update_key_material(&req);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn enforce_whitelist_rejects_role_update_for_non_admin() {
        let req = UserUpdateRequest {
            role: Some(Role::User),
            enabled: None,
            auth_type: None,
            public_key: None,
            jwk: None,
        };
        let result = AdminManager::enforce_whitelist(&req, "test_user");
        assert!(result.is_err());
        match result {
            Err(RbsError::AuthzInsufficientPermissions) => {}
            _ => panic!("Expected AuthzInsufficientPermissions"),
        }
    }

    #[test]
    fn enforce_whitelist_rejects_enabled_update_for_non_admin() {
        let req = UserUpdateRequest {
            role: None,
            enabled: Some(false),
            auth_type: None,
            public_key: None,
            jwk: None,
        };
        let result = AdminManager::enforce_whitelist(&req, "test_user");
        assert!(result.is_err());
    }

    #[test]
    fn enforce_whitelist_accepts_key_update() {
        let req = UserUpdateRequest {
            role: None,
            enabled: None,
            auth_type: Some(AuthType::Jwt),
            public_key: Some("dGVzdEtleQ==".to_string()),  // base64 of "testKey"
            jwk: None,
        };
        let result = AdminManager::enforce_whitelist(&req, "test_user");
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_whitelist_accepts_empty_request() {
        let req = UserUpdateRequest {
            role: None,
            enabled: None,
            auth_type: None,
            public_key: None,
            jwk: None,
        };
        let result = AdminManager::enforce_whitelist(&req, "test_user");
        assert!(result.is_ok());
    }

    // ── Filtered list_users integration tests (SQLite in-memory) ──

    async fn setup_test_users(db: &sea_orm::DatabaseConnection) {
        let now = chrono::Utc::now().with_nanosecond(0).unwrap();
        let users = vec![
            ("Alice", DbRole::Admin, UserStatus::Enabled),
            ("Bob", DbRole::User, UserStatus::Enabled),
            ("Charlie", DbRole::User, UserStatus::Disabled),
            ("Dave", DbRole::User, UserStatus::Enabled),
            ("Eve", DbRole::User, UserStatus::Disabled),
        ];
        for (name, role, status) in users {
            let model = UserActiveModel {
                user_id: Set(uuid::Uuid::new_v4().to_string()),
                username: Set(name.to_string()),
                role: Set(role),
                auth_type: Set(DbAuthType::Jwt),
                auth_value: Set("test-key".to_string()),
                auth_alg: Set("RSA".to_string()),
                status: Set(status),
                created_at: Set(now),
                updated_at: Set(now),
                ..Default::default()
            };
            model.insert(db).await.expect("insert test user");
        }
    }

    async fn run_filtered_query(db: &sea_orm::DatabaseConnection, params: &UserListQuery) -> Vec<String> {
        let models = AdminManager::build_filtered_query(params)
            .order_by_asc(UserColumn::Username)
            .all(db)
            .await
            .expect("query users");
        models.into_iter().map(|m| m.username).collect()
    }

    #[tokio::test]
    async fn filter_no_params_returns_all() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.expect("connect");
        crate::rdb::execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql").await.expect("migrate");
        setup_test_users(&db).await;

        let params = UserListQuery { limit: None, offset: None, role: None, enabled: None };
        let users = run_filtered_query(&db, &params).await;
        assert_eq!(users.len(), 5);
    }

    #[tokio::test]
    async fn filter_by_role_user() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.expect("connect");
        crate::rdb::execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql").await.expect("migrate");
        setup_test_users(&db).await;

        let params = UserListQuery { limit: None, offset: None, role: Some(Role::User), enabled: None };
        let users = run_filtered_query(&db, &params).await;
        assert_eq!(users.len(), 4);
        assert!(!users.contains(&"Alice".to_string()));
    }

    #[tokio::test]
    async fn filter_by_role_admin() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.expect("connect");
        crate::rdb::execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql").await.expect("migrate");
        setup_test_users(&db).await;

        let params = UserListQuery { limit: None, offset: None, role: Some(Role::Admin), enabled: None };
        let users = run_filtered_query(&db, &params).await;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0], "Alice");
    }

    #[tokio::test]
    async fn filter_by_enabled_true() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.expect("connect");
        crate::rdb::execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql").await.expect("migrate");
        setup_test_users(&db).await;

        let params = UserListQuery { limit: None, offset: None, role: None, enabled: Some(true) };
        let users = run_filtered_query(&db, &params).await;
        assert_eq!(users.len(), 3);
        assert!(!users.contains(&"Charlie".to_string()));
        assert!(!users.contains(&"Eve".to_string()));
    }

    #[tokio::test]
    async fn filter_by_enabled_false() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.expect("connect");
        crate::rdb::execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql").await.expect("migrate");
        setup_test_users(&db).await;

        let params = UserListQuery { limit: None, offset: None, role: None, enabled: Some(false) };
        let users = run_filtered_query(&db, &params).await;
        assert_eq!(users.len(), 2);
        assert_eq!(users, vec!["Charlie", "Eve"]);
    }

    #[tokio::test]
    async fn filter_by_role_and_enabled_combined() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.expect("connect");
        crate::rdb::execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql").await.expect("migrate");
        setup_test_users(&db).await;

        let params = UserListQuery { limit: None, offset: None, role: Some(Role::User), enabled: Some(true) };
        let users = run_filtered_query(&db, &params).await;
        assert_eq!(users.len(), 2);
        assert_eq!(users, vec!["Bob", "Dave"]);
    }

    #[tokio::test]
    async fn filter_admin_disabled_returns_empty() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.expect("connect");
        crate::rdb::execute_sql_file_path(&db, "../rdb_sql/sqlite_rbs.sql").await.expect("migrate");
        setup_test_users(&db).await;

        let params = UserListQuery { limit: None, offset: None, role: Some(Role::Admin), enabled: Some(false) };
        let users = run_filtered_query(&db, &params).await;
        assert!(users.is_empty());
    }
}

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

use rbs_api_types::error::RbsError;
use rbs_api_types::{
    AdminConfig, UserCreateRequest, UserListResponse, UserResponse, UserUpdateRequest,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait};
use serde_json::Value;

use crate::auth::{AdminAction, AuthContext, AuthzError, AuthzFacade, RequiredRole};
use crate::infra::rdb::get_connection_from_pool;

use super::entity::{
    ActiveModel as UserActiveModel, Column as UserColumn, Entity as UserEntity, Model as UserModel,
};
use super::key::{jwk_to_pem, validate_and_derive_alg};

const ADMIN_USERNAME: &str = "Administrator";
const ROLE_ADMIN: &str = "admin";
const ROLE_USER: &str = "user";
const AUTH_TYPE_JWT: &str = "jwt";

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
    /// Create a new AdminManager from config.
    #[must_use]
    pub fn new(config: AdminConfig) -> Self {
        Self {
            config,
            authz: AuthzFacade::new(),
        }
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
        let now = now_iso8601();

        let model = UserActiveModel {
            user_id: Set(user_id.clone()),
            username: Set(ADMIN_USERNAME.to_string()),
            role: Set(ROLE_ADMIN.to_string()),
            auth_type: Set(AUTH_TYPE_JWT.to_string()),
            auth_value: Set(auth_value),
            auth_alg: Set(auth_alg),
            status: Set(1),
            created_at: Set(now.clone()),
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
    pub async fn list_users(&self, limit: i64, offset: i64, auth_ctx: &AuthContext) -> Result<UserListResponse> {
        log::info!("[DEBUG] list_users called: limit={}, offset={}", limit, offset);

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

        log::debug!("Listing users (limit={}, offset={}) by '{}'", limit, offset, bearer.sub);

        let db = get_connection_from_pool().map_err(|e| {
            log::error!("Failed to get DB connection for list_users: {}", e);
            internal_err(e)
        })?;

        let total_count = UserEntity::find().count(&*db).await.map_err(|e| {
            log::error!("Failed to count users: {}", e);
            internal_err(e)
        })? as i64;

        let models = UserEntity::find()
            .order_by_asc(UserColumn::Username)
            .limit(Some(limit as u64))
            .offset(Some(offset as u64))
            .all(&*db)
            .await
            .map_err(|e| {
                log::error!("Failed to list users: {}", e);
                internal_err(e)
            })?;

        let items = models.into_iter().map(|m| model_to_response(&m)).collect();

        Ok(UserListResponse { items, total_count, limit, offset })
    }

    /// Create a user (admin only).
    pub async fn create_user(&self, req: &UserCreateRequest, auth_ctx: &AuthContext) -> Result<UserResponse> {
        let bearer = self.require_enabled_admin(auth_ctx).await?;

        validator::Validate::validate(req).map_err(|e| RbsError::InvalidParameter(e.to_string()))?;
        req.validate_key_pair()?;
        let (auth_value, auth_alg) = Self::extract_auth_material(req)?;
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
                return RbsError::AuthzInsufficientPermissions;
            }
            log::error!("Failed to insert user '{}': {}", req.username, e);
            internal_err(e)
        })?;

        log::info!("User '{}' (id={}, role={}) created by '{}'",
            req.username,
            inserted.user_id,
            inserted.role,
            bearer.sub,
        );
        Ok(model_to_response(&inserted))
    }

    /// Get a user (admin or self).
    pub async fn get_user(&self, username: &str, auth_ctx: &AuthContext) -> Result<Option<UserResponse>> {
        log::info!("[DEBUG] get_user: called with username={}", username);
        let bearer = self.require_enabled_bearer(auth_ctx).await?;

        if bearer.role != ROLE_ADMIN && bearer.sub != username {
            log::warn!("Get user '{}' rejected for '{}': not admin and not self", username, bearer.sub);
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
            log::warn!("Update user '{}' rejected for '{}': not admin and not self", username, bearer.sub);
            return Err(RbsError::AuthzInsufficientPermissions);
        }

        validator::Validate::validate(req).map_err(|e| RbsError::InvalidParameter(e.to_string()))?;
        req.validate()?;
        if !is_admin {
            Self::enforce_whitelist(req, username)?;
        }

        let key_material = Self::extract_update_key_material(req)?;

        let db = get_connection_from_pool().map_err(|e| {
            log::error!("Failed to get DB connection for update_user: {}", e);
            internal_err(e)
        })?;

        let updated = Self::apply_user_update(&db, username, req, &key_material)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("not_found") {
                    log::warn!("Update user '{}' rejected: not found", username);
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
            log::warn!("Delete user '{}' rejected: admin attempted self-deletion", username);
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
            log::warn!("Delete user '{}' rejected: not found", username);
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
            validate_and_derive_alg(pk)?;
            pk.to_string()
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
            let alg = validate_and_derive_alg(pk)?;
            Ok(Some((pk.to_string(), alg)))
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
        use sea_orm::ConnectionTrait;

        let user_id = generate_uuid();
        let now = now_iso8601();
        let role = req.role.as_deref().unwrap_or(ROLE_USER).to_string();
        let status: i32 = if req.enabled.unwrap_or(true) { 1 } else { 0 };
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
                    .filter(UserColumn::Role.ne(ROLE_ADMIN))
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
                    auth_type: Set(AUTH_TYPE_JWT.to_string()),
                    auth_value: Set(auth_value),
                    auth_alg: Set(auth_alg),
                    status: Set(status),
                    created_at: Set(now.clone()),
                    updated_at: Set(now),
                    ..Default::default()
                };

                model.insert(txn).await
            })
        })
        .await
    }

    // ── Update helpers ──

    /// Non-admin users may only update their own key material.
    fn enforce_whitelist(req: &UserUpdateRequest, username: &str) -> Result<()> {
        if req.role.is_some() {
            log::warn!("Self-update by '{}' rejected: attempted to change role", username);
            return Err(RbsError::AuthzInsufficientPermissions);
        }
        if req.enabled.is_some() {
            log::warn!("Self-update by '{}' rejected: attempted to change enabled", username);
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
        use sea_orm::ConnectionTrait;

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
                if let Some(ref role) = role {
                    active.role = Set(role.clone());
                }
                if let Some(enabled) = enabled {
                    active.status = Set(if enabled { 1 } else { 0 });
                }
                if let Some(ref auth_type) = auth_type {
                    active.auth_type = Set(auth_type.clone());
                }

                active.updated_at = Set(now_iso8601());
                active.update(txn).await
            })
        })
        .await
    }

    // ── AuthZ helpers ──

    /// Authorize with `AdminOnly`, check enabled, return `BearerContext`.
    async fn require_enabled_admin<'a>(&self, auth_ctx: &'a AuthContext) -> Result<&'a crate::auth::BearerContext> {
        log::info!("[DEBUG] require_enabled_admin: starting authz check");

        let result = self.authz
            .check(auth_ctx)
            .action(AdminAction::List)
            .required_role(RequiredRole::AdminOnly)
            .ensure_allowed()
            .await;

        match result {
            Ok(_) => log::info!("[DEBUG] require_enabled_admin: authz check passed"),
            Err(e) => {
                log::error!("[DEBUG] require_enabled_admin: authz check failed: {:?}", e);
                return Err(map_authz_err(e, auth_ctx));
            }
        }

        let bearer = extract_bearer(auth_ctx)?;
        log::info!("[DEBUG] require_enabled_admin: extract_bearer succeeded, sub={}", bearer.sub);

        self.ensure_enabled(&bearer.sub).await?;
        log::info!("[DEBUG] require_enabled_admin: ensure_enabled passed");

        Ok(bearer)
    }

    /// Authorize with `UserScoped`, check enabled, return `BearerContext`.
    async fn require_enabled_bearer<'a>(&self, auth_ctx: &'a AuthContext) -> Result<&'a crate::auth::BearerContext> {
        log::info!("[DEBUG] require_enabled_bearer: starting authz check");
        let result = self.authz
            .check(auth_ctx)
            .action(AdminAction::Get)
            .required_role(RequiredRole::UserScoped)
            .ensure_allowed()
            .await;

        match result {
            Ok(_) => log::info!("[DEBUG] require_enabled_bearer: authz check passed"),
            Err(e) => {
                log::error!("[DEBUG] require_enabled_bearer: authz check failed: {:?}", e);
                return Err(map_authz_err(e, auth_ctx));
            }
        }

        let bearer = extract_bearer(auth_ctx)?;
        log::info!("[DEBUG] require_enabled_bearer: extract_bearer succeeded, sub={}", bearer.sub);

        self.ensure_enabled(&bearer.sub).await?;
        log::info!("[DEBUG] require_enabled_bearer: ensure_enabled passed");

        Ok(bearer)
    }

    /// Verify the calling user is enabled.
    async fn ensure_enabled(&self, username: &str) -> Result<()> {
        log::info!("[DEBUG] ensure_enabled: checking username={}", username);

        let db = get_connection_from_pool().map_err(|e| {
            log::error!("[DEBUG] ensure_enabled: get_connection_from_pool failed: {}", e);
            internal_err(e)
        })?;
        log::info!("[DEBUG] ensure_enabled: got DB connection");

        let model = UserEntity::find_by_id(username)
            .one(&*db)
            .await
            .map_err(|e| {
                log::error!("[DEBUG] ensure_enabled: query failed: {}", e);
                internal_err(e)
            })?;
        log::info!("[DEBUG] ensure_enabled: query succeeded, model={:?}", model.as_ref().map(|m| (&m.username, m.status)));

        match model {
            Some(m) if m.status == 0 => {
                log::warn!("Operation rejected: user '{}' is disabled", username);
                Err(RbsError::AuthzInsufficientPermissions)
            }
            Some(_) => Ok(()),
            None => {
                log::warn!("Operation rejected: user '{}' not found", username);
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
                log::warn!("BearerToken verification failed: user '{}' not found", sub);
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
            log::warn!("Admin operation rejected: AttestToken used");
            Err(RbsError::AuthnInvalidToken)
        }
    }
}

/// Map `AuthzError` to `RbsError`, logging appropriately.
fn map_authz_err(e: AuthzError, ctx: &AuthContext) -> RbsError {
    match ctx {
        AuthContext::Bearer(b) => {
            log::warn!("Authz denied for '{}' (role={}): {:?}", b.sub, b.role, e);
        }
        AuthContext::Attest(_) => {
            log::warn!("Authz denied for AttestToken: {:?}", e);
        }
    }
    match e {
        AuthzError::Denied => RbsError::AuthzInsufficientPermissions,
        _ => RbsError::InternalUnexpected { context: format!("Authz error: {:?}", e) },
    }
}

/// Convert a database model to API response.
fn model_to_response(m: &UserModel) -> UserResponse {
    UserResponse {
        id: m.user_id.clone(),
        username: m.username.clone(),
        role: m.role.clone(),
        enabled: m.status == 1,
        created_at: m.created_at.clone(),
        updated_at: m.updated_at.clone(),
    }
}

/// Generate a UUID v4 string.
fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Current time in ISO 8601 format.
fn now_iso8601() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn internal_err(e: impl std::fmt::Display) -> RbsError {
    RbsError::InternalUnexpected { context: e.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_uuid_format() {
        let uuid = generate_uuid();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().filter(|&c| c == '-').count(), 4);
    }
}

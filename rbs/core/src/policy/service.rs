use std::sync::Arc;

use sea_orm::TransactionTrait;

use super::config::PolicyConfig;
use super::error::PolicyError;
use super::repository::{PolicyEntity, PolicyRepository};
use super::validator::PolicyValidator;

use crate::auth::authz::{Action, AuthzFacade, RequiredRole};
use crate::auth::context::AuthContext;
use crate::resource::adapter::PolicyClient;

// Re-export HTTP-facing request / response types from rbs-api-types.
pub use rbs_api_types::policy::{
    CreatePolicyRequest, PolicyListResponse, PolicyResponse, UpdatePolicyRequest,
};

/// Policy list query parameters (internal, not HTTP-facing).
#[derive(Debug, Clone)]
pub struct PolicyQuery {
    pub ids: Option<Vec<String>>,
    pub offset: i64,
    pub limit: i64,
}

/// PolicyService - single struct holding all dependencies.
/// All CRUD operations are methods on this struct.
pub struct PolicyService {
    pub repo: Arc<dyn PolicyRepository>,
    pub authz: AuthzFacade,
    pub resource_client: Arc<dyn PolicyClient>,
    pub validator: PolicyValidator,
    pub config: PolicyConfig,
}

impl PolicyService {
    pub fn new(
        repo: Arc<dyn PolicyRepository>,
        authz: AuthzFacade,
        resource_client: Arc<dyn PolicyClient>,
        validator: PolicyValidator,
        config: PolicyConfig,
    ) -> Self {
        Self { repo, authz, resource_client, validator, config }
    }

    // ---------------------------------------------------------------------------
    // Helper: generate a UUID-like policy ID (UUID without dashes).
    // ---------------------------------------------------------------------------
    fn generate_policy_id() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    /// Create a new policy.
    pub async fn create(&self, ctx: &AuthContext, req: &CreatePolicyRequest) -> Result<PolicyResponse, PolicyError> {
        // ── step 1: permission check ──
        // TODO: auth module under active development — AuthzFacade API may change.
        self.authz.check(ctx).action(Action::Create).required_role(RequiredRole::UserScoped).ensure_allowed().await.map_err(|_| PolicyError::PermissionDenied)?;

        // ── step 2: data validation ──
        self.validator.validate_name(&req.name)?;
        let user_id = ctx.sub();

        // name duplicate check
        if let Some(_existing) = self.repo.find_by_name_and_user(&req.name, user_id).await? {
            return Err(PolicyError::NameDuplicate { name: req.name.clone() });
        }

        // count limit check
        let count = self.repo.count_by_user(user_id).await?;
        self.validator.check_user_policy_count(count)?;

        // content decode and size check
        let _decoded = self.validator.decode_and_check_size(&req.content_type, &req.content)?;

        // Rego syntax check
        self.validator.validate_rego_syntax(&_decoded)?;

        // ── step 3: execute ──
        let now = chrono::Utc::now().timestamp_millis();
        let entity = PolicyEntity {
            policy_id: Self::generate_policy_id(),
            user_id: user_id.to_string(),
            policy_name: req.name.clone(),
            policy_version: 1,
            policy_content: req.content.clone(),
            content_type: req.content_type.clone(),
            created_at: now,
            updated_at: now,
        };
        self.repo.insert(entity.clone()).await?;

        Ok(PolicyResponse {
            policy_id: entity.policy_id,
            policy_name: entity.policy_name,
            policy_version: entity.policy_version,
            policy_content: entity.policy_content,
            content_type: entity.content_type,
            created_at: entity.created_at,
            updated_at: entity.updated_at,
            applied_resources: None,
        })
    }

    /// Update an existing policy with optimistic locking.
    pub async fn update(
        &self,
        ctx: &AuthContext,
        policy_id: &str,
        req: &UpdatePolicyRequest,
    ) -> Result<PolicyResponse, PolicyError> {
        // ── step 1: permission check ──
        // TODO: auth module under active development — AuthzFacade API may change.
        self.authz.check(ctx).action(Action::Update).required_role(RequiredRole::UserScoped).ensure_allowed().await.map_err(|_| PolicyError::PermissionDenied)?;

        // ── step 2: data validation ──
        self.validator.validate_name(&req.name)?;
        let user_id = ctx.sub();

        // find existing policy
        let existing = self
            .repo
            .find_by_id(policy_id)
            .await?
            .ok_or(PolicyError::NotFound)?;

        // ownership check
        if existing.user_id != user_id {
            return Err(PolicyError::PermissionDenied);
        }

        // name duplicate check (only if name changed)
        if req.name != existing.policy_name {
            if let Some(conflict) = self.repo.find_by_name_and_user(&req.name, user_id).await? {
                if conflict.policy_id != policy_id {
                    return Err(PolicyError::NameDuplicate { name: req.name.clone() });
                }
            }
        }

        // content decode and size check
        let _decoded = self.validator.decode_and_check_size(&req.content_type, &req.content)?;

        // Rego syntax check
        self.validator.validate_rego_syntax(&_decoded)?;

        // ── step 3: execute with optimistic lock ──
        let now = chrono::Utc::now().timestamp_millis();
        let updated_entity = PolicyEntity {
            policy_id: policy_id.to_string(),
            user_id: user_id.to_string(),
            policy_name: req.name.clone(),
            policy_version: existing.policy_version, // will be incremented by update_with_version
            policy_content: req.content.clone(),
            content_type: req.content_type.clone(),
            created_at: existing.created_at,
            updated_at: now,
        };

        let affected = self
            .repo
            .update_with_version(policy_id, existing.policy_version, updated_entity.clone())
            .await?;

        if affected == 0 {
            return Err(PolicyError::VersionConflict {
                expected: existing.policy_version,
                current: existing.policy_version, // actual version unknown, report expected
            });
        }

        let new_version = existing.policy_version + 1;
        Ok(PolicyResponse {
            policy_id: policy_id.to_string(),
            policy_name: req.name.clone(),
            policy_version: new_version,
            policy_content: req.content.clone(),
            content_type: req.content_type.clone(),
            created_at: existing.created_at,
            updated_at: now,
            applied_resources: None,
        })
    }

    /// Delete one or more policies (single or batch).
    /// Uses a database transaction for batch operations: validates all policies first,
    /// collects all errors, and only commits if every check passes.
    pub async fn delete(&self, ctx: &AuthContext, policy_ids: &[String]) -> Result<(), PolicyError> {
        if policy_ids.is_empty() {
            return Err(PolicyError::ParamInvalid { field: "policy_ids" });
        }

        // ── step 1: permission check ──
        self.authz.check(ctx).action(Action::Delete).required_role(RequiredRole::UserScoped).ensure_allowed().await.map_err(|_| PolicyError::PermissionDenied)?;

        let user_id = ctx.sub();

        // ── step 2: full validation (collect all errors) ──
        let mut referenced_names: Vec<String> = Vec::new();
        let entities = self.repo.find_by_ids_and_user(policy_ids, user_id).await?;

        // Check for missing policies
        if entities.len() != policy_ids.len() {
            let found_ids: std::collections::HashSet<&str> = entities.iter().map(|e| e.policy_id.as_str()).collect();
            for pid in policy_ids {
                if !found_ids.contains(pid.as_str()) {
                    return Err(PolicyError::NotFound);
                }
            }
        }

        // Check ownership and references
        for entity in &entities {
            if entity.user_id != user_id {
                return Err(PolicyError::PermissionDenied);
            }
            let refs = self.resource_client.relation_res_ids(&entity.policy_id, user_id).await?;
            if !refs.is_empty() {
                referenced_names.push(entity.policy_name.clone());
            }
        }

        if !referenced_names.is_empty() {
            return Err(PolicyError::BeingReferenced { policy_names: referenced_names });
        }

        // ── step 3: execute deletion within a transaction ──
        let db = self.repo.db_connection();
        let txn = db.begin().await.map_err(|_| PolicyError::ParamInvalid { field: "db" })?;

        let affected = self.repo.delete_by_ids_txn(&txn, policy_ids, user_id).await?;
        if affected as usize != policy_ids.len() {
            let _ = txn.rollback().await;
            return Err(PolicyError::NotFound);
        }

        txn.commit().await.map_err(|_| PolicyError::ParamInvalid { field: "db" })?;

        Ok(())
    }

    /// List policies with optional ID filter and pagination.
    pub async fn list(&self, ctx: &AuthContext, query: &PolicyQuery) -> Result<PolicyListResponse, PolicyError> {
        // ── step 1: permission check ──
        // TODO: auth module under active development — AuthzFacade API may change.
        self.authz.check(ctx).action(Action::Get).required_role(RequiredRole::UserScoped).ensure_allowed().await.map_err(|_| PolicyError::PermissionDenied)?;

        let user_id = ctx.sub();

        // ── step 2: execute ──
        let limit = if query.limit > self.config.max_page_size as i64 {
            self.config.max_page_size as i64
        } else if query.limit < 0 {
            0
        } else {
            query.limit
        };

        let (items, total) = if let Some(ref ids) = query.ids {
            if ids.is_empty() {
                (vec![], 0u64)
            } else {
                let entities = self.repo.find_by_ids_and_user(ids, user_id).await?;
                let count = entities.len() as u64;
                (entities, count)
            }
        } else {
            self.repo.list_by_user(user_id, query.offset, limit).await?
        };

        let items = items
            .into_iter()
            .map(|e| PolicyResponse {
                policy_id: e.policy_id,
                policy_name: e.policy_name,
                policy_version: e.policy_version,
                policy_content: String::new(), // content NOT included in list
                content_type: e.content_type,
                created_at: e.created_at,
                updated_at: e.updated_at,
                applied_resources: None,
            })
            .collect();

        Ok(PolicyListResponse { items, total })
    }

    /// Get a single policy by ID with full details.
    pub async fn get_by_id(&self, ctx: &AuthContext, policy_id: &str) -> Result<PolicyResponse, PolicyError> {
        // ── step 1: permission check ──
        // TODO: auth module under active development — AuthzFacade API may change.
        self.authz.check(ctx).action(Action::Get).required_role(RequiredRole::UserScoped).ensure_allowed().await.map_err(|_| PolicyError::PermissionDenied)?;

        let user_id = ctx.sub();

        // ── step 2: execute ──
        let entity = self
            .repo
            .find_by_id(policy_id)
            .await?
            .ok_or(PolicyError::NotFound)?;

        // ownership check
        if entity.user_id != user_id {
            return Err(PolicyError::PermissionDenied);
        }

        // get applied resources
        let applied_resources = self.resource_client.relation_res_ids(policy_id, user_id).await?;

        Ok(PolicyResponse {
            policy_id: entity.policy_id,
            policy_name: entity.policy_name,
            policy_version: entity.policy_version,
            policy_content: entity.policy_content,
            content_type: entity.content_type,
            created_at: entity.created_at,
            updated_at: entity.updated_at,
            applied_resources: Some(applied_resources),
        })
    }
}

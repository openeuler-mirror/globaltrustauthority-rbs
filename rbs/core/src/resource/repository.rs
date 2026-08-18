use std::sync::Arc;
use sea_orm::*;
use super::error::ResourceError;

/// Resource entity stored in t_res_info.
#[derive(Debug, Clone)]
pub struct ResourceEntity {
    pub username: String,
    pub provider_name: String,
    pub repo_name: String,
    pub res_type: String,
    pub res_name: String,
    pub res_info: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub content_type: Option<String>,
    pub export_mode: String,
    pub policy_id: String,
}

// ── URI parsing helper ─────────────────────────────────────────────────

/// Parse URI `/rbs/v0/{provider}/{repo}/{type}/{name}` into components.
fn parse_uri(uri: &str) -> Result<(&str, &str, &str, &str), ResourceError> {
    let path = uri.trim_start_matches("/rbs/v0/");
    let parts: Vec<&str> = path.splitn(5, '/').collect();
    if parts.len() != 4 {
        return Err(ResourceError::ParamInvalid { field: "uri" });
    }
    Ok((parts[0], parts[1], parts[2], parts[3]))
}

// ── SeaORM repository ──────────────────────────────────────────────────

/// SeaORM-backed `ResourceRepository`.
pub struct SeaOrmResourceRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmResourceRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl ResourceRepository for SeaOrmResourceRepository {
    async fn insert(&self, entity: &ResourceEntity) -> Result<(), ResourceError> {
        let model = entity::ActiveModel {
            username: sea_orm::Set(entity.username.clone()),
            provider_name: sea_orm::Set(entity.provider_name.clone()),
            repo_name: sea_orm::Set(entity.repo_name.clone()),
            res_type: sea_orm::Set(entity.res_type.clone()),
            res_name: sea_orm::Set(entity.res_name.clone()),
            res_info: sea_orm::Set(entity.res_info.clone()),
            created_at: sea_orm::Set(entity.created_at),
            updated_at: sea_orm::Set(entity.updated_at),
            content_type: sea_orm::Set(entity.content_type.clone()),
            export_mode: sea_orm::Set(entity.export_mode.clone()),
            policy_id: sea_orm::Set(entity.policy_id.clone()),
        };
        sea_orm::ActiveModelTrait::insert(model, self.db.as_ref()).await
            .map_err(|e| {
                log::error!("resource db insert error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        Ok(())
    }

    async fn find_by_uri(&self, uri: &str) -> Result<Option<ResourceEntity>, ResourceError> {
        let (prov, repo, rtype, rname) = parse_uri(uri)?;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let model = entity::Entity::find()
            .filter(entity::Column::ProviderName.eq(prov))
            .filter(entity::Column::RepoName.eq(repo))
            .filter(entity::Column::ResType.eq(rtype))
            .filter(entity::Column::ResName.eq(rname))
            .one(self.db.as_ref())
            .await
            .map_err(|e| {
                log::error!("resource db find_by_uri error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        Ok(model.map(|m| ResourceEntity {
            username: m.username, provider_name: m.provider_name, repo_name: m.repo_name,
            res_type: m.res_type, res_name: m.res_name, res_info: m.res_info,
            created_at: m.created_at, updated_at: m.updated_at,
            content_type: m.content_type, export_mode: m.export_mode, policy_id: m.policy_id,
        }))
    }

    async fn update(&self, uri: &str, entity: &ResourceEntity, old_update_time: i64) -> Result<u64, ResourceError> {
        let _ = parse_uri(uri)?;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use entity::ActiveModel;
        let active = ActiveModel {
            res_info: Set(entity.res_info.clone()),
            updated_at: Set(entity.updated_at),
            content_type: Set(entity.content_type.clone()),
            export_mode: Set(entity.export_mode.clone()),
            policy_id: Set(entity.policy_id.clone()),
            ..Default::default()
        };
        let result = entity::Entity::update_many()
            .set(active)
            .filter(entity::Column::ProviderName.eq(entity.provider_name.clone()))
            .filter(entity::Column::RepoName.eq(entity.repo_name.clone()))
            .filter(entity::Column::ResType.eq(entity.res_type.clone()))
            .filter(entity::Column::ResName.eq(entity.res_name.clone()))
            .filter(entity::Column::Username.eq(entity.username.clone()))
            .filter(entity::Column::UpdatedAt.eq(old_update_time))
            .exec(self.db.as_ref())
            .await
            .map_err(|e| {
                log::error!("resource db update error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        Ok(result.rows_affected)
    }

    async fn delete(&self, uri: &str, username: &str) -> Result<u64, ResourceError> {
        let (prov, repo, rtype, rname) = parse_uri(uri)?;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let result = entity::Entity::delete_many()
            .filter(entity::Column::ProviderName.eq(prov))
            .filter(entity::Column::RepoName.eq(repo))
            .filter(entity::Column::ResType.eq(rtype))
            .filter(entity::Column::ResName.eq(rname))
            .filter(entity::Column::Username.eq(username))
            .exec(self.db.as_ref())
            .await
            .map_err(|e| {
                log::error!("resource db delete error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        Ok(result.rows_affected)
    }

    async fn list_by_user(&self, username: &str) -> Result<Vec<ResourceEntity>, ResourceError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
        let models = entity::Entity::find()
            .filter(entity::Column::Username.eq(username))
            .order_by_desc(entity::Column::CreatedAt)
            .all(self.db.as_ref())
            .await
            .map_err(|e| {
                log::error!("resource db list_by_user error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        Ok(models.into_iter().map(|m| ResourceEntity {
            username: m.username, provider_name: m.provider_name, repo_name: m.repo_name,
            res_type: m.res_type, res_name: m.res_name, res_info: m.res_info,
            created_at: m.created_at, updated_at: m.updated_at,
            content_type: m.content_type, export_mode: m.export_mode, policy_id: m.policy_id,
        }).collect())
    }

    async fn find_by_policy_id(&self, policy_id: &str) -> Result<Vec<ResourceEntity>, ResourceError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let models = entity::Entity::find()
            .filter(entity::Column::PolicyId.eq(policy_id))
            .all(self.db.as_ref())
            .await
            .map_err(|e| {
                log::error!("resource db find_by_policy_id error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        Ok(models.into_iter().map(|m| ResourceEntity {
            username: m.username, provider_name: m.provider_name, repo_name: m.repo_name,
            res_type: m.res_type, res_name: m.res_name, res_info: m.res_info,
            created_at: m.created_at, updated_at: m.updated_at,
            content_type: m.content_type, export_mode: m.export_mode, policy_id: m.policy_id,
        }).collect())
    }

    async fn count_by_user(&self, username: &str) -> Result<usize, ResourceError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let count = entity::Entity::find()
            .filter(entity::Column::Username.eq(username))
            .count(self.db.as_ref())
            .await
            .map_err(|e| {
                log::error!("resource db count_by_user error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        Ok(count as usize)
    }

    /// Atomically create a resource under the per-user limit, holding an exclusive
    /// lock on the owning user's `t_user_info` row for the whole transaction.
    ///
    /// The idempotent `UPDATE t_user_info SET updated_at = updated_at WHERE username = ?`
    /// acquires the user-row X-lock *before* the COUNT read, so on both MySQL
    /// (InnoDB REPEATABLE READ — read view established at the first consistent
    /// read, which is the COUNT after the lock is held) and SQLite (WAL single
    /// writer, busy_timeout) the COUNT sees the latest committed state and cannot
    /// race with a concurrent same-user insert. Different users lock different
    /// rows, so cross-user concurrency is unaffected.
    async fn create_with_user_limit_check(
        &self, uri: &str, entity: &ResourceEntity, max_per_user: usize,
    ) -> Result<(), ResourceError> {
        use sea_orm::{ConnectionTrait, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};

        let backend = self.db.get_database_backend();
        let txn = self.db.begin().await.map_err(|e| {
            log::error!("resource db create txn begin error: {e}");
            ResourceError::BackendError { detail: e.to_string() }
        })?;

        // 1. Acquire per-user exclusive lock (idempotent UPDATE).
        let lock_stmt = sea_orm::Statement::from_sql_and_values(
            backend,
            "UPDATE t_user_info SET updated_at = updated_at WHERE username = ?",
            [entity.username.clone().into()],
        );
        let lock_res = txn.execute(lock_stmt).await.map_err(|e| {
            log::error!("resource db create user-lock error: {e}");
            let _ = std::future::ready(()); // best-effort; rollback below
            ResourceError::BackendError { detail: e.to_string() }
        });
        if let Err(e) = lock_res {
            let _ = txn.rollback().await;
            return Err(e);
        }
        if lock_res.as_ref().unwrap().rows_affected() == 0 {
            let _ = txn.rollback().await;
            log::error!("resource create denied: owning user '{}' not found", entity.username);
            return Err(ResourceError::BackendError {
                detail: format!("owning user '{}' not found", entity.username),
            });
        }

        // 2. Duplicate check (same 4-column semantics as find_by_uri).
        let (prov, repo, rtype, rname) = parse_uri(uri)?;
        let dup = entity::Entity::find()
            .filter(entity::Column::ProviderName.eq(prov))
            .filter(entity::Column::RepoName.eq(repo))
            .filter(entity::Column::ResType.eq(rtype))
            .filter(entity::Column::ResName.eq(rname))
            .one(&txn)
            .await
            .map_err(|e| {
                log::error!("resource db create dup-check error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        if dup.is_some() {
            let _ = txn.rollback().await;
            log::error!("Resource create denied: uri '{}' already exists", uri);
            return Err(ResourceError::AlreadyExists { uri: uri.to_string() });
        }

        // 3. Count check (lock already held → sees latest committed rows).
        let count = entity::Entity::find()
            .filter(entity::Column::Username.eq(entity.username.clone()))
            .count(&txn)
            .await
            .map_err(|e| {
                log::error!("resource db create count error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        if count as usize >= max_per_user {
            let _ = txn.rollback().await;
            log::error!(
                "Resource create denied: count {} exceeds max {} for user '{}'",
                count, max_per_user, entity.username
            );
            return Err(ResourceError::CountExceed { max: max_per_user, current: count as usize });
        }

        // 4. Insert (within the same transaction).
        let model = entity::ActiveModel {
            username: sea_orm::Set(entity.username.clone()),
            provider_name: sea_orm::Set(entity.provider_name.clone()),
            repo_name: sea_orm::Set(entity.repo_name.clone()),
            res_type: sea_orm::Set(entity.res_type.clone()),
            res_name: sea_orm::Set(entity.res_name.clone()),
            res_info: sea_orm::Set(entity.res_info.clone()),
            created_at: sea_orm::Set(entity.created_at),
            updated_at: sea_orm::Set(entity.updated_at),
            content_type: sea_orm::Set(entity.content_type.clone()),
            export_mode: sea_orm::Set(entity.export_mode.clone()),
            policy_id: sea_orm::Set(entity.policy_id.clone()),
        };
        sea_orm::ActiveModelTrait::insert(model, &txn).await.map_err(|e| {
            log::error!("resource db create insert error: {e}");
            ResourceError::BackendError { detail: e.to_string() }
        })?;

        txn.commit().await.map_err(|e| {
            log::error!("resource db create txn commit error: {e}");
            ResourceError::BackendError { detail: e.to_string() }
        })?;
        Ok(())
    }
}


/// ResourceRepository trait - data access for resource metadata.
#[async_trait::async_trait]
pub trait ResourceRepository: Send + Sync {
    async fn insert(&self, entity: &ResourceEntity) -> Result<(), ResourceError>;
    async fn find_by_uri(&self, uri: &str) -> Result<Option<ResourceEntity>, ResourceError>;
    async fn update(&self, uri: &str, entity: &ResourceEntity, old_update_time: i64) -> Result<u64, ResourceError>;
    async fn delete(&self, uri: &str, username: &str) -> Result<u64, ResourceError>;
    async fn list_by_user(&self, username: &str) -> Result<Vec<ResourceEntity>, ResourceError>;
    async fn count_by_user(&self, username: &str) -> Result<usize, ResourceError>;
    async fn create_with_user_limit_check(
        &self, uri: &str, entity: &ResourceEntity, max_per_user: usize,
    ) -> Result<(), ResourceError>;
    async fn find_by_policy_id(&self, policy_id: &str) -> Result<Vec<ResourceEntity>, ResourceError>;
}

// ── SeaORM entity definition for t_res_info ────────────────────────────

pub(crate) mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_res_info")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub username: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub provider_name: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub repo_name: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub res_type: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub res_name: String,
        pub res_info: Option<String>,
        pub created_at: i64,
        pub updated_at: i64,
        pub content_type: Option<String>,
        pub export_mode: String,
        pub policy_id: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

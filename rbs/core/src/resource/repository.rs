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
            .map_err(|e| ResourceError::BackendError { detail: e.to_string() })?;
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
            .map_err(|e| ResourceError::BackendError { detail: e.to_string() })?;
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
            .map_err(|e| ResourceError::BackendError { detail: e.to_string() })?;
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
            .map_err(|e| ResourceError::BackendError { detail: e.to_string() })?;
        Ok(result.rows_affected)
    }

    async fn list_by_user(&self, username: &str) -> Result<Vec<ResourceEntity>, ResourceError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
        let models = entity::Entity::find()
            .filter(entity::Column::Username.eq(username))
            .order_by_desc(entity::Column::CreatedAt)
            .all(self.db.as_ref())
            .await
            .map_err(|e| ResourceError::BackendError { detail: e.to_string() })?;
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
            .map_err(|e| ResourceError::BackendError { detail: e.to_string() })?;
        Ok(models.into_iter().map(|m| ResourceEntity {
            username: m.username, provider_name: m.provider_name, repo_name: m.repo_name,
            res_type: m.res_type, res_name: m.res_name, res_info: m.res_info,
            created_at: m.created_at, updated_at: m.updated_at,
            content_type: m.content_type, export_mode: m.export_mode, policy_id: m.policy_id,
        }).collect())
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

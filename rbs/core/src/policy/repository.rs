use std::sync::Arc;
use sea_orm::*;
use super::error::PolicyError;

/// Policy entity as stored in the database.
#[derive(Debug, Clone)]
pub struct PolicyEntity {
    pub policy_id: String,
    pub user_id: String,
    pub policy_name: String,
    pub policy_version: i32,
    pub policy_content: String,
    pub content_type: String,
    pub created_at: i64,
    pub updated_at: i64,
}

// ── PolicyRepository trait ────────────────────────────────────────────

/// Policy repository trait - abstract data access layer.
/// Service depends on this trait, not concrete DB implementation.
#[async_trait::async_trait]
pub trait PolicyRepository: Send + Sync {
    async fn insert(&self, entity: PolicyEntity) -> Result<(), PolicyError>;
    async fn find_by_id(&self, policy_id: &str) -> Result<Option<PolicyEntity>, PolicyError>;
    async fn find_by_name_and_user(&self, name: &str, user_id: &str) -> Result<Option<PolicyEntity>, PolicyError>;
    async fn find_by_ids_and_user(&self, policy_ids: &[String], user_id: &str) -> Result<Vec<PolicyEntity>, PolicyError>;
    async fn list_by_user(&self, user_id: &str, offset: i64, limit: i64) -> Result<(Vec<PolicyEntity>, u64), PolicyError>;
    async fn count_by_user(&self, user_id: &str) -> Result<usize, PolicyError>;
    async fn update_with_version(&self, policy_id: &str, expected_version: i32, entity: PolicyEntity) -> Result<u64, PolicyError>;
    /// Delete by IDs and user within a transaction.
    async fn delete_by_ids_txn(&self, conn: &sea_orm::DatabaseTransaction, policy_ids: &[String], user_id: &str) -> Result<u64, PolicyError>;
    async fn delete(&self, policy_id: &str) -> Result<(), PolicyError>;
    /// Get a reference to the underlying database connection for transactions.
    fn db_connection(&self) -> &sea_orm::DatabaseConnection;
}

// ── SeaORM repository ──────────────────────────────────────────────────

/// SeaORM-backed `PolicyRepository`.
pub struct SeaOrmPolicyRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmPolicyRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl PolicyRepository for SeaOrmPolicyRepository {
    async fn insert(&self, entity: PolicyEntity) -> Result<(), PolicyError> {
        let model = entity::ActiveModel {
            policy_id: sea_orm::Set(entity.policy_id),
            user_id: sea_orm::Set(entity.user_id),
            policy_name: sea_orm::Set(entity.policy_name),
            policy_version: sea_orm::Set(entity.policy_version),
            policy_content: sea_orm::Set(entity.policy_content),
            content_type: sea_orm::Set(entity.content_type),
            created_at: sea_orm::Set(entity.created_at),
            updated_at: sea_orm::Set(entity.updated_at),
        };
        sea_orm::ActiveModelTrait::insert(model, self.db.as_ref()).await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        Ok(())
    }

    async fn find_by_id(&self, policy_id: &str) -> Result<Option<PolicyEntity>, PolicyError> {
        let model = entity::Entity::find_by_id(policy_id)
            .one(self.db.as_ref())
            .await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        Ok(model.map(|m| PolicyEntity {
            policy_id: m.policy_id, user_id: m.user_id, policy_name: m.policy_name,
            policy_version: m.policy_version, policy_content: m.policy_content,
            content_type: m.content_type, created_at: m.created_at, updated_at: m.updated_at,
        }))
    }

    async fn find_by_name_and_user(&self, name: &str, user_id: &str) -> Result<Option<PolicyEntity>, PolicyError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let model = entity::Entity::find()
            .filter(entity::Column::PolicyName.eq(name))
            .filter(entity::Column::UserId.eq(user_id))
            .one(self.db.as_ref())
            .await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        Ok(model.map(|m| PolicyEntity {
            policy_id: m.policy_id, user_id: m.user_id, policy_name: m.policy_name,
            policy_version: m.policy_version, policy_content: m.policy_content,
            content_type: m.content_type, created_at: m.created_at, updated_at: m.updated_at,
        }))
    }

    async fn find_by_ids_and_user(&self, policy_ids: &[String], user_id: &str) -> Result<Vec<PolicyEntity>, PolicyError> {
        if policy_ids.is_empty() { return Ok(vec![]); }
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let models = entity::Entity::find()
            .filter(entity::Column::PolicyId.is_in(policy_ids.iter().cloned()))
            .filter(entity::Column::UserId.eq(user_id))
            .all(self.db.as_ref())
            .await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        Ok(models.into_iter().map(|m| PolicyEntity {
            policy_id: m.policy_id, user_id: m.user_id, policy_name: m.policy_name,
            policy_version: m.policy_version, policy_content: m.policy_content,
            content_type: m.content_type, created_at: m.created_at, updated_at: m.updated_at,
        }).collect())
    }

    async fn list_by_user(&self, user_id: &str, offset: i64, limit: i64) -> Result<(Vec<PolicyEntity>, u64), PolicyError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
        let total = entity::Entity::find()
            .filter(entity::Column::UserId.eq(user_id))
            .count(self.db.as_ref())
            .await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        let models = entity::Entity::find()
            .filter(entity::Column::UserId.eq(user_id))
            .order_by_asc(entity::Column::CreatedAt)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db.as_ref())
            .await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        Ok((models.into_iter().map(|m| PolicyEntity {
            policy_id: m.policy_id, user_id: m.user_id, policy_name: m.policy_name,
            policy_version: m.policy_version, policy_content: m.policy_content,
            content_type: m.content_type, created_at: m.created_at, updated_at: m.updated_at,
        }).collect(), total))
    }

    async fn count_by_user(&self, user_id: &str) -> Result<usize, PolicyError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let count = entity::Entity::find()
            .filter(entity::Column::UserId.eq(user_id))
            .count(self.db.as_ref())
            .await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        Ok(count as usize)
    }

    async fn update_with_version(&self, policy_id: &str, expected_version: i32, entity: PolicyEntity) -> Result<u64, PolicyError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use sea_orm::sea_query::Expr;
        let active = entity::ActiveModel {
            policy_name: Set(entity.policy_name.clone()),
            policy_content: Set(entity.policy_content.clone()),
            content_type: Set(entity.content_type.clone()),
            updated_at: Set(entity.updated_at),
            ..Default::default()
        };
        let result = entity::Entity::update_many()
            .set(active)
            .col_expr(entity::Column::PolicyVersion, Expr::col(entity::Column::PolicyVersion).add(1))
            .filter(entity::Column::PolicyId.eq(policy_id))
            .filter(entity::Column::PolicyVersion.eq(expected_version))
            .exec(self.db.as_ref())
            .await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        Ok(result.rows_affected)
    }

    async fn delete_by_ids_txn(&self, conn: &sea_orm::DatabaseTransaction, policy_ids: &[String], user_id: &str) -> Result<u64, PolicyError> {
        if policy_ids.is_empty() { return Ok(0); }
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let result = entity::Entity::delete_many()
            .filter(entity::Column::PolicyId.is_in(policy_ids.iter().cloned()))
            .filter(entity::Column::UserId.eq(user_id))
            .exec(conn)
            .await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        Ok(result.rows_affected)
    }

    fn db_connection(&self) -> &sea_orm::DatabaseConnection { &self.db }

    async fn delete(&self, policy_id: &str) -> Result<(), PolicyError> {
        use sea_orm::EntityTrait;
        entity::Entity::delete_by_id(policy_id)
            .exec(self.db.as_ref())
            .await
            .map_err(|_| PolicyError::ParamInvalid { field: "db" })?;
        Ok(())
    }

}

// ── SeaORM entity definition for t_res_policy ──────────────────────────

pub(crate) mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_res_policy")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub policy_id: String,
        pub user_id: String,
        pub policy_name: String,
        pub policy_version: i32,
        pub policy_content: String,
        pub content_type: String,
        pub created_at: i64,
        pub updated_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

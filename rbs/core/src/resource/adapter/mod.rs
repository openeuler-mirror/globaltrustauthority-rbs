use super::error::ResourceError;
use std::sync::Arc;
use zeroize::Zeroizing;

pub mod vault;
pub use vault::VaultBackend;

/// Trait for backend storage providers.
#[async_trait::async_trait]
pub trait ResourceBackend: Send + Sync {
    async fn check_resource_exists(&self, uri: &str) -> Result<bool, ResourceError>;
    async fn get_resource_content(&self, uri: &str) -> Result<Zeroizing<Vec<u8>>, ResourceError>;
}

/// BackendProvider routes res_provider to the correct backend adapter.
#[derive(Clone)]
pub struct BackendProvider {
    backends: std::collections::HashMap<String, Arc<dyn ResourceBackend>>,
}

impl BackendProvider {
    pub fn new() -> Self {
        Self { backends: std::collections::HashMap::new() }
    }

    pub fn register(&mut self, name: &str, backend: Arc<dyn ResourceBackend>) {
        self.backends.insert(name.to_string(), backend);
    }

    pub fn get_backend(&self, provider_name: &str) -> Option<Arc<dyn ResourceBackend>> {
        self.backends.get(provider_name).cloned()
    }
}

impl Default for BackendProvider {
    fn default() -> Self {
        Self::new()
    }
}

use sea_orm::{DatabaseConnection};

/// Real `PolicyClient` backed by the database.
/// Bridges `ResourceService` ↔ policy data without a dependency on `PolicyService`.
pub struct DbPolicyClient {
    pub db: Arc<DatabaseConnection>,
}

impl DbPolicyClient {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl PolicyClient for DbPolicyClient {
    async fn validate_policy(&self, policy_id: &str, username: &str) -> Result<bool, ResourceError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use crate::policy::repository::entity;
        let exists = entity::Entity::find()
            .filter(entity::Column::PolicyId.eq(policy_id.to_owned()))
            .filter(entity::Column::Username.eq(username.to_owned()))
            .one(self.db.as_ref())
            .await
            .map_err(|e| {
                log::error!("DbPolicyClient validate_policy db error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        log::info!("DbPolicyClient validate_policy: policy_id='{}', user='{}', valid={}", policy_id, username, exists.is_some());
        Ok(exists.is_some())
    }

    async fn get_policy_content(&self, policy_id: &str) -> Result<String, ResourceError> {
        use sea_orm::EntityTrait;
        use crate::policy::repository::entity;
        let model = entity::Entity::find_by_id(policy_id)
            .one(self.db.as_ref())
            .await
            .map_err(|e| {
                log::error!("DbPolicyClient get_policy_content db error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?
            .ok_or_else(|| {
                log::error!("DbPolicyClient get_policy_content: policy '{}' not found", policy_id);
                ResourceError::PolicyIdInvalid(policy_id.to_string())
            })?;
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(&model.policy_content)
            .map_err(|e| {
                log::error!("DbPolicyClient get_policy_content base64 decode error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        String::from_utf8(decoded)
            .map_err(|e| {
                log::error!("DbPolicyClient get_policy_content utf8 decode error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })
    }

    async fn relation_res_ids(&self, policy_id: &str, _username: &str) -> Result<Vec<String>, ResourceError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
        use crate::resource::repository::entity;
        let rows = entity::Entity::find()
            .select_only()
            .column(entity::Column::ProviderName)
            .column(entity::Column::RepoName)
            .column(entity::Column::ResType)
            .column(entity::Column::ResName)
            .filter(entity::Column::PolicyId.eq(policy_id.to_owned()))
            .into_tuple::<(String, String, String, String)>()
            .all(self.db.as_ref())
            .await
            .map_err(|e| {
                log::error!("DbPolicyClient relation_res_ids db error: {e}");
                ResourceError::BackendError { detail: e.to_string() }
            })?;
        let ids: Vec<String> = rows.into_iter()
            .map(|(prov, repo, rtype, rname)| format!("/rbs/v0/{}/{}/{}/{}", prov, repo, rtype, rname))
            .collect();
        log::info!("DbPolicyClient relation_res_ids: policy_id='{}', found {} related resource(s)", policy_id, ids.len());
        Ok(ids)
    }
}

/// PolicyClient trait - isolates calls to the policy management module.
#[async_trait::async_trait]
pub trait PolicyClient: Send + Sync {
    async fn validate_policy(&self, policy_id: &str, username: &str) -> Result<bool, ResourceError>;

    async fn get_policy_content(&self, policy_id: &str) -> Result<String, ResourceError>;

    async fn relation_res_ids(&self, policy_id: &str, username: &str) -> Result<Vec<String>, ResourceError>;
}

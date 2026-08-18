use super::error::ResourceError;
use bitflags::bitflags;
use rbs_api_types::{GetResourceOptions, ResourceDesc};
use std::sync::Arc;
use zeroize::Zeroizing;

pub mod vault;
pub use vault::VaultBackend;

pub mod ca;
pub use ca::CABackend;

pub mod hsm;
pub use hsm::HsmBackend;

/// Capability flags advertised by a `ResourceBackend`.
///
/// `get_resource_content` (read) is always required and is not a capability.
/// Reading never appears in the bitfield — every backend must support reads.
bitflags! {
    /// Optional `ResourceBackend` operations gated by capability.
    ///
    /// Aligned with `module_interfaces.md` §3.2: read is mandatory (not a flag);
    /// `PUT` / `DELETE` / `CHECK` are optional and declared per backend.
    #[allow(unused_doc_comments)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct BackendCapabilities: u8 {
        /// Backend can write/replace resource content (`put_resource_content`).
        const PUT = 1 << 0;
        /// Backend can destroy a resource (`delete_resource`).
        const DELETE = 1 << 1;
        /// Backend can report whether a resource already exists
        /// (`check_resource_exists`).
        const CHECK = 1 << 2;
    }
}

/// Trait for backend storage providers.
///
/// `get_resource_content` is the only mandatory method (read). The optional
/// write/delete/check methods are gated by `capabilities()`: the
/// `ResourceService` inspects the bitfield and only invokes a method whose
/// bit is set, so a backend that does not support an operation should leave
/// its bit clear and rely on the default (which returns
/// `ResourceError::BackendOperationUnsupported`).
///
/// Aligned with `module_interfaces.md` §3.2 — capability-bit gating, not the
/// old `create_resource` / `update_resource` two-method form.
#[async_trait::async_trait]
pub trait ResourceBackend: Send + Sync {
    /// Report the optional operations this backend supports.
    fn capabilities(&self) -> BackendCapabilities;

    /// Read resource content. Required for every backend.
    /// CA backends issue a certificate on demand using `opts.csr_der`;
    /// Vault/HSM backends ignore `opts.csr_der`.
    async fn get_resource_content(
        &self,
        desc: &ResourceDesc,
        opts: GetResourceOptions,
    ) -> Result<Zeroizing<Vec<u8>>, ResourceError>;

    /// Write/replace resource content. Only called when `PUT` is declared.
    /// HSM: import/replace key material. Default returns unsupported.
    async fn put_resource_content(
        &self,
        _desc: &ResourceDesc,
        _data: &[u8],
    ) -> Result<(), ResourceError> {
        Err(ResourceError::BackendOperationUnsupported)
    }

    /// Destroy a resource. Only called when `DELETE` is declared.
    /// Should be idempotent (Ok when the object is already gone).
    /// Default returns unsupported.
    async fn delete_resource(&self, _desc: &ResourceDesc) -> Result<(), ResourceError> {
        Err(ResourceError::BackendOperationUnsupported)
    }

    /// Report whether a resource already exists. Only called when `CHECK` is
    /// declared. Used by Vault-style backends to validate a referenced secret
    /// exists before registering metadata. Default returns unsupported.
    async fn check_resource_exists(&self, _desc: &ResourceDesc) -> Result<bool, ResourceError> {
        Err(ResourceError::BackendOperationUnsupported)
    }
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

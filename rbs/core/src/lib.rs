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

//! RBS core library.

pub mod admin;
mod attestation;
pub mod auth;
mod infra;
pub mod policy;
pub mod policy_engine;
pub mod resource;

use std::sync::Arc;

pub mod system;

pub use admin::AdminManager;
pub use attestation::{AttestationManager, AttestationProvider, BuiltinAttestationProvider, GtaRestProvider};
pub use auth::{
    Action, Auth, AuthContext, Authenticator, AuthzChecker, AuthzCheckerImpl,
    AuthzError, AuthzFacade, AttestContext, BearerContext, RequiredRole,
    TokenType, AuthError, UserKeyProvider,
};
pub use policy::{
    PolicyConfig, PolicyEntity, PolicyError, PolicyRepository, PolicyService, PolicyValidator,
    SeaOrmPolicyRepository,
};
pub use resource::{
    CreateResourceRequest, ResourceConfig, ResourceContentResponse, ResourceEntity, ResourceError,
    ResourceInfoResponse, ResourceRepository, ResourceResponse, ResourceService,
    SeaOrmResourceRepository, ResourceValidator, UpdateResourceRequest,
};
pub use resource::adapter::{BackendProvider, DbPolicyClient, VaultBackend};
pub use infra::logging::init_logging;
pub use infra::init_database;
pub use infra::rdb;
pub use rbs_api_types::config::{
    AdminConfig, AdminKeyConfig, AttestationBackendConfig, AttestationBackendMode, AttestationConfig,
    AttestationRestConfig, AuthConfig, CoreConfig, LogRotationConfig, LoggingConfig,
    RotationCompression,
};
pub use rbs_api_types::error::RbsError;
pub use system::{BuildMetadata, RbsVersion, API_VERSION, SERVICE_NAME};

/// Core runtime handle.
pub struct RbsCore {
    attestation: AttestationManager,
    resource: ResourceService,
    policy: PolicyService,
    admin: AdminManager,
}

impl std::fmt::Debug for RbsCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RbsCore")
            .field("attestation", &self.attestation)
            .finish()
    }
}

impl RbsCore {
    #[must_use]
    pub fn new(
        attestation: AttestationManager,
        resource: ResourceService,
        policy: PolicyService,
        admin: AdminManager,
    ) -> Self {
        Self { attestation, resource, policy, admin }
    }

    #[must_use]
    pub fn attestation(&self) -> &AttestationManager { &self.attestation }

    #[must_use]
    pub fn resource(&self) -> &ResourceService { &self.resource }

    #[must_use]
    pub fn policy(&self) -> &PolicyService { &self.policy }

    #[must_use]
    pub fn admin(&self) -> &AdminManager { &self.admin }

    #[must_use]
    pub fn system(&self) -> System { System }
}

/// Builder for constructing `RbsCore` from configuration.
pub struct RbsCoreBuilder {
    config: CoreConfig,
}

impl RbsCoreBuilder {
    #[must_use]
    pub fn new(config: CoreConfig) -> Self { Self { config } }

    #[must_use]
    pub fn build(self) -> RbsCore {
        let mut attestation = AttestationManager::new();
        attestation.set_default(&self.config.attestation.default_as_provider);

        for (name, backend_config) in &self.config.attestation.backends {
            let provider: Arc<dyn AttestationProvider> = match backend_config.mode {
                AttestationBackendMode::Builtin => {
                    Arc::new(BuiltinAttestationProvider::default()) as Arc<dyn AttestationProvider>
                }
                AttestationBackendMode::Rest => {
                    Arc::new(GtaRestProvider::new(backend_config.rest.clone())) as Arc<dyn AttestationProvider>
                }
            };
            attestation.register(name, provider);
        }

        let engine = Arc::new(policy_engine::RealPolicyEngine);
        let authz_facade = AuthzFacade::new(engine.clone());
        let authz: Arc<dyn AuthzChecker> = Arc::new(AuthzCheckerImpl::new(engine.clone()));

        let policy_config = PolicyConfig::default();
        let policy_validator = PolicyValidator::new(policy_config.clone());
        let db = infra::rdb::get_connection_from_pool()
            .expect("database connection pool must be initialized before building RbsCore");
        let policy_repo: Arc<dyn PolicyRepository> = Arc::new(SeaOrmPolicyRepository::new(db.clone()));
        let resource_repo: Arc<dyn ResourceRepository> = Arc::new(SeaOrmResourceRepository::new(db.clone()));
        let policy_client: Arc<dyn resource::adapter::PolicyClient> = Arc::new(DbPolicyClient::new(db));
        let policy = PolicyService::new(policy_repo, authz_facade.clone(), policy_client.clone(), policy_validator, policy_config);

        let mut resource_config = ResourceConfig::default();
        let mut backend_provider = BackendProvider::default();
        // Register resource backends from config
        if let Some(ref rp_config) = self.config.resource {
            resource_config.configured_backends = rp_config.backends.keys().cloned().collect();
            for (name, backend_cfg) in &rp_config.backends {
                if backend_cfg.backend_type == "vault" {
                    let vault = resource::adapter::VaultBackend::new(
                        backend_cfg.url.clone(),
                        backend_cfg.token.clone(),
                        backend_cfg.mount_path.clone(),
                        backend_cfg.kv_version.clone(),
                    );
                    backend_provider.register(name, Arc::new(vault));
                    log::info!("Registered resource backend '{}' (type=vault, url={})",
                        name, backend_cfg.url);
                } else {
                    log::warn!("Unknown resource backend type '{}' for backend '{}'",
                        backend_cfg.backend_type, name);
                }
            }
        }
        let resource_validator = ResourceValidator::new(resource_config);
        let resource = ResourceService::new(
            resource_repo, authz, backend_provider, policy_client.clone(), resource_validator,
        );

        let admin = AdminManager::new(self.config.admin, authz_facade.clone());

        RbsCore::new(attestation, resource, policy, admin)
    }
}

impl Default for RbsCore {
    fn default() -> Self {
        let engine = Arc::new(policy_engine::RealPolicyEngine);
        let authz_facade = AuthzFacade::new(engine.clone());
        let authz: Arc<dyn AuthzChecker> = Arc::new(AuthzCheckerImpl::new(engine.clone()));

        // Spawn a fresh OS thread so that block_on is allowed even when
        // Default is called from within an existing tokio runtime.
        let db = std::thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(async {
                let conn = sea_orm::Database::connect("sqlite::memory:").await.expect("sqlite");
                crate::infra::rdb::migrate_core_tables(&conn).await.expect("migrate");
                Arc::new(conn)
            })
        }).join().expect("db init thread");

        let policy_repo: Arc<dyn PolicyRepository> = Arc::new(SeaOrmPolicyRepository::new(db.clone()));
        let resource_repo: Arc<dyn ResourceRepository> = Arc::new(SeaOrmResourceRepository::new(db.clone()));
        let policy_client: Arc<dyn resource::adapter::PolicyClient> = Arc::new(DbPolicyClient::new(db));

        let policy = PolicyService::new(
            policy_repo, authz_facade.clone(), policy_client.clone(),
            PolicyValidator::new(PolicyConfig::default()), PolicyConfig::default(),
        );
        let resource = ResourceService::new(
            resource_repo, authz, BackendProvider::new(),
            policy_client, ResourceValidator::new(ResourceConfig::default()),
        );
        RbsCore::new(AttestationManager::default(), resource, policy, AdminManager::new(AdminConfig::default(), authz_facade))
    }
}

/// System-scoped operations (version, etc.).
#[derive(Debug, Clone, Copy, Default)]
pub struct System;

impl System {
    #[must_use]
    pub fn version(&self) -> RbsVersion { system::get_rbs_version() }
}

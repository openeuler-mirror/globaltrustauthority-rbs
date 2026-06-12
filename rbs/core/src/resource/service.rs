use chrono::Timelike;
use std::sync::Arc;

use base64::Engine;
use zeroize::Zeroize;
use crate::auth::authz::{Action, RequiredRole};
use crate::auth::authz_checker::AuthzChecker;
use crate::auth::context::{AttestContext, AuthContext};

use super::adapter::{BackendProvider, PolicyClient};
use super::error::ResourceError;
use super::repository::ResourceRepository;
use super::validator::ResourceValidator;
use super::{
    CreateResourceRequest, ResourceContentResponse, ResourceResponse,
    UpdateResourceRequest, ATTEST_TEE_PUBKEY_KEY, BEARER_ENC_PUBKEY_KEY,
};

/// ResourceService - single struct holding all dependencies.
pub struct ResourceService {
    pub repo: Arc<dyn ResourceRepository>,
    pub authz: Arc<dyn AuthzChecker>,
    pub backend_provider: BackendProvider,
    pub policy_client: Arc<dyn PolicyClient>,
    pub validator: ResourceValidator,
}

fn millis_to_rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|dt| dt.with_nanosecond(0).unwrap_or(dt).to_rfc3339())
        .unwrap_or_default()
}

impl ResourceService {
    pub fn new(
        repo: Arc<dyn ResourceRepository>,
        authz: Arc<dyn AuthzChecker>,
        backend_provider: BackendProvider,
        policy_client: Arc<dyn PolicyClient>,
        validator: ResourceValidator,
    ) -> Self {
        Self { repo, authz, backend_provider, policy_client, validator }
    }

    // ── POST - create ─────────────────────────────────────────────────

    pub async fn create(
        &self, ctx: &AuthContext, req: &CreateResourceRequest,
    ) -> Result<ResourceResponse, ResourceError> {
        log::info!("Resource create requested: uri={}, user={}", req.uri, ctx.sub());

        self.authz.check_action(ctx, Action::Create, RequiredRole::UserScoped).await.map_err(|_| {
            log::error!("Resource create denied: permission denied for user '{}'", ctx.sub());
            ResourceError::PermissionDenied
        })?;

        let parsed = self.validator.validate_uri(&req.uri).map_err(|e| {
            log::error!("Resource create denied: URI validation failed: {}", e);
            e
        })?;
        if req.policy_id.is_empty() {
            log::error!("Resource create denied: empty policy_id");
            return Err(ResourceError::ParamInvalid { field: "policy_id" });
        }
        if let Some(ref ct) = req.content_type { self.validator.validate_content_type(ct).map_err(|e| { log::error!("Resource create denied: {}", e); e })?; }
        if let Some(ref em) = req.export_mode { self.validator.validate_export_mode(em).map_err(|e| { log::error!("Resource create denied: {}", e); e })?; }
        self.validator.validate_additional_info(req.additional_info.as_deref()).map_err(|e| { log::error!("Resource create denied: {}", e); e })?;

        let username = ctx.sub();
        let valid = self.policy_client.validate_policy(&req.policy_id, username).await?;
        if !valid {
            log::error!("Resource create denied: policy_id '{}' invalid for user '{}'", req.policy_id, username);
            return Err(ResourceError::PolicyIdInvalid(req.policy_id.clone()));
        }

        let backend = self.backend_provider.get_backend(&parsed.res_provider)
            .ok_or_else(|| {
                log::error!("Resource create failed: backend '{}' not found", parsed.res_provider);
                ResourceError::BackendUnsupported { provider: parsed.res_provider.clone() }
            })?;
        if !backend.check_resource_exists(&req.uri).await? {
            log::error!("Resource create denied: resource '{}' not found in backend", req.uri);
            return Err(ResourceError::BackendNotFound);
        }

        if self.repo.find_by_uri(&req.uri).await?.is_some() {
            log::error!("Resource create denied: uri '{}' already exists", req.uri);
            return Err(ResourceError::AlreadyExists { uri: req.uri.clone() });
        }

        let now = chrono::Utc::now().timestamp_millis();
        let entity = super::repository::ResourceEntity {
            username: username.to_string(), provider_name: parsed.res_provider,
            repo_name: parsed.repository_name, res_type: parsed.resource_type,
            res_name: parsed.resource_name, res_info: req.additional_info.clone(),
            created_at: now, updated_at: now, content_type: req.content_type.clone(),
            export_mode: req.export_mode.clone().unwrap_or_else(|| "jwe".to_string()),
            policy_id: req.policy_id.clone(),
        };
        self.repo.insert(&entity).await?;
        log::info!("Resource created: uri='{}', user='{}', policy_id='{}'", req.uri, username, req.policy_id);
        Ok(ResourceResponse {
            uri: req.uri.clone(), provider_name: entity.provider_name,
            repository_name: entity.repo_name,
            resource_type: entity.res_type, resource_name: entity.res_name,
            created_at: millis_to_rfc3339(entity.created_at), updated_at: millis_to_rfc3339(entity.updated_at),
            content_type: entity.content_type, export_mode: entity.export_mode,
            policy_id: entity.policy_id,
            additional_info: entity.res_info,
        })
    }

    // ── PUT - update ──────────────────────────────────────────────────

    /// Returns `(response, created)` — `created: true` when a new resource was inserted.
    pub async fn update(
        &self, ctx: &AuthContext, uri: &str, req: &UpdateResourceRequest,
    ) -> Result<(ResourceResponse, bool), ResourceError> {
        log::info!("Resource update requested: uri={}, user={}", uri, ctx.sub());

        self.authz.check_action(ctx, Action::Update, RequiredRole::UserScoped).await.map_err(|_| {
            log::error!("Resource update denied: permission denied for user '{}'", ctx.sub());
            ResourceError::PermissionDenied
        })?;

        let parsed = self.validator.validate_uri(uri).map_err(|e| {
            log::error!("Resource update denied: URI validation failed: {}", e);
            e
        })?;
        if req.policy_id.is_empty() {
            log::error!("Resource update denied: empty policy_id");
            return Err(ResourceError::ParamInvalid { field: "policy_id" });
        }
        if let Some(ref ct) = req.content_type { self.validator.validate_content_type(ct).map_err(|e| { log::error!("Resource update denied: {}", e); e })?; }
        if let Some(ref em) = req.export_mode { self.validator.validate_export_mode(em).map_err(|e| { log::error!("Resource update denied: {}", e); e })?; }
        self.validator.validate_additional_info(req.additional_info.as_deref()).map_err(|e| { log::error!("Resource update denied: {}", e); e })?;
        let username = ctx.sub();

        // ── step 2b: policy and backend check (for both create and update) ──
        let valid = self.policy_client.validate_policy(&req.policy_id, username).await?;
        if !valid {
            log::error!("Resource update denied: policy_id '{}' invalid for user '{}'", req.policy_id, username);
            return Err(ResourceError::PolicyIdInvalid(req.policy_id.clone()));
        }
        let backend = self.backend_provider.get_backend(&parsed.res_provider)
            .ok_or_else(|| {
                log::error!("Resource update failed: backend '{}' not found", parsed.res_provider);
                ResourceError::BackendUnsupported { provider: parsed.res_provider.clone() }
            })?;
        if !backend.check_resource_exists(uri).await? {
            log::error!("Resource update denied: resource '{}' not found in backend", uri);
            return Err(ResourceError::BackendNotFound);
        }

        let existing = self.repo.find_by_uri(uri).await?;
        let now = chrono::Utc::now().timestamp_millis();

        if let Some(existing_entity) = existing {
            if existing_entity.username != username {
                log::error!("Resource update denied: user '{}' cannot update resource '{}' owned by '{}'", username, uri, existing_entity.username);
                return Err(ResourceError::PermissionDenied);
            }
            let updated = super::repository::ResourceEntity {
                username: existing_entity.username, provider_name: existing_entity.provider_name,
                repo_name: existing_entity.repo_name, res_type: existing_entity.res_type,
                res_name: existing_entity.res_name,
                res_info: req.additional_info.clone().or(existing_entity.res_info),
                created_at: existing_entity.created_at, updated_at: now,
                content_type: req.content_type.clone().or(existing_entity.content_type),
                export_mode: req.export_mode.clone().unwrap_or(existing_entity.export_mode),
                policy_id: req.policy_id.clone(),
            };
            let old_update_time = existing_entity.updated_at;
            let affected = self.repo.update(uri, &updated, old_update_time).await?;
            if affected == 0 {
                log::error!("Resource update conflict: uri='{}', expected version mismatch", uri);
                return Err(ResourceError::VersionConflict);
            }
            log::info!("Resource updated: uri='{}', user='{}'", uri, username);
            Ok((ResourceResponse { uri: uri.to_string(), provider_name: updated.provider_name, repository_name: updated.repo_name, resource_type: updated.res_type, resource_name: updated.res_name, created_at: millis_to_rfc3339(updated.created_at), updated_at: millis_to_rfc3339(updated.updated_at), content_type: updated.content_type, export_mode: updated.export_mode, policy_id: updated.policy_id, additional_info: updated.res_info }, false))
        } else {
            let entity = super::repository::ResourceEntity {
                username: username.to_string(), provider_name: parsed.res_provider,
                repo_name: parsed.repository_name, res_type: parsed.resource_type,
                res_name: parsed.resource_name, res_info: req.additional_info.clone(),
                created_at: now, updated_at: now, content_type: req.content_type.clone(),
                export_mode: req.export_mode.clone().unwrap_or_else(|| "jwe".to_string()),
                policy_id: req.policy_id.clone(),
            };
            self.repo.insert(&entity).await?;
            log::info!("Resource created via update: uri='{}', user='{}', policy_id='{}'", uri, username, req.policy_id);
            Ok((ResourceResponse { uri: uri.to_string(), provider_name: entity.provider_name, repository_name: entity.repo_name, resource_type: entity.res_type, resource_name: entity.res_name, created_at: millis_to_rfc3339(entity.created_at), updated_at: millis_to_rfc3339(entity.updated_at), content_type: entity.content_type, export_mode: entity.export_mode, policy_id: entity.policy_id, additional_info: entity.res_info }, true))
        }
    }

    // ── DELETE ─────────────────────────────────────────────────────────

    pub async fn delete(&self, ctx: &AuthContext, uri: &str) -> Result<(), ResourceError> {
        log::info!("Resource delete requested: uri={}, user={}", uri, ctx.sub());

        self.authz.check_action(ctx, Action::Delete, RequiredRole::UserScoped).await.map_err(|_| {
            log::error!("Resource delete denied: permission denied for user '{}'", ctx.sub());
            ResourceError::PermissionDenied
        })?;
        let _parsed = self.validator.validate_uri(uri).map_err(|e| {
            log::error!("Resource delete denied: URI validation failed: {}", e);
            e
        })?;
        let entity = self.repo.find_by_uri(uri).await?.ok_or_else(|| {
            log::error!("Resource delete denied: resource '{}' not found", uri);
            ResourceError::NotFound
        })?;
        if entity.username != ctx.sub() {
            log::error!("Resource delete denied: user '{}' cannot delete resource '{}' owned by '{}'", ctx.sub(), uri, entity.username);
            return Err(ResourceError::PermissionDenied);
        }
        self.repo.delete(uri, &entity.username).await?;
        log::info!("Resource deleted: uri='{}', user='{}'", uri, entity.username);
        Ok(())
    }

    // ── GET /content ───────────────────────────────────────────────────

    pub async fn get_content(
        &self, ctx: &AuthContext, uri: &str,
    ) -> Result<ResourceContentResponse, ResourceError> {
        log::info!("Resource get_content requested: uri={}, user={}", uri, ctx.sub());

        // step 1: parameter validation
        let parsed = self.validator.validate_uri(uri).map_err(|e| {
            log::error!("Resource get_content denied: URI validation failed: {}", e);
            e
        })?;

        // step 2: resource existence
        let entity = self.repo.find_by_uri(uri).await?.ok_or_else(|| {
            log::error!("Resource get_content denied: resource '{}' not found", uri);
            ResourceError::NotFound
        })?;

        // step 3: get resource-bound Rego policy
        let rego = self.policy_client.get_policy_content(&entity.policy_id).await?;

        // step 4: authorisation (AuthzFacade branches on token type internally)
        self.authz.check_resource_get(ctx, &entity.username, &rego).await
            .map_err(|_| {
                log::error!("Resource get_content denied: user '{}' not authorized for uri '{}'", ctx.sub(), uri);
                ResourceError::NotFound
            })?;

        // step 5: backend fetch
        let backend = self.backend_provider.get_backend(&parsed.res_provider)
            .ok_or_else(|| {
                log::error!("Resource get_content failed: backend '{}' not found", parsed.res_provider);
                ResourceError::BackendUnsupported { provider: parsed.res_provider.clone() }
            })?;
        let mut raw_content = backend.get_resource_content(uri).await?;
        let content_type = entity.content_type.clone();

        // step 6: JWE encrypt + base64 encode
        let pubkey = match ctx {
            AuthContext::Attest(a) => {
                a.claims.get("attester_data")
                    .and_then(|ad| ad.get("runtime_data"))
                    .and_then(|rd| rd.get(ATTEST_TEE_PUBKEY_KEY))
                    .and_then(|v| Self::json_value_to_string(&v))
            }
            AuthContext::Bearer(b) => {
                b.claims.get(BEARER_ENC_PUBKEY_KEY).and_then(|v| Self::json_value_to_string(&v))
            }
        };
        let pubkey = pubkey.ok_or_else(|| {
            log::error!("Resource get_content failed: encryption public key not found in token claims for uri '{}'", uri);
            ResourceError::JweEncryptionFailed {
                reason: format!("{ATTEST_TEE_PUBKEY_KEY} or {BEARER_ENC_PUBKEY_KEY} not found in token claims"),
            }
        })?;
        let encrypted = Self::jwe_encrypt(&raw_content, &pubkey)?;
        // Zero plaintext immediately after JWE encryption — minimize exposure time in memory
        raw_content.zeroize();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        log::info!("Resource get_content completed: uri='{}', user='{}'", uri, ctx.sub());
        Ok(ResourceContentResponse {
            uri: uri.to_string(), content: encoded, content_type, export_mode: entity.export_mode,
        })
    }

    // ── GET /info ──────────────────────────────────────────────────────

    pub async fn get_info(
        &self, ctx: &AuthContext, uri: &str,
    ) -> Result<ResourceResponse, ResourceError> {
        log::info!("Resource get_info requested: uri={}, user={}", uri, ctx.sub());

        // step 1: parameter validation
        let _parsed = self.validator.validate_uri(uri).map_err(|e| {
            log::error!("Resource get_info denied: URI validation failed: {}", e);
            e
        })?;

        // step 2: resource existence
        let entity = self.repo.find_by_uri(uri).await?.ok_or_else(|| {
            log::error!("Resource get_info denied: resource '{}' not found", uri);
            ResourceError::NotFound
        })?;

        // step 3: get resource-bound Rego policy
        let rego = self.policy_client.get_policy_content(&entity.policy_id).await?;

        // step 4: authorisation
        self.authz.check_resource_get(ctx, &entity.username, &rego).await
            .map_err(|_| {
                log::error!("Resource get_info denied: user '{}' not authorized for uri '{}'", ctx.sub(), uri);
                ResourceError::NotFound
            })?;

        // step 5: return metadata (no backend fetch)
        log::info!("Resource get_info completed: uri='{}', user='{}'", uri, ctx.sub());
        Ok(ResourceResponse {
            uri: uri.to_string(),
            provider_name: entity.provider_name, repository_name: entity.repo_name,
            resource_type: entity.res_type, resource_name: entity.res_name,
            created_at: millis_to_rfc3339(entity.created_at), updated_at: millis_to_rfc3339(entity.updated_at),
            content_type: entity.content_type, export_mode: entity.export_mode,
            policy_id: entity.policy_id,
            additional_info: entity.res_info,
        })
    }

    // ── POST /retrieve ─────────────────────────────────────────────────

    pub async fn retrieve(
        &self, attest_ctx: &AttestContext, uri: &str,
    ) -> Result<ResourceContentResponse, ResourceError> {
        log::info!("Resource retrieve requested: uri={}", uri);

        // step 1: parameter validation
        let parsed = self.validator.validate_uri(uri).map_err(|e| {
            log::error!("Resource retrieve denied: URI validation failed: {}", e);
            e
        })?;

        // step 2: resource existence
        let entity = self.repo.find_by_uri(uri).await?.ok_or_else(|| {
            log::error!("Resource retrieve denied: resource '{}' not found", uri);
            ResourceError::NotFound
        })?;

        // step 3: get resource-bound Rego policy
        let rego = self.policy_client.get_policy_content(&entity.policy_id).await?;

        // step 4: authorisation — unified via AuthzChecker (Attest path evaluates rego)
        let auth_ctx = AuthContext::Attest(attest_ctx.clone());
        self.authz.check_resource_get(&auth_ctx, &entity.username, &rego).await
            .map_err(|_| {
                log::error!("Resource retrieve denied: attestation token not authorized for uri '{}'", uri);
                ResourceError::NotFound
            })?;

        // step 5: backend fetch
        let backend = self.backend_provider.get_backend(&parsed.res_provider)
            .ok_or_else(|| {
                log::error!("Resource retrieve failed: backend '{}' not found", parsed.res_provider);
                ResourceError::BackendUnsupported { provider: parsed.res_provider.clone() }
            })?;
        let mut raw_content = backend.get_resource_content(uri).await?;
        let content_type = entity.content_type.clone();

        // step 6: JWE encrypt + base64 encode
        let pubkey = attest_ctx.claims.get("attester_data")
            .and_then(|ad| ad.get("runtime_data"))
            .and_then(|rd| rd.get(ATTEST_TEE_PUBKEY_KEY))
            .and_then(|v| Self::json_value_to_string(&v))
            .or_else(|| attest_ctx.claims.get(ATTEST_TEE_PUBKEY_KEY).and_then(|v| Self::json_value_to_string(&v)))
            .ok_or_else(|| {
                log::error!("Resource retrieve failed: TEE public key not found in attestation claims for uri '{}'", uri);
                ResourceError::JweEncryptionFailed {
                    reason: format!("{ATTEST_TEE_PUBKEY_KEY} not found in attestation claims"),
                }
            })?;
        let encrypted = Self::jwe_encrypt(&raw_content, &pubkey)?;
        // Zero plaintext immediately after JWE encryption — minimize exposure time in memory
        raw_content.zeroize();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        log::info!("Resource retrieve completed: uri='{}'", uri);
        Ok(ResourceContentResponse {
            uri: uri.to_string(), content: encoded, content_type, export_mode: entity.export_mode,
        })
    }

    /// Convert a JSON value (String or Object) to a string representation.
    /// - `Value::String` → inner string
    /// - `Value::Object` → serialized JSON
    fn json_value_to_string(v: &serde_json::Value) -> Option<String> {
        match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Object(_) => Some(v.to_string()),
            _ => None,
        }
    }

    fn jwe_encrypt(data: &[u8], pubkey: &str) -> Result<Vec<u8>, ResourceError> {
        use josekit::jwk::Jwk;
        use josekit::jwe::{self, JweHeader};

        let jwk = Jwk::from_bytes(pubkey.as_bytes())
            .map_err(|e| {
                log::error!("JWE encryption failed: invalid JWK: {}", e);
                ResourceError::JweEncryptionFailed {
                    reason: format!("invalid JWK: {e}"),
                }
            })?;

        let mut header = JweHeader::new();
        header.set_content_encryption("A256GCM");

        let jwe_compact = match jwk.key_type() {
            "RSA" => {
                let encrypter = jwe::RSA_OAEP_256
                    .encrypter_from_jwk(&jwk)
                    .map_err(|e| {
                        log::error!("JWE encryption failed: RSA encrypter creation error: {}", e);
                        ResourceError::JweEncryptionFailed {
                            reason: format!("RSA encrypter: {e}"),
                        }
                    })?;
                jwe::serialize_compact(data, &header, &encrypter)
                    .map_err(|e| {
                        log::error!("JWE encryption failed: RSA JWE serialize error: {}", e);
                        ResourceError::JweEncryptionFailed {
                            reason: format!("JWE encrypt: {e}"),
                        }
                    })?
            }
            "EC" => {
                let encrypter = jwe::ECDH_ES_A256KW
                    .encrypter_from_jwk(&jwk)
                    .map_err(|e| {
                        log::error!("JWE encryption failed: EC encrypter creation error: {}", e);
                        ResourceError::JweEncryptionFailed {
                            reason: format!("EC encrypter: {e}"),
                        }
                    })?;
                jwe::serialize_compact(data, &header, &encrypter)
                    .map_err(|e| {
                        log::error!("JWE encryption failed: EC JWE serialize error: {}", e);
                        ResourceError::JweEncryptionFailed {
                            reason: format!("JWE encrypt: {e}"),
                        }
                    })?
            }
            other => {
                log::error!("JWE encryption failed: unsupported JWK key type '{}'", other);
                return Err(ResourceError::JweEncryptionFailed {
                    reason: format!("unsupported JWK key type: {other}"),
                });
            }
        };

        Ok(jwe_compact.into_bytes())
    }
}

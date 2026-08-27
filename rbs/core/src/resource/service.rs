use chrono::Timelike;
use std::sync::Arc;

use base64::Engine;
use zeroize::Zeroize;
use crate::auth::authz::{Action, AuthzError, RequiredRole};
use crate::auth::authz_checker::AuthzChecker;
use crate::auth::context::{AttestContext, AuthContext};

use super::adapter::{BackendCapabilities, BackendProvider, PolicyClient};
use super::error::ResourceError;
use super::repository::ResourceRepository;
use super::validator::{ParsedUri, ResourceValidator};
use super::{
    CreateResourceRequest, ResourceContentResponse, ResourceResponse,
    UpdateResourceRequest, ATTEST_TEE_PUBKEY_KEY, BEARER_ENC_PUBKEY_KEY,
};

/// Build a ResourceDesc (addressing) from parsed URI segments.
fn build_resource_desc(parsed: &ParsedUri) -> rbs_api_types::ResourceDesc {
    rbs_api_types::ResourceDesc {
        repository_name: parsed.repository_name.clone(),
        resource_type: parsed.resource_type.clone(),
        resource_name: parsed.resource_name.clone(),
    }
}

/// Build GetResourceOptions: extract CSR from Attest claims if present (data-driven).
/// CSR path: `attester_data.runtime_data.csr` (DER Base64), mirroring the TEE-pubkey
/// extraction path used for JWE encryption (SR-001 §4.2).
fn build_get_options(ctx: &AuthContext) -> rbs_api_types::GetResourceOptions {
    let csr_der = match ctx {
        AuthContext::Attest(attest_ctx) => {
            attest_ctx.claims.get("attester_data")
                .and_then(|ad| ad.get("runtime_data"))
                .and_then(|rd| rd.get("csr"))
                .and_then(|v| v.as_str())
                .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                .map(zeroize::Zeroizing::new)
        }
        _ => None,
    };
    rbs_api_types::GetResourceOptions { csr_der }
}

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

/// Map an `AuthzError` returned by `check_resource_get` on a read path
/// (`get_content` / `get_info` / `retrieve`) to a `ResourceError`.
///
/// Two classes are distinguished:
///
/// - `AuthzError::Denied` — the policy (or ownership) decision went against the
///   caller. Collapsed to `NotFound` so unauthorized callers cannot distinguish
///   "resource missing" from "resource present but denied" (anti-enumeration).
///   Logged at `warn` with the policy id so operators can still tell them apart.
/// - Any other variant — no decision could be reached (broken Rego, missing
///   evaluation input): a server-side fault, logged at `error` with the detail
///   and surfaced as a 500 instead of masquerading as a missing resource.
fn read_authz_error(op: &str, uri: &str, policy_id: &str, e: AuthzError) -> ResourceError {
    match e {
        AuthzError::Denied => {
            log::warn!(
                "Resource {} denied: caller not authorized for uri '{}' (policy_id='{}')",
                op, uri, policy_id
            );
            ResourceError::NotFound
        }
        AuthzError::PolicyEvaluationFailed(detail) => {
            log::error!(
                "Resource {} failed: policy evaluation error for uri '{}' (policy_id='{}'): {}",
                op, uri, policy_id, detail
            );
            ResourceError::PolicyEvaluationFailed
        }
        other => {
            log::error!(
                "Resource {} failed: authorization error for uri '{}' (policy_id='{}'): {}",
                op, uri, policy_id, other
            );
            ResourceError::PolicyEvaluationFailed
        }
    }
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
        &self, ctx: &AuthContext, uri: &str, req: &CreateResourceRequest,
    ) -> Result<ResourceResponse, ResourceError> {
        log::info!("Resource create requested: uri={}, user={}", uri, ctx.sub());

        self.authz.check_action(ctx, Action::Create, RequiredRole::UserScoped).await.map_err(|_| {
            log::error!("Resource create denied: permission denied for user '{}'", ctx.sub());
            ResourceError::PermissionDenied
        })?;

        let parsed = self.validator.validate_uri(uri).map_err(|e| {
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

        // Decode content if present; backend decides what to do with it.
        let mut content_bytes: Option<Vec<u8>> = match req.content.as_ref() {
            Some(s) => Some(base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| {
                log::error!("Resource create denied: content base64 decode failed: {}", e);
                ResourceError::ParamInvalid { field: "content" }
            })?),
            None => None,
        };

        // Build the backend addressing descriptor BEFORE constructing the
        // entity (entity moves `parsed.resource_name`).
        let desc = build_resource_desc(&parsed);
        let now = chrono::Utc::now().timestamp_millis();
        let entity = super::repository::ResourceEntity {
            username: username.to_string(), provider_name: parsed.res_provider,
            repo_name: parsed.repository_name, res_type: parsed.resource_type,
            res_name: parsed.resource_name, res_info: req.additional_info.clone(),
            created_at: now, updated_at: now, content_type: req.content_type.clone(),
            export_mode: req.export_mode.clone().unwrap_or_else(|| "jwe".to_string()),
            policy_id: req.policy_id.clone(),
        };

        // DB-first reservation (module_interfaces.md §3.2, "失败可补偿 delete DB row"):
        // the atomic duplicate-check + per-user count + insert runs BEFORE any
        // backend mutation. A concurrent create for the same URI fails here
        // with AlreadyExists *without* touching the backend, so the loser can
        // neither orphan nor clobber the winner's backend object — closing the
        // TOCTOU window of the old "put-then-insert-then-delete-object" flow.
        if let Err(e) = self.repo
            .create_with_user_limit_check(uri, &entity, self.validator.max_per_user())
            .await
        {
            log::error!("Resource create failed: db insert error for uri '{}': {}", uri, e);
            if let Some(c) = content_bytes.as_mut() { c.zeroize(); }
            return Err(e);
        }

        let caps = backend.capabilities();
        // Backend dispatch AFTER the DB row is committed (DB is the single
        // source of truth). Failure rolls back the reserved DB row, never the
        // backend object — which may be externally managed (Vault/CHECK) or, for
        // PUT backends, is rebuilt on retry rather than blindly destroyed.
        let backend_result: Result<(), ResourceError> = async {
            // Capability-gated backend dispatch (module_interfaces.md §3.2):
            //   PUT    → put_resource_content (replace)
            //   CHECK  → must already exist
            //   neither → metadata-only (e.g. CA get-only)
            if caps.contains(BackendCapabilities::PUT) {
                if let Some(ref content) = content_bytes {
                    backend.put_resource_content(&desc, content).await.map_err(|e| {
                        log::error!("Resource create failed: backend put error for uri '{}': {}", uri, e);
                        e
                    })?;
                }
            } else if caps.contains(BackendCapabilities::CHECK) {
                let exists = backend.check_resource_exists(&desc).await?;
                if !exists {
                    log::error!("Resource create denied: backend object '{}' not found", uri);
                    return Err(ResourceError::BackendNotFound);
                }
            }
            Ok(())
        }.await;
        if let Err(e) = backend_result {
            // Compensate: remove the reserved DB row (NOT the backend object).
            let _ = self.repo.delete(uri, &entity.username).await;
            log::error!(
                "Resource create rolled back DB row for uri '{}': backend error {}",
                uri, e
            );
            if let Some(c) = content_bytes.as_mut() { c.zeroize(); }
            return Err(e);
        }
        // D7: zeroize content after backend call regardless of success/failure
        if let Some(c) = content_bytes.as_mut() { c.zeroize(); }

        log::info!("Resource created: uri='{}', user='{}', policy_id='{}'", uri, username, req.policy_id);
        Ok(ResourceResponse {
            uri: uri.to_string(), provider_name: entity.provider_name,
            repository_name: entity.repo_name,
            resource_type: entity.res_type, resource_name: entity.res_name,
            created_at: millis_to_rfc3339(entity.created_at), updated_at: millis_to_rfc3339(entity.updated_at),
            content_type: entity.content_type, export_mode: entity.export_mode,
            policy_id: entity.policy_id,
            additional_info: entity.res_info,
        })
    }

    /// Backend dispatch for the create flow, run AFTER the DB row is reserved.

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
        if let Some(ref ct) = req.content_type { self.validator.validate_content_type(ct).map_err(|e| { log::error!("Resource update denied: {}", e); e })?; }
        if let Some(ref em) = req.export_mode { self.validator.validate_export_mode(em).map_err(|e| { log::error!("Resource update denied: {}", e); e })?; }
        self.validator.validate_additional_info(req.additional_info.as_deref()).map_err(|e| { log::error!("Resource update denied: {}", e); e })?;
        let username = ctx.sub();

        // Resolve the effective policy id. An explicit `Some(policy_id)` rebinds the
        // resource (and is validated); `None` keeps the existing resource's binding.
        // A brand-new resource created via the upsert path still requires an explicit policy.
        let existing = self.repo.find_by_uri(uri).await?;
        let effective_policy_id = match req.policy_id.as_deref() {
            Some(pid) if !pid.is_empty() => pid.to_string(),
            Some(_) => {
                log::error!("Resource update denied: empty policy_id");
                return Err(ResourceError::ParamInvalid { field: "policy_id" });
            }
            None => match existing.as_ref() {
                Some(entity) => entity.policy_id.clone(),
                None => {
                    log::error!("Resource update denied: policy_id required to create a new resource");
                    return Err(ResourceError::ParamInvalid { field: "policy_id" });
                }
            },
        };

        // ── step 2b: policy and backend check (for both create and update) ──
        let valid = self.policy_client.validate_policy(&effective_policy_id, username).await?;
        if !valid {
            log::error!("Resource update denied: policy_id '{}' invalid for user '{}'", effective_policy_id, username);
            return Err(ResourceError::PolicyIdInvalid(effective_policy_id.clone()));
        }
        let backend = self.backend_provider.get_backend(&parsed.res_provider)
            .ok_or_else(|| {
                log::error!("Resource update failed: backend '{}' not found", parsed.res_provider);
                ResourceError::BackendUnsupported { provider: parsed.res_provider.clone() }
            })?;

        // Decode content if present; backend decides what to do (CA rejects, HSM puts, Vault ignores).
        let mut content_bytes: Option<Vec<u8>> = match req.content.as_ref() {
            Some(s) => Some(base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| {
                log::error!("Resource update denied: content base64 decode failed: {}", e);
                ResourceError::ParamInvalid { field: "content" }
            })?),
            None => None,
        };
        let desc = build_resource_desc(&parsed);
        // Ownership check MUST precede any backend write: otherwise an
        // attacker with a valid policy could overwrite another user's HSM
        // object before the 403 is returned.
        if let Some(ref existing_entity) = existing {
            if existing_entity.username != username {
                log::error!(
                    "Resource update denied: user '{}' cannot update resource '{}' owned by '{}'",
                    username, uri, existing_entity.username
                );
                return Err(ResourceError::PermissionDenied);
            }
        }

        let caps = backend.capabilities();
        // Parameter pre-check: content present but backend cannot store it →
        // reject before any DB or backend mutation (no reservation to roll back).
        if content_bytes.is_some() && !caps.contains(BackendCapabilities::PUT) {
            log::error!(
                "Resource update denied: backend '{}' cannot store content for uri '{}'",
                parsed.res_provider, uri
            );
            if let Some(c) = content_bytes.as_mut() { c.zeroize(); }
            return Err(ResourceError::BackendOperationUnsupported);
        }

        let now = chrono::Utc::now().timestamp_millis();

        if let Some(existing_entity) = existing {
            // Snapshot the pre-update state so the DB update can be rolled
            // back if the backend put fails (DB is the single source of
            // truth: commit the version first, mutate the backend second).
            let existing_snapshot = existing_entity.clone();
            let updated = super::repository::ResourceEntity {
                username: existing_entity.username, provider_name: existing_entity.provider_name,
                repo_name: existing_entity.repo_name, res_type: existing_entity.res_type,
                res_name: existing_entity.res_name,
                res_info: req.additional_info.clone().or(existing_entity.res_info),
                created_at: existing_entity.created_at, updated_at: now,
                content_type: req.content_type.clone().or(existing_entity.content_type),
                export_mode: req.export_mode.clone().unwrap_or(existing_entity.export_mode),
                policy_id: effective_policy_id.clone(),
            };
            // DB-first: claim the version via optimistic lock. A concurrent
            // update for the same URI fails here (affected==0) WITHOUT
            // touching the backend, so the loser can neither clobber the
            // winner's object nor leave the DB ahead of the backend.
            let old_update_time = existing_snapshot.updated_at;
            let affected = self.repo.update(uri, &updated, old_update_time).await?;
            if affected == 0 {
                log::error!("Resource update conflict: uri='{}', expected version mismatch", uri);
                if let Some(c) = content_bytes.as_mut() { c.zeroize(); }
                return Err(ResourceError::VersionConflict);
            }
            // Backend put AFTER the version is claimed. Failure rolls back the
            // DB row to the pre-update state (NOT the backend object, which is
            // still the old one because the put never succeeded).
            if let Some(ref content) = content_bytes {
                if let Err(e) = backend.put_resource_content(&desc, content).await {
                    // Roll back: restore the prior row, using `now` (the
                    // updated_at we just wrote) as the optimistic-lock baseline.
                    let rollback = super::repository::ResourceEntity {
                        username: existing_snapshot.username,
                        provider_name: existing_snapshot.provider_name,
                        repo_name: existing_snapshot.repo_name,
                        res_type: existing_snapshot.res_type,
                        res_name: existing_snapshot.res_name,
                        res_info: existing_snapshot.res_info,
                        created_at: existing_snapshot.created_at,
                        updated_at: existing_snapshot.updated_at,
                        content_type: existing_snapshot.content_type,
                        export_mode: existing_snapshot.export_mode,
                        policy_id: existing_snapshot.policy_id,
                    };
                    let _ = self.repo.update(uri, &rollback, now).await;
                    log::error!(
                        "Resource update rolled back DB row for uri '{}': backend error {}",
                        uri, e
                    );
                    if let Some(c) = content_bytes.as_mut() { c.zeroize(); }
                    return Err(e);
                }
            }
            // D7: zeroize content after backend call regardless of success/failure
            if let Some(c) = content_bytes.as_mut() { c.zeroize(); }
            log::info!("Resource updated: uri='{}', user='{}'", uri, username);
            Ok((ResourceResponse { uri: uri.to_string(), provider_name: updated.provider_name, repository_name: updated.repo_name, resource_type: updated.res_type, resource_name: updated.res_name, created_at: millis_to_rfc3339(updated.created_at), updated_at: millis_to_rfc3339(updated.updated_at), content_type: updated.content_type, export_mode: updated.export_mode, policy_id: updated.policy_id, additional_info: updated.res_info }, false))
        } else {
            // create-path: DB-first reservation, then backend put (mirrors
            // `create`). A concurrent upsert for the same URI fails the atomic
            // insert with AlreadyExists BEFORE touching the backend, so it can
            // neither orphan nor clobber the winner's object.
            let entity = super::repository::ResourceEntity {
                username: username.to_string(), provider_name: parsed.res_provider,
                repo_name: parsed.repository_name, res_type: parsed.resource_type,
                res_name: parsed.resource_name, res_info: req.additional_info.clone(),
                created_at: now, updated_at: now, content_type: req.content_type.clone(),
                export_mode: req.export_mode.clone().unwrap_or_else(|| "jwe".to_string()),
                policy_id: effective_policy_id.clone(),
            };
            if let Err(e) = self.repo
                .create_with_user_limit_check(uri, &entity, self.validator.max_per_user())
                .await
            {
                log::error!("Resource update (create path) failed: db insert error for uri '{}': {}", uri, e);
                if let Some(c) = content_bytes.as_mut() { c.zeroize(); }
                return Err(e);
            }
            // Backend put AFTER the DB row is committed. Failure rolls back
            // the reserved DB row (NOT the backend object).
            if let Some(ref content) = content_bytes {
                if let Err(e) = backend.put_resource_content(&desc, content).await {
                    let _ = self.repo.delete(uri, &entity.username).await;
                    log::error!(
                        "Resource update (create path) rolled back DB row for uri '{}': backend error {}",
                        uri, e
                    );
                    if let Some(c) = content_bytes.as_mut() { c.zeroize(); }
                    return Err(e);
                }
            }
            // D7: zeroize content after backend call regardless of success/failure
            if let Some(c) = content_bytes.as_mut() { c.zeroize(); }
            log::info!("Resource created via update: uri='{}', user='{}', policy_id='{}'", uri, username, effective_policy_id);
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
        let parsed = self.validator.validate_uri(uri).map_err(|e| {
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

        // Capability-gated backend dispatch (module_interfaces.md §3.2):
        // DELETE → backend.delete_resource then DB delete; otherwise DB only.
        let backend = self.backend_provider.get_backend(&parsed.res_provider)
            .ok_or_else(|| {
                log::error!("Resource delete failed: backend '{}' not found", parsed.res_provider);
                ResourceError::BackendUnsupported { provider: parsed.res_provider.clone() }
            })?;
        let desc = build_resource_desc(&parsed);
        if backend.capabilities().contains(BackendCapabilities::DELETE) {
            backend.delete_resource(&desc).await.map_err(|e| {
                log::error!("Resource delete failed: backend delete error for uri '{}': {}", uri, e);
                e
            })?;
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
        // res_provider=Some: admin_policy.rego applies Bearer-deny for hsm/ca content GET
        self.authz.check_resource_get(ctx, &entity.username, &rego, Some(&parsed.res_provider)).await
            .map_err(|e| read_authz_error("get_content", uri, &entity.policy_id, e))?;

        // step 5: backend fetch
        let backend = self.backend_provider.get_backend(&parsed.res_provider)
            .ok_or_else(|| {
                log::error!("Resource get_content failed: backend '{}' not found", parsed.res_provider);
                ResourceError::BackendUnsupported { provider: parsed.res_provider.clone() }
            })?;
        let desc = build_resource_desc(&parsed);
        let opts = build_get_options(ctx);
        let mut raw_content = backend.get_resource_content(&desc, opts).await?;
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

        // step 1: parameter validation (URI format checked; parsed segments not
        // needed for authz since res_provider=None — info returns metadata only)
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
        // res_provider=None: get_info returns metadata only (no secret content),
        // so admin_policy.rego Bearer-deny for hsm/ca must NOT apply (SR-001 §4.5).
        self.authz.check_resource_get(ctx, &entity.username, &rego, None).await
            .map_err(|e| read_authz_error("get_info", uri, &entity.policy_id, e))?;

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
        self.authz.check_resource_get(&auth_ctx, &entity.username, &rego, Some(&parsed.res_provider)).await
            .map_err(|e| read_authz_error("retrieve", uri, &entity.policy_id, e))?;

        // step 5: backend fetch
        let backend = self.backend_provider.get_backend(&parsed.res_provider)
            .ok_or_else(|| {
                log::error!("Resource retrieve failed: backend '{}' not found", parsed.res_provider);
                ResourceError::BackendUnsupported { provider: parsed.res_provider.clone() }
            })?;
        let desc = build_resource_desc(&parsed);
        let opts = build_get_options(&auth_ctx);
        let mut raw_content = backend.get_resource_content(&desc, opts).await?;
        let content_type = entity.content_type.clone();

        // step 6: JWE encrypt + base64 encode
        let pubkey = attest_ctx.claims.get("attester_data")
            .and_then(|ad| ad.get("runtime_data"))
            .and_then(|rd| rd.get(ATTEST_TEE_PUBKEY_KEY))
            .and_then(|v| Self::json_value_to_string(&v))
            .or_else(|| attest_ctx.claims.get("attester_data")
                .and_then(|ad| ad.get(ATTEST_TEE_PUBKEY_KEY))
                .and_then(|v| Self::json_value_to_string(&v)))
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

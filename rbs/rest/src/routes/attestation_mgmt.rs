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

//! Attestation management routes (`/rbs/v0/attestation/{as_provider}/{type}`).
//! CRUD for ref_value / cert / policy (6 ops × 2 path forms × 3 resources = 36
//! handlers). Handler bodies generated via macros; utoipa annotations per-handler.
//! All require Bearer + admin; Attest tokens rejected by middleware.

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use rbs_api_types::attestation_mgmt::{PolicyListQuery, AttestationPolicyListResponse};
use rbs_api_types::{
    CertCreateRequest, CertDeleteRequest,
    CertListQuery, CertListResponse, CertMutationResponse, CertUpdateRequest,
    ErrorBody, PolicyCreateRequest, PolicyDeleteRequest,
    PolicyMutationResponse, PolicyUpdateRequest, RefValueCreateRequest, RefValueDeleteRequest,
    RefValueListQuery, RefValueListResponse, RefValueMutationResponse, RefValueUpdateRequest,
};
use rbs_core::{AuthContext, CertProvider, PolicyProvider, RbsCore, RefValueProvider};
use serde::Serialize;
use std::sync::Arc;
use validator::Validate;

use crate::middleware::OptAuthContext;
use crate::routes::error::rbs_error_response;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn require_auth(req: &HttpRequest) -> Result<AuthContext, HttpResponse> {
    req.extensions()
        .get::<OptAuthContext>()
        .and_then(|c| c.0.clone())
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(ErrorBody::new("authentication required"))
        })
}

async fn mgmt_auth(core: &RbsCore, req: &HttpRequest, as_provider: &str, op: &str) -> Result<AuthContext, HttpResponse> {
    let ctx = require_auth(req)?;
    log::info!("AttestationMgmt {} request: provider='{}', user='{}'", op, as_provider, ctx.sub());
    if let Err(e) = core.admin().require_enabled_admin(&ctx).await {
        return Err(rbs_error_response(&e));
    }
    Ok(ctx)
}

fn bad_request(e: impl ToString) -> HttpResponse {
    log::error!("AttestationMgmt validation error: {}", e.to_string());
    HttpResponse::BadRequest().json(ErrorBody::new(e.to_string()))
}

fn ok_json<T: Serialize>(data: T, op: &str, as_provider: &str, user: &str) -> HttpResponse {
    log::info!("AttestationMgmt {} succeeded: provider='{}', user='{}'", op, as_provider, user);
    HttpResponse::Ok().json(data)
}

fn ok_created<T: Serialize>(data: T, op: &str, as_provider: &str, user: &str) -> HttpResponse {
    log::info!("AttestationMgmt {} succeeded: provider='{}', user='{}'", op, as_provider, user);
    HttpResponse::Created().json(data)
}

fn ok_no_content(op: &str, as_provider: &str, user: &str) -> HttpResponse {
    log::info!("AttestationMgmt {} succeeded: provider='{}', user='{}'", op, as_provider, user);
    HttpResponse::NoContent().finish()
}

fn resolve_ref_value_provider<'a>(core: &'a RbsCore, p: &'a str) -> Result<&'a dyn RefValueProvider, HttpResponse> {
    core.attestation().ref_value_for(Some(p)).map_err(|e| rbs_error_response(&e))
}
fn resolve_cert_provider<'a>(core: &'a RbsCore, p: &'a str) -> Result<&'a dyn CertProvider, HttpResponse> {
    core.attestation().cert_for(Some(p)).map_err(|e| rbs_error_response(&e))
}
fn resolve_policy_provider<'a>(core: &'a RbsCore, p: &'a str) -> Result<&'a dyn PolicyProvider, HttpResponse> {
    core.attestation().policy_for(Some(p)).map_err(|e| rbs_error_response(&e))
}

fn default_provider(core: &RbsCore) -> String { core.attestation().default_name().to_string() }

// ── Handler body macros ─────────────────────────────────────────────────────
// Each macro expands to a block that early-returns on auth/validation/provider
// errors, then maps the provider result to an HttpResponse.

macro_rules! h_list {
    ($core:expr, $req:expr, $ap:expr, $q:expr, $res:ident, $call:ident, $op:literal) => {{
        let ap = $ap; let q = $q; let ctx = match mgmt_auth($core, $req, &ap, $op).await { Ok(c) => c, Err(r) => return r };
        if let Err(e) = Validate::validate(&q) { return bad_request(e) }
        let p = match $res($core, &ap) { Ok(p) => p, Err(r) => return r };
        match p.$call(&ap, q).await {
            Ok(r) => ok_json(r, $op, &ap, ctx.sub()),
            Err(e) => rbs_error_response(&e),
        }
    }};
}

macro_rules! h_get {
    ($core:expr, $req:expr, $ap:expr, $id:expr, $res:ident, $call:ident, $op:literal) => {{
        let ap = $ap; let ctx = match mgmt_auth($core, $req, &ap, $op).await { Ok(c) => c, Err(r) => return r };
        let p = match $res($core, &ap) { Ok(p) => p, Err(r) => return r };
        match p.$call(&ap, $id).await {
            Ok(r) => ok_json(r, $op, &ap, ctx.sub()),
            Err(e) => rbs_error_response(&e),
        }
    }};
}

macro_rules! h_create {
    ($core:expr, $req:expr, $ap:expr, $body:expr, $res:ident, $call:ident, $op:literal) => {{
        let ap = $ap; let body = $body; let ctx = match mgmt_auth($core, $req, &ap, $op).await { Ok(c) => c, Err(r) => return r };
        if let Err(e) = Validate::validate(&body) { return bad_request(e) }
        let p = match $res($core, &ap) { Ok(p) => p, Err(r) => return r };
        match p.$call(&ap, body).await {
            Ok(r) => ok_created(r, $op, &ap, ctx.sub()),
            Err(e) => rbs_error_response(&e),
        }
    }};
}

macro_rules! h_update {
    ($core:expr, $req:expr, $ap:expr, $body:expr, $res:ident, $call:ident, $op:literal) => {{
        let ap = $ap; let body = $body; let ctx = match mgmt_auth($core, $req, &ap, $op).await { Ok(c) => c, Err(r) => return r };
        let p = match $res($core, &ap) { Ok(p) => p, Err(r) => return r };
        match p.$call(&ap, body).await {
            Ok(r) => ok_json(r, $op, &ap, ctx.sub()),
            Err(e) => rbs_error_response(&e),
        }
    }};
}

macro_rules! h_del_batch {
    ($core:expr, $req:expr, $ap:expr, $body:expr, $res:ident, $call:ident, $op:literal) => {{
        let ap = $ap; let body = $body; let ctx = match mgmt_auth($core, $req, &ap, $op).await { Ok(c) => c, Err(r) => return r };
        let p = match $res($core, &ap) { Ok(p) => p, Err(r) => return r };
        match p.$call(&ap, body).await {
            Ok(()) => ok_no_content($op, &ap, ctx.sub()),
            Err(e) => rbs_error_response(&e),
        }
    }};
}

macro_rules! h_del_single {
    ($core:expr, $req:expr, $ap:expr, $id:expr, $res:ident, $call:ident, $op:literal) => {{
        let ap = $ap; let ctx = match mgmt_auth($core, $req, &ap, $op).await { Ok(c) => c, Err(r) => return r };
        let p = match $res($core, &ap) { Ok(p) => p, Err(r) => return r };
        match p.$call(&ap, $id).await {
            Ok(()) => ok_no_content($op, &ap, ctx.sub()),
            Err(e) => rbs_error_response(&e),
        }
    }};
}

// ===========================================================================
// ref_value handlers (AR-001) — 12 handlers
// ===========================================================================

#[utoipa::path(
    get, path = "/rbs/v0/attestation/{as_provider}/ref_value",
    operation_id = "listRefValues", summary = "List reference value baselines",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("as_provider" = String, Path, description = "Attestation provider name"),
        ("ids" = Option<String>, Query, description = "Comma-separated ref_value IDs (1-10)"),("attester_type" = Option<String>, Query, description = "Filter by attester type"),("limit" = Option<i64>, Query, description = "Page size (1-10, default 10)"),
        ("offset" = Option<i64>, Query, description = "Offset (0-100000, default 0)"),
    ),
    responses(
        (status = 200, description = "Ref_value list", body = RefValueListResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn list_ref_values(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, query: web::Query<RefValueListQuery>) -> HttpResponse {
    h_list!(&core, &req, path.into_inner(), query.into_inner(), resolve_ref_value_provider, list_ref_values, "list_ref_values")
}

#[utoipa::path(
    get, path = "/rbs/v0/attestation/ref_value",
    operation_id = "listRefValuesDefault", summary = "List reference value baselines (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("ids" = Option<String>, Query, description = "Comma-separated ref_value IDs (1-10)"),("attester_type" = Option<String>, Query, description = "Filter by attester type"),("limit" = Option<i64>, Query, description = "Page size (1-10, default 10)"),
        ("offset" = Option<i64>, Query, description = "Offset (0-100000, default 0)"),
    ),
    responses(
        (status = 200, description = "Ref_value list", body = RefValueListResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn list_ref_values_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, query: web::Query<RefValueListQuery>) -> HttpResponse {
    h_list!(&core, &req, default_provider(&core), query.into_inner(), resolve_ref_value_provider, list_ref_values, "list_ref_values")
}

#[utoipa::path(
    get, path = "/rbs/v0/attestation/{as_provider}/ref_value/{id}",
    operation_id = "getRefValue", summary = "Get a single reference value baseline",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("as_provider" = String, Path, description = "Attestation provider name"),
        ("id" = String, Path, description = "Ref_value ID"),
    ),
    responses(
        (status = 200, description = "Ref_value detail", body = RefValueListResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn get_ref_value(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<(String, String)>) -> HttpResponse {
    let (ap, id) = path.into_inner();
    h_get!(&core, &req, ap, id, resolve_ref_value_provider, get_ref_value, "get_ref_value")
}

#[utoipa::path(
    get, path = "/rbs/v0/attestation/ref_value/{id}",
    operation_id = "getRefValueDefault", summary = "Get a single reference value baseline (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("id" = String, Path, description = "Ref_value ID")),
    responses(
        (status = 200, description = "Ref_value detail", body = RefValueListResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn get_ref_value_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    h_get!(&core, &req, default_provider(&core), path.into_inner(), resolve_ref_value_provider, get_ref_value, "get_ref_value")
}

#[utoipa::path(
    post, path = "/rbs/v0/attestation/{as_provider}/ref_value",
    operation_id = "createRefValue", summary = "Create a reference value baseline",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("as_provider" = String, Path, description = "Attestation provider name")),
    request_body = RefValueCreateRequest,
    responses(
        (status = 201, description = "Ref_value created", body = RefValueMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn create_ref_value(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, body: web::Json<RefValueCreateRequest>) -> HttpResponse {
    h_create!(&core, &req, path.into_inner(), body.into_inner(), resolve_ref_value_provider, create_ref_value, "create_ref_value")
}

#[utoipa::path(
    post, path = "/rbs/v0/attestation/ref_value",
    operation_id = "createRefValueDefault", summary = "Create a reference value baseline (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    request_body = RefValueCreateRequest,
    responses(
        (status = 201, description = "Ref_value created", body = RefValueMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn create_ref_value_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<RefValueCreateRequest>) -> HttpResponse {
    h_create!(&core, &req, default_provider(&core), body.into_inner(), resolve_ref_value_provider, create_ref_value, "create_ref_value")
}

#[utoipa::path(
    put, path = "/rbs/v0/attestation/{as_provider}/ref_value",
    operation_id = "updateRefValue", summary = "Update a reference value baseline",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("as_provider" = String, Path, description = "Attestation provider name")),
    request_body = RefValueUpdateRequest,
    responses(
        (status = 200, description = "Ref_value updated", body = RefValueMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn update_ref_value(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, body: web::Json<RefValueUpdateRequest>) -> HttpResponse {
    h_update!(&core, &req, path.into_inner(), body.into_inner(), resolve_ref_value_provider, update_ref_value, "update_ref_value")
}

#[utoipa::path(
    put, path = "/rbs/v0/attestation/ref_value",
    operation_id = "updateRefValueDefault", summary = "Update a reference value baseline (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    request_body = RefValueUpdateRequest,
    responses(
        (status = 200, description = "Ref_value updated", body = RefValueMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn update_ref_value_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<RefValueUpdateRequest>) -> HttpResponse {
    h_update!(&core, &req, default_provider(&core), body.into_inner(), resolve_ref_value_provider, update_ref_value, "update_ref_value")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/{as_provider}/ref_value",
    operation_id = "deleteRefValues", summary = "Batch delete reference value baselines",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("as_provider" = String, Path, description = "Attestation provider name")),
    request_body = RefValueDeleteRequest,
    responses(
        (status = 204, description = "Ref_values deleted"),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_ref_values(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, body: web::Json<RefValueDeleteRequest>) -> HttpResponse {
    h_del_batch!(&core, &req, path.into_inner(), body.into_inner(), resolve_ref_value_provider, delete_ref_values, "delete_ref_values")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/ref_value",
    operation_id = "deleteRefValuesDefault", summary = "Batch delete reference value baselines (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    request_body = RefValueDeleteRequest,
    responses(
        (status = 204, description = "Ref_values deleted"),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_ref_values_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<RefValueDeleteRequest>) -> HttpResponse {
    h_del_batch!(&core, &req, default_provider(&core), body.into_inner(), resolve_ref_value_provider, delete_ref_values, "delete_ref_values")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/{as_provider}/ref_value/{id}",
    operation_id = "deleteRefValue", summary = "Delete a single reference value baseline",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("as_provider" = String, Path, description = "Attestation provider name"),
        ("id" = String, Path, description = "Ref_value ID"),
    ),
    responses(
        (status = 204, description = "Ref_value deleted"),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_ref_value(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<(String, String)>) -> HttpResponse {
    let (ap, id) = path.into_inner();
    h_del_single!(&core, &req, ap, id, resolve_ref_value_provider, delete_ref_value, "delete_ref_value")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/ref_value/{id}",
    operation_id = "deleteRefValueDefault", summary = "Delete a single reference value baseline (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("id" = String, Path, description = "Ref_value ID")),
    responses(
        (status = 204, description = "Ref_value deleted"),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_ref_value_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    h_del_single!(&core, &req, default_provider(&core), path.into_inner(), resolve_ref_value_provider, delete_ref_value, "delete_ref_value")
}

// ===========================================================================
// cert handlers (AR-002) — 12 handlers
// ===========================================================================

#[utoipa::path(
    get, path = "/rbs/v0/attestation/{as_provider}/cert",
    operation_id = "listCerts", summary = "List certificates",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("as_provider" = String, Path, description = "Attestation provider name"),
        ("ids" = Option<String>, Query, description = "Comma-separated certificate IDs"),("cert_type" = Option<String>, Query, description = "Filter by certificate type"),("limit" = Option<i64>, Query, description = "Page size (1-10, default 10)"),
        ("offset" = Option<i64>, Query, description = "Offset (0-100000, default 0)"),
    ),
    responses(
        (status = 200, description = "Certificate list", body = CertListResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn list_certs(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, query: web::Query<CertListQuery>) -> HttpResponse {
    h_list!(&core, &req, path.into_inner(), query.into_inner(), resolve_cert_provider, list_certs, "list_certs")
}

#[utoipa::path(
    get, path = "/rbs/v0/attestation/cert",
    operation_id = "listCertsDefault", summary = "List certificates (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("ids" = Option<String>, Query, description = "Comma-separated certificate IDs"),("cert_type" = Option<String>, Query, description = "Filter by certificate type"),("limit" = Option<i64>, Query, description = "Page size (1-10, default 10)"),
        ("offset" = Option<i64>, Query, description = "Offset (0-100000, default 0)"),
    ),
    responses(
        (status = 200, description = "Certificate list", body = CertListResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn list_certs_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, query: web::Query<CertListQuery>) -> HttpResponse {
    h_list!(&core, &req, default_provider(&core), query.into_inner(), resolve_cert_provider, list_certs, "list_certs")
}

#[utoipa::path(
    get, path = "/rbs/v0/attestation/{as_provider}/cert/{id}",
    operation_id = "getCert", summary = "Get a single certificate",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("as_provider" = String, Path, description = "Attestation provider name"),
        ("id" = String, Path, description = "Certificate or CRL ID"),
    ),
    responses(
        (status = 200, description = "Certificate detail", body = CertListResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn get_cert(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<(String, String)>) -> HttpResponse {
    let (ap, id) = path.into_inner();
    h_get!(&core, &req, ap, id, resolve_cert_provider, get_cert, "get_cert")
}

#[utoipa::path(
    get, path = "/rbs/v0/attestation/cert/{id}",
    operation_id = "getCertDefault", summary = "Get a single certificate (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("id" = String, Path, description = "Certificate or CRL ID")),
    responses(
        (status = 200, description = "Certificate detail", body = CertListResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn get_cert_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    h_get!(&core, &req, default_provider(&core), path.into_inner(), resolve_cert_provider, get_cert, "get_cert")
}

#[utoipa::path(
    post, path = "/rbs/v0/attestation/{as_provider}/cert",
    operation_id = "createCert", summary = "Create a certificate",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("as_provider" = String, Path, description = "Attestation provider name")),
    request_body = CertCreateRequest,
    responses(
        (status = 201, description = "Certificate created", body = CertMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn create_cert(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, body: web::Json<CertCreateRequest>) -> HttpResponse {
    h_create!(&core, &req, path.into_inner(), body.into_inner(), resolve_cert_provider, create_cert, "create_cert")
}

#[utoipa::path(
    post, path = "/rbs/v0/attestation/cert",
    operation_id = "createCertDefault", summary = "Create a certificate (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    request_body = CertCreateRequest,
    responses(
        (status = 201, description = "Certificate created", body = CertMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn create_cert_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<CertCreateRequest>) -> HttpResponse {
    h_create!(&core, &req, default_provider(&core), body.into_inner(), resolve_cert_provider, create_cert, "create_cert")
}

#[utoipa::path(
    put, path = "/rbs/v0/attestation/{as_provider}/cert",
    operation_id = "updateCert", summary = "Update a certificate",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("as_provider" = String, Path, description = "Attestation provider name")),
    request_body = CertUpdateRequest,
    responses(
        (status = 200, description = "Certificate updated", body = CertMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn update_cert(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, body: web::Json<CertUpdateRequest>) -> HttpResponse {
    h_update!(&core, &req, path.into_inner(), body.into_inner(), resolve_cert_provider, update_cert, "update_cert")
}

#[utoipa::path(
    put, path = "/rbs/v0/attestation/cert",
    operation_id = "updateCertDefault", summary = "Update a certificate (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    request_body = CertUpdateRequest,
    responses(
        (status = 200, description = "Certificate updated", body = CertMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn update_cert_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<CertUpdateRequest>) -> HttpResponse {
    h_update!(&core, &req, default_provider(&core), body.into_inner(), resolve_cert_provider, update_cert, "update_cert")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/{as_provider}/cert",
    operation_id = "deleteCerts", summary = "Batch delete certificates",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("as_provider" = String, Path, description = "Attestation provider name")),
    request_body = CertDeleteRequest,
    responses(
        (status = 204, description = "Certificates deleted"),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_certs(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, body: web::Json<CertDeleteRequest>) -> HttpResponse {
    h_del_batch!(&core, &req, path.into_inner(), body.into_inner(), resolve_cert_provider, delete_certs, "delete_certs")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/cert",
    operation_id = "deleteCertsDefault", summary = "Batch delete certificates (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    request_body = CertDeleteRequest,
    responses(
        (status = 204, description = "Certificates deleted"),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_certs_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<CertDeleteRequest>) -> HttpResponse {
    h_del_batch!(&core, &req, default_provider(&core), body.into_inner(), resolve_cert_provider, delete_certs, "delete_certs")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/{as_provider}/cert/{id}",
    operation_id = "deleteCert", summary = "Delete a single certificate",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("as_provider" = String, Path, description = "Attestation provider name"),
        ("id" = String, Path, description = "Certificate or CRL ID"),
    ),
    responses(
        (status = 204, description = "Certificate deleted"),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_cert(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<(String, String)>) -> HttpResponse {
    let (ap, id) = path.into_inner();
    h_del_single!(&core, &req, ap, id, resolve_cert_provider, delete_cert, "delete_cert")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/cert/{id}",
    operation_id = "deleteCertDefault", summary = "Delete a single certificate (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("id" = String, Path, description = "Certificate or CRL ID")),
    responses(
        (status = 204, description = "Certificate deleted"),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_cert_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    h_del_single!(&core, &req, default_provider(&core), path.into_inner(), resolve_cert_provider, delete_cert, "delete_cert")
}

// ===========================================================================
// attestation policy handlers (AR-003) — 12 handlers
// ===========================================================================

#[utoipa::path(
    get, path = "/rbs/v0/attestation/{as_provider}/policy",
    operation_id = "listAttestationPolicies", summary = "List attestation policies",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("as_provider" = String, Path, description = "Attestation provider name"),
        ("ids" = Option<String>, Query, description = "Comma-separated policy IDs"),("attester_type" = Option<String>, Query, description = "Filter by attester type"),("limit" = Option<i64>, Query, description = "Page size (1-10, default 10)"),
        ("offset" = Option<i64>, Query, description = "Offset (0-100000, default 0)"),
    ),
    responses(
        (status = 200, description = "Policy list", body = AttestationPolicyListResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn list_attestation_policies(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, query: web::Query<PolicyListQuery>) -> HttpResponse {
    h_list!(&core, &req, path.into_inner(), query.into_inner(), resolve_policy_provider, list_policies, "list_attestation_policies")
}

#[utoipa::path(
    get, path = "/rbs/v0/attestation/policy",
    operation_id = "listAttestationPoliciesDefault", summary = "List attestation policies (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("ids" = Option<String>, Query, description = "Comma-separated policy IDs"),("attester_type" = Option<String>, Query, description = "Filter by attester type"),("limit" = Option<i64>, Query, description = "Page size (1-10, default 10)"),
        ("offset" = Option<i64>, Query, description = "Offset (0-100000, default 0)"),
    ),
    responses(
        (status = 200, description = "Policy list", body = AttestationPolicyListResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn list_attestation_policies_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, query: web::Query<PolicyListQuery>) -> HttpResponse {
    h_list!(&core, &req, default_provider(&core), query.into_inner(), resolve_policy_provider, list_policies, "list_attestation_policies")
}

#[utoipa::path(
    get, path = "/rbs/v0/attestation/{as_provider}/policy/{id}",
    operation_id = "getAttestationPolicy", summary = "Get a single attestation policy",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("as_provider" = String, Path, description = "Attestation provider name"),
        ("id" = String, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy detail", body = AttestationPolicyListResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn get_attestation_policy(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<(String, String)>) -> HttpResponse {
    let (ap, id) = path.into_inner();
    h_get!(&core, &req, ap, id, resolve_policy_provider, get_policy, "get_attestation_policy")
}

#[utoipa::path(
    get, path = "/rbs/v0/attestation/policy/{id}",
    operation_id = "getAttestationPolicyDefault", summary = "Get a single attestation policy (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("id" = String, Path, description = "Policy ID")),
    responses(
        (status = 200, description = "Policy detail", body = AttestationPolicyListResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn get_attestation_policy_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    h_get!(&core, &req, default_provider(&core), path.into_inner(), resolve_policy_provider, get_policy, "get_attestation_policy")
}

#[utoipa::path(
    post, path = "/rbs/v0/attestation/{as_provider}/policy",
    operation_id = "createAttestationPolicy", summary = "Create an attestation policy",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("as_provider" = String, Path, description = "Attestation provider name")),
    request_body = PolicyCreateRequest,
    responses(
        (status = 201, description = "Policy created", body = PolicyMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn create_attestation_policy(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, body: web::Json<PolicyCreateRequest>) -> HttpResponse {
    h_create!(&core, &req, path.into_inner(), body.into_inner(), resolve_policy_provider, create_policy, "create_attestation_policy")
}

#[utoipa::path(
    post, path = "/rbs/v0/attestation/policy",
    operation_id = "createAttestationPolicyDefault", summary = "Create an attestation policy (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    request_body = PolicyCreateRequest,
    responses(
        (status = 201, description = "Policy created", body = PolicyMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Provider not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn create_attestation_policy_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<PolicyCreateRequest>) -> HttpResponse {
    h_create!(&core, &req, default_provider(&core), body.into_inner(), resolve_policy_provider, create_policy, "create_attestation_policy")
}

#[utoipa::path(
    put, path = "/rbs/v0/attestation/{as_provider}/policy",
    operation_id = "updateAttestationPolicy", summary = "Update an attestation policy",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("as_provider" = String, Path, description = "Attestation provider name")),
    request_body = PolicyUpdateRequest,
    responses(
        (status = 200, description = "Policy updated", body = PolicyMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn update_attestation_policy(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, body: web::Json<PolicyUpdateRequest>) -> HttpResponse {
    h_update!(&core, &req, path.into_inner(), body.into_inner(), resolve_policy_provider, update_policy, "update_attestation_policy")
}

#[utoipa::path(
    put, path = "/rbs/v0/attestation/policy",
    operation_id = "updateAttestationPolicyDefault", summary = "Update an attestation policy (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    request_body = PolicyUpdateRequest,
    responses(
        (status = 200, description = "Policy updated", body = PolicyMutationResponse),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn update_attestation_policy_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<PolicyUpdateRequest>) -> HttpResponse {
    h_update!(&core, &req, default_provider(&core), body.into_inner(), resolve_policy_provider, update_policy, "update_attestation_policy")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/{as_provider}/policy",
    operation_id = "deleteAttestationPolicies", summary = "Batch delete attestation policies",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("as_provider" = String, Path, description = "Attestation provider name")),
    request_body = PolicyDeleteRequest,
    responses(
        (status = 204, description = "Policies deleted"),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_attestation_policies(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>, body: web::Json<PolicyDeleteRequest>) -> HttpResponse {
    h_del_batch!(&core, &req, path.into_inner(), body.into_inner(), resolve_policy_provider, delete_policies, "delete_attestation_policies")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/policy",
    operation_id = "deleteAttestationPoliciesDefault", summary = "Batch delete attestation policies (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    request_body = PolicyDeleteRequest,
    responses(
        (status = 204, description = "Policies deleted"),
        (status = 400, description = "Bad request", body = ErrorBody), (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody), (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_attestation_policies_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<PolicyDeleteRequest>) -> HttpResponse {
    h_del_batch!(&core, &req, default_provider(&core), body.into_inner(), resolve_policy_provider, delete_policies, "delete_attestation_policies")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/{as_provider}/policy/{id}",
    operation_id = "deleteAttestationPolicy", summary = "Delete a single attestation policy",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(
        ("as_provider" = String, Path, description = "Attestation provider name"),
        ("id" = String, Path, description = "Policy ID"),
    ),
    responses(
        (status = 204, description = "Policy deleted"),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_attestation_policy(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<(String, String)>) -> HttpResponse {
    let (ap, id) = path.into_inner();
    h_del_single!(&core, &req, ap, id, resolve_policy_provider, delete_policy, "delete_attestation_policy")
}

#[utoipa::path(
    delete, path = "/rbs/v0/attestation/policy/{id}",
    operation_id = "deleteAttestationPolicyDefault", summary = "Delete a single attestation policy (default provider)",
    tags = ["Attestation"], security(("bearerAuth" = [])),
    params(("id" = String, Path, description = "Policy ID")),
    responses(
        (status = 204, description = "Policy deleted"),
        (status = 401, description = "Unauthorized", body = ErrorBody), (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody), (status = 500, description = "Internal error", body = ErrorBody),
        (status = 503, description = "GTA unreachable or timeout; other GTA statuses forwarded as-is", body = ErrorBody),
    )
)]
pub async fn delete_attestation_policy_default(core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    h_del_single!(&core, &req, default_provider(&core), path.into_inner(), resolve_policy_provider, delete_policy, "delete_attestation_policy")
}

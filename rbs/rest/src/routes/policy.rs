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

//! Policy routes (`/rbs/v0/resource/policy`).

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, http::StatusCode};
use rbs_api_types::{
    BatchDeleteQuery, CreatePolicyRequest, ErrorBody, PolicyListQuery, PolicyListResponse,
    PolicyResponse, UpdatePolicyRequest, validate_policy_id,
};
use rbs_core::policy::service::PolicyQuery;
use rbs_core::RbsCore;
use std::sync::Arc;
use validator::Validate;

use crate::middleware::OptAuthContext;

fn require_auth(req: &HttpRequest) -> Result<rbs_core::AuthContext, HttpResponse> {
    req.extensions().get::<OptAuthContext>().and_then(|c| c.0.clone())
        .ok_or_else(|| HttpResponse::Unauthorized().json(ErrorBody::new("authentication required".to_string())))
}

fn error_response(e: impl ToString, status: u16) -> HttpResponse {
    HttpResponse::build(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .json(ErrorBody::new(e.to_string()))
}

fn validate_path_id(policy_id: &str) -> Result<(), HttpResponse> {
    validate_policy_id(policy_id)
        .map_err(|msg| HttpResponse::BadRequest().json(ErrorBody::new(msg)))
}

/// `GET /rbs/v0/resource/policy`: List policies.
#[utoipa::path(
    get,
    path = "/rbs/v0/resource/policy",
    operation_id = "listPolicies",
    summary = "List policies",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    params(
        ("ids" = Option<String>, Query, description = "Comma-separated policy IDs"),
        ("limit" = Option<i64>, Query, description = "Page size (1..100, default 10)"),
        ("offset" = Option<i64>, Query, description = "Offset (0..100000, default 0)"),
    ),
    responses(
        (status = 200, description = "Policy list", body = PolicyListResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn list_policies(
    core: web::Data<Arc<RbsCore>>, req: HttpRequest, query: web::Query<PolicyListQuery>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let query = query.into_inner();
    if let Err(e) = Validate::validate(&query) {
        return HttpResponse::BadRequest().json(ErrorBody::new(e.to_string()));
    }
    let ids: Option<Vec<String>> = query.ids.as_deref()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect());
    let limit = query.limit.unwrap_or(10);
    let offset = query.offset.unwrap_or(0);
    match core.policy().list(&ctx, &PolicyQuery { ids, offset, limit }).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `POST /rbs/v0/resource/policy`: Create policy.
#[utoipa::path(
    post,
    path = "/rbs/v0/resource/policy",
    operation_id = "createPolicy",
    summary = "Create a policy",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    request_body = CreatePolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = PolicyResponse),
        (status = 400, description = "Bad request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Conflict (name duplicate / count exceeded)", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn create_policy(
    core: web::Data<Arc<RbsCore>>, req: HttpRequest, body: web::Json<CreatePolicyRequest>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let body = body.into_inner();
    if let Err(e) = Validate::validate(&body) {
        return HttpResponse::BadRequest().json(ErrorBody::new(e.to_string()));
    }
    match core.policy().create(&ctx, &body).await {
        Ok(resp) => HttpResponse::Created().json(resp),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `GET /rbs/v0/resource/policy/{policy_id}`: Get policy detail.
#[utoipa::path(
    get,
    path = "/rbs/v0/resource/policy/{policy_id}",
    operation_id = "getPolicy",
    summary = "Get policy detail",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    params(
        ("policy_id" = String, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy detail", body = PolicyResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn get_policy(
    core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let id = path.into_inner();
    if let Err(r) = validate_path_id(&id) { return r; }
    match core.policy().get_by_id(&ctx, &id).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `PUT /rbs/v0/resource/policy/{policy_id}`: Update policy.
#[utoipa::path(
    put,
    path = "/rbs/v0/resource/policy/{policy_id}",
    operation_id = "updatePolicy",
    summary = "Update a policy",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    params(
        ("policy_id" = String, Path, description = "Policy ID"),
    ),
    request_body = UpdatePolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = PolicyResponse),
        (status = 400, description = "Bad request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Version conflict", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn update_policy(
    core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>,
    body: web::Json<UpdatePolicyRequest>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let id = path.into_inner();
    if let Err(r) = validate_path_id(&id) { return r; }
    let body = body.into_inner();
    if let Err(e) = Validate::validate(&body) {
        return HttpResponse::BadRequest().json(ErrorBody::new(e.to_string()));
    }
    match core.policy().update(&ctx, &id, &body).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `DELETE /rbs/v0/resource/policy/{policy_id}`: Single delete.
#[utoipa::path(
    delete,
    path = "/rbs/v0/resource/policy/{policy_id}",
    operation_id = "deletePolicy",
    summary = "Delete a policy",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    params(
        ("policy_id" = String, Path, description = "Policy ID"),
    ),
    responses(
        (status = 204, description = "Policy deleted"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Policy is referenced by resources", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn delete_policy(
    core: web::Data<Arc<RbsCore>>, req: HttpRequest, path: web::Path<String>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let pid = path.into_inner();
    if let Err(r) = validate_path_id(&pid) { return r; }
    match core.policy().delete(&ctx, &[pid]).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `DELETE /rbs/v0/resource/policy?ids=id1,id2`: Batch delete.
#[utoipa::path(
    delete,
    path = "/rbs/v0/resource/policy",
    operation_id = "batchDeletePolicies",
    summary = "Batch delete policies",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    params(
        ("ids" = String, Query, description = "Comma-separated policy IDs"),
    ),
    responses(
        (status = 204, description = "Policies deleted"),
        (status = 400, description = "Bad request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Policy is referenced by resources", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn batch_delete_policies(
    core: web::Data<Arc<RbsCore>>, req: HttpRequest, query: web::Query<BatchDeleteQuery>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let ids: Vec<String> = query.ids.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    match core.policy().delete(&ctx, &ids).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

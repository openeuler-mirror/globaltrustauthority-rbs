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
    PolicyResponse, UpdatePolicyRequest, POLICY_BATCH_DELETE_MAX_IDS, validate_policy_id,
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
    let msg = e.to_string();
    if status >= 500 {
        log::error!("Policy HTTP error response: status={}, error='{}'", status, msg);
    } else if status >= 400 {
        log::error!("Policy HTTP error response: status={}, error='{}'", status, msg);
    }
    HttpResponse::build(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .json(ErrorBody::new(msg))
}

fn validate_path_id(policy_id: &str) -> Result<(), HttpResponse> {
    validate_policy_id(policy_id)
        .map_err(|msg| {
            log::error!("Policy path ID validation error: {}", msg);
            HttpResponse::BadRequest().json(ErrorBody::new(msg))
        })
}

/// `GET /rbs/v0/resource/policy`: List policies.
#[utoipa::path(
    get,
    path = "/rbs/v0/resource/policy",
    operation_id = "listPolicies",
    summary = "List policies",
    description = "List the caller's own policies with optional `ids` filter and pagination; policies are user-scoped and other users' policies are never returned. When `ids` is present, only those are returned and pagination is ignored.",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    params(PolicyListQuery),
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
    log::info!("Policy list HTTP request received: user='{}'", ctx.sub());
    let query = query.into_inner();
    if let Err(e) = Validate::validate(&query) {
        log::error!("Policy list validation error: {}", e);
        return HttpResponse::BadRequest().json(ErrorBody::new(e.to_string()));
    }
    let ids: Option<Vec<String>> = query.ids.as_deref()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect());
    if let Some(ref id_list) = ids {
        for id in id_list {
            if let Err(msg) = validate_policy_id(id) {
                log::error!("Policy list validation error: {}", msg);
                return HttpResponse::BadRequest().json(ErrorBody::new(msg));
            }
        }
    }
    let limit = query.limit.unwrap_or(10);
    let offset = query.offset.unwrap_or(0);
    match core.policy().list(&ctx, &PolicyQuery { ids, offset, limit }).await {
        Ok(resp) => {
            log::info!("Policy list succeeded: user='{}', total_count={}", ctx.sub(), resp.total_count);
            HttpResponse::Ok().json(resp)
        }
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `POST /rbs/v0/resource/policy`: Create policy.
#[utoipa::path(
    post,
    path = "/rbs/v0/resource/policy",
    operation_id = "createPolicy",
    summary = "Create a policy",
    description = "Create a policy owned by the caller. `content` must be base64-encoded Rego that decodes to valid UTF-8 within the configured size limit; the name must be unique per user. 409 on duplicate name or when the per-user policy quota is reached.",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    request_body(content = CreatePolicyRequest, description = "Policy name, content encoding (`base64`), and base64-encoded Rego content."),
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
    log::info!("Policy create HTTP request received: user='{}'", ctx.sub());
    let body = body.into_inner();
    if let Err(e) = Validate::validate(&body) {
        log::error!("Policy create validation error: {}", e);
        return HttpResponse::BadRequest().json(ErrorBody::new(e.to_string()));
    }
    match core.policy().create(&ctx, &body).await {
        Ok(resp) => {
            log::info!("Policy create succeeded: id='{}', user='{}'", resp.policy_id, ctx.sub());
            HttpResponse::Created().json(resp)
        }
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `GET /rbs/v0/resource/policy/{policy_id}`: Get policy detail.
#[utoipa::path(
    get,
    path = "/rbs/v0/resource/policy/{policy_id}",
    operation_id = "getPolicy",
    summary = "Get policy detail",
    description = "Fetch a single policy including `applied_resources` (URIs of resources bound to it). User-scoped: 403 when the policy belongs to another user.",
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
    log::info!("Policy get HTTP request received: id='{}', user='{}'", id, ctx.sub());
    if let Err(r) = validate_path_id(&id) { return r; }
    match core.policy().get_by_id(&ctx, &id).await {
        Ok(resp) => {
            log::info!("Policy get succeeded: id='{}', user='{}'", id, ctx.sub());
            HttpResponse::Ok().json(resp)
        }
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `PUT /rbs/v0/resource/policy/{policy_id}`: Update policy.
#[utoipa::path(
    put,
    path = "/rbs/v0/resource/policy/{policy_id}",
    operation_id = "updatePolicy",
    summary = "Update a policy",
    description = "Replace a policy (name, content_type, and content are all required — full replacement, not a patch). The version increments on every update; a concurrent update loses the race and fails with 409 (optimistic locking). User-scoped: 403 when owned by another user.",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    params(
        ("policy_id" = String, Path, description = "Policy ID"),
    ),
    request_body(content = UpdatePolicyRequest, description = "Full replacement values: new name, content encoding (`base64`), and base64-encoded Rego content."),
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
    log::info!("Policy update HTTP request received: id='{}', user='{}'", id, ctx.sub());
    if let Err(r) = validate_path_id(&id) { return r; }
    let body = body.into_inner();
    if let Err(e) = Validate::validate(&body) {
        log::error!("Policy update validation error: {}", e);
        return HttpResponse::BadRequest().json(ErrorBody::new(e.to_string()));
    }
    match core.policy().update(&ctx, &id, &body).await {
        Ok(resp) => {
            log::info!("Policy update succeeded: id='{}', user='{}'", id, ctx.sub());
            HttpResponse::Ok().json(resp)
        }
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `DELETE /rbs/v0/resource/policy/{policy_id}`: Single delete.
#[utoipa::path(
    delete,
    path = "/rbs/v0/resource/policy/{policy_id}",
    operation_id = "deletePolicy",
    summary = "Delete a policy",
    description = "Delete one policy owned by the caller. Rejected with 409 while any resource still references the policy — delete or rebind those resources first.",
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
    log::info!("Policy delete HTTP request received: id='{}', user='{}'", pid, ctx.sub());
    let pid_clone = pid.clone();
    if let Err(r) = validate_path_id(&pid) { return r; }
    match core.policy().delete(&ctx, &[pid]).await {
        Ok(()) => {
            log::info!("Policy delete succeeded: id='{}', user='{}'", pid_clone, ctx.sub());
            HttpResponse::NoContent().finish()
        }
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `DELETE /rbs/v0/resource/policy?ids=id1,id2`: Batch delete.
#[utoipa::path(
    delete,
    path = "/rbs/v0/resource/policy",
    operation_id = "batchDeletePolicies",
    summary = "Batch delete policies",
    description = "Delete up to 10 policies in a single transaction. All IDs must exist and belong to the caller; rejected with 409 (nothing deleted) when any listed policy is still referenced by a resource.",
    tags = ["Policy"],
    security(("bearerAuth" = [])),
    params(
        ("ids" = String, Query, description = "Comma-separated policy IDs (maximum 10 IDs)"),
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
    log::info!("Policy batch_delete HTTP request received: user='{}'", ctx.sub());
    let ids: Vec<String> = query.ids.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if ids.len() > POLICY_BATCH_DELETE_MAX_IDS {
        let msg = format!("policy batch_delete denied: ids count {} exceeds maximum {}", ids.len(), POLICY_BATCH_DELETE_MAX_IDS);
        log::error!("{}", msg);
        return HttpResponse::BadRequest().json(ErrorBody::new(msg));
    }
    for id in &ids {
        if let Err(msg) = validate_policy_id(id) {
            log::error!("Policy batch_delete validation error: {}", msg);
            return HttpResponse::BadRequest().json(ErrorBody::new(msg));
        }
    }
    match core.policy().delete(&ctx, &ids).await {
        Ok(()) => {
            log::info!("Policy batch_delete succeeded: count={}, user='{}'", ids.len(), ctx.sub());
            HttpResponse::NoContent().finish()
        }
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

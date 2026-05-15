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

//! Resource routes (`/rbs/v0/{res_provider}/{...}`).

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, http::StatusCode};
use rbs_api_types::{
    CreateResourceRequest, ErrorBody, ResourceContentResponse,
    ResourceResponse, UpdateResourceRequest,
};
use rbs_core::auth::{Auth, TokenType};
use rbs_core::RbsCore;
use std::sync::Arc;

use crate::middleware::OptAuthContext;

fn require_auth(req: &HttpRequest) -> Result<rbs_core::AuthContext, HttpResponse> {
    req.extensions().get::<OptAuthContext>().and_then(|c| c.0.clone())
        .ok_or_else(|| HttpResponse::Unauthorized().json(ErrorBody::new("authentication required".to_string())))
}

fn error_response(e: impl ToString, status: u16) -> HttpResponse {
    HttpResponse::build(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .json(ErrorBody::new(e.to_string()))
}

fn build_uri(path: &str) -> String { format!("/rbs/v0/{}", path) }

/// `POST /rbs/v0/{uri}`: Create resource.
#[utoipa::path(
    post,
    path = "/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}",
    operation_id = "createResource",
    summary = "Create resource",
    tags = ["Resource"],
    security(("bearerAuth" = [])),
    request_body = CreateResourceRequest,
    params(
        ("res_provider" = String, Path, description = "Resource provider name"),
        ("repository_name" = String, Path, description = "Repository name"),
        ("resource_type" = String, Path, description = "Resource type (secret, cert, etc.)"),
        ("resource_name" = String, Path, description = "Resource name"),
    ),
    responses(
        (status = 201, description = "Resource created", body = ResourceResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Resource already exists", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn create_resource(
    core: web::Data<Arc<RbsCore>>, path: web::Path<String>,
    body: web::Json<CreateResourceRequest>, req: HttpRequest,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let mut cr = body.into_inner();
    cr.uri = build_uri(&path.into_inner());
    match core.resource().create(&ctx, &cr).await {
        Ok(resp) => HttpResponse::Created().json(resp),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `GET /rbs/v0/{uri}`: Retrieve resource content.
#[utoipa::path(
    get,
    path = "/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}",
    operation_id = "getResource",
    summary = "Get resource content",
    tags = ["Resource"],
    security(("bearerAuth" = []), ("attestAuth" = [])),
    params(
        ("res_provider" = String, Path, description = "Resource provider name"),
        ("repository_name" = String, Path, description = "Repository name"),
        ("resource_type" = String, Path, description = "Resource type (secret, cert, etc.)"),
        ("resource_name" = String, Path, description = "Resource name"),
    ),
    responses(
        (status = 200, description = "Resource content (base64-encoded JWE)", body = ResourceContentResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Resource not found or access denied", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn get_resource(
    core: web::Data<Arc<RbsCore>>, path: web::Path<String>, req: HttpRequest,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let uri = build_uri(&path.into_inner());
    match core.resource().get_content(&ctx, &uri).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `PUT /rbs/v0/{uri}`: Update or create resource.
#[utoipa::path(
    put,
    path = "/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}",
    operation_id = "updateResource",
    summary = "Update or create resource",
    tags = ["Resource"],
    security(("bearerAuth" = [])),
    request_body = UpdateResourceRequest,
    params(
        ("res_provider" = String, Path, description = "Resource provider name"),
        ("repository_name" = String, Path, description = "Repository name"),
        ("resource_type" = String, Path, description = "Resource type (secret, cert, etc.)"),
        ("resource_name" = String, Path, description = "Resource name"),
    ),
    responses(
        (status = 200, description = "Resource updated", body = ResourceResponse),
        (status = 201, description = "Resource created", body = ResourceResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn update_resource(
    core: web::Data<Arc<RbsCore>>, path: web::Path<String>,
    body: web::Json<UpdateResourceRequest>, req: HttpRequest,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let uri = build_uri(&path.into_inner());
    match core.resource().update(&ctx, &uri, &body.into_inner()).await {
        Ok((resp, true)) => HttpResponse::Created().json(resp),
        Ok((resp, false)) => HttpResponse::Ok().json(resp),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `DELETE /rbs/v0/{uri}`: Delete resource.
#[utoipa::path(
    delete,
    path = "/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}",
    operation_id = "deleteResource",
    summary = "Delete resource",
    tags = ["Resource"],
    security(("bearerAuth" = [])),
    params(
        ("res_provider" = String, Path, description = "Resource provider name"),
        ("repository_name" = String, Path, description = "Repository name"),
        ("resource_type" = String, Path, description = "Resource type (secret, cert, etc.)"),
        ("resource_name" = String, Path, description = "Resource name"),
    ),
    responses(
        (status = 204, description = "Resource deleted"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Resource not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn delete_resource(
    core: web::Data<Arc<RbsCore>>, path: web::Path<String>, req: HttpRequest,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let uri = build_uri(&path.into_inner());
    match core.resource().delete(&ctx, &uri).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `GET /rbs/v0/{uri}/info`: Get resource metadata.
#[utoipa::path(
    get,
    path = "/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info",
    operation_id = "getResourceInfo",
    summary = "Get resource metadata",
    tags = ["Resource"],
    security(("bearerAuth" = []), ("attestAuth" = [])),
    params(
        ("res_provider" = String, Path, description = "Resource provider name"),
        ("repository_name" = String, Path, description = "Repository name"),
        ("resource_type" = String, Path, description = "Resource type (secret, cert, etc.)"),
        ("resource_name" = String, Path, description = "Resource name"),
    ),
    responses(
        (status = 200, description = "Resource metadata", body = ResourceResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Resource not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn get_resource_info(
    core: web::Data<Arc<RbsCore>>, path: web::Path<String>, req: HttpRequest,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let uri = build_uri(&path.into_inner());
    match core.resource().get_info(&ctx, &uri).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

/// `POST /rbs/v0/{uri}/retrieve`: Retrieve resource with attestation evidence.
///
/// The client submits RBC evidences in the request body. The service calls the
/// configured attestation backend to verify the evidence and obtain an attest
/// token, then uses the token claims (including `tee-pubkey`) for Rego policy
/// evaluation and JWE encryption of the resource content.
#[utoipa::path(
    post,
    path = "/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve",
    operation_id = "retrieveResource",
    summary = "Retrieve resource with attestation evidence",
    tags = ["Resource"],
    security(()),
    params(
        ("res_provider" = String, Path, description = "Resource provider name"),
        ("repository_name" = String, Path, description = "Repository name"),
        ("resource_type" = String, Path, description = "Resource type (secret, cert, etc.)"),
        ("resource_name" = String, Path, description = "Resource name"),
    ),
    responses(
        (status = 200, description = "Resource content (base64-encoded JWE)", body = ResourceContentResponse),
        (status = 404, description = "Resource not found or access denied", body = ErrorBody),
        (status = 502, description = "Attestation backend error", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn retrieve_resource(
    core: web::Data<Arc<RbsCore>>,
    auth: web::Data<Arc<dyn Auth>>,
    path: web::Path<String>,
    body: web::Json<rbs_api_types::ResourceRetrieveRequest>,
    _req: HttpRequest,
) -> HttpResponse {
    let uri = build_uri(&path.into_inner());

    // Step 1: call attestation backend with evidence to obtain an attest token.
    let attest_resp = match core.attestation().attest(body.into_inner()).await {
        Ok(resp) => resp,
        Err(e) => return error_response(e.to_string(), 502),
    };

    // Step 2: parse the attest token to extract claims (containing tee-pubkey etc.).
    let attest_ctx = match auth.authenticate(&attest_resp.token, TokenType::Attest).await {
        Ok(rbs_core::AuthContext::Attest(ctx)) => ctx,
        Ok(_) => return error_response("attest token resolved to unexpected auth context", 500),
        Err(e) => return error_response(e.to_string(), 500),
    };

    // Step 3: retrieve resource content — policy evaluation + backend fetch + JWE encrypt + base64.
    match core.resource().retrieve(&attest_ctx, &uri).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => error_response(e.to_string(), e.http_status()),
    }
}

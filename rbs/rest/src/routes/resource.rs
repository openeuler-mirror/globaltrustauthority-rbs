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

use actix_web::{web, HttpResponse, http::StatusCode};
use rbs_api_types::{
    error::RbsError, ErrorBody, ResourceContentResponse, ResourceInfoResponse, ResourceMetadataResponse,
    ResourceRetrieveRequest, ResourceUpsertRequest,
};
use rbs_core::RbsCore;
use std::sync::Arc;

/// `GET /rbs/v0/{uri}`: Retrieve resource content.
#[utoipa::path(
    get,
    path = "/rbs/v0/{uri:.+}",
    operation_id = "getResource",
    summary = "Get resource content by URI",
    tags = ["Resource"],
    security(()),
    params(
        ("uri" = String, Path, description = "Resource URI (format: {res_provider}/{repository_name}/{resource_type}/{resource_name})")
    ),
    responses(
        (status = 200, description = "Resource content (JSON).", body = ResourceContentResponse),
        (status = 400, description = "Invalid URI or request.", body = ErrorBody),
        (status = 404, description = "Resource not found.", body = ErrorBody),
        (status = 409, description = "Resource conflict.", body = ErrorBody),
        (status = 429, description = "Rate limit exceeded.", body = ErrorBody),
        (status = 503, description = "Provider not found or unavailable.", body = ErrorBody),
        (status = 500, description = "Internal server error.", body = ErrorBody),
    )
)]
pub async fn get_resource(
    core: web::Data<Arc<RbsCore>>,
    path: web::Path<String>,
) -> HttpResponse {
    let uri = path.into_inner();
    match core.resource().get(&uri).await {
        Ok(Some(resp)) => HttpResponse::Ok().json(resp),
        Ok(None) => HttpResponse::NotFound().json(ErrorBody::new(RbsError::ResourceNotFound.external_message())),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

/// `PUT /rbs/v0/{uri}`: Create or update resource.
#[utoipa::path(
    put,
    path = "/rbs/v0/{uri:.+}",
    operation_id = "upsertResource",
    summary = "Create or update resource",
    tags = ["Resource"],
    security(()),
    params(
        ("uri" = String, Path, description = "Resource URI")
    ),
    request_body = ResourceUpsertRequest,
    responses(
        (status = 200, description = "Resource metadata (JSON).", body = ResourceMetadataResponse),
        (status = 400, description = "Invalid URI or request.", body = ErrorBody),
        (status = 404, description = "Provider not found.", body = ErrorBody),
        (status = 409, description = "Resource conflict.", body = ErrorBody),
        (status = 429, description = "Rate limit exceeded.", body = ErrorBody),
        (status = 503, description = "Provider not found or unavailable.", body = ErrorBody),
        (status = 500, description = "Internal server error.", body = ErrorBody),
    )
)]
pub async fn upsert_resource(
    core: web::Data<Arc<RbsCore>>,
    path: web::Path<String>,
    body: web::Json<ResourceUpsertRequest>,
) -> HttpResponse {
    let uri = path.into_inner();
    match core.resource().upsert(&uri, &body.into_inner()).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

/// `DELETE /rbs/v0/{uri}`: Delete resource.
#[utoipa::path(
    delete,
    path = "/rbs/v0/{uri:.+}",
    operation_id = "deleteResource",
    summary = "Delete resource by URI",
    tags = ["Resource"],
    security(()),
    params(
        ("uri" = String, Path, description = "Resource URI")
    ),
    responses(
        (status = 204, description = "Resource deleted."),
        (status = 400, description = "Invalid URI or request.", body = ErrorBody),
        (status = 404, description = "Resource or provider not found.", body = ErrorBody),
        (status = 429, description = "Rate limit exceeded.", body = ErrorBody),
        (status = 503, description = "Provider not found or unavailable.", body = ErrorBody),
        (status = 500, description = "Internal server error.", body = ErrorBody),
    )
)]
pub async fn delete_resource(
    core: web::Data<Arc<RbsCore>>,
    path: web::Path<String>,
) -> HttpResponse {
    let uri = path.into_inner();
    match core.resource().delete(&uri).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

/// `GET /rbs/v0/{uri}/info`: Get resource metadata (no content).
#[utoipa::path(
    get,
    path = "/rbs/v0/{uri}/info",
    operation_id = "getResourceInfo",
    summary = "Get resource metadata by URI",
    tags = ["Resource"],
    security(()),
    params(
        ("uri" = String, Path, description = "Resource URI")
    ),
    responses(
        (status = 200, description = "Resource metadata (JSON).", body = ResourceInfoResponse),
        (status = 400, description = "Invalid URI or request.", body = ErrorBody),
        (status = 404, description = "Resource not found.", body = ErrorBody),
        (status = 409, description = "Resource conflict.", body = ErrorBody),
        (status = 429, description = "Rate limit exceeded.", body = ErrorBody),
        (status = 503, description = "Provider not found or unavailable.", body = ErrorBody),
        (status = 500, description = "Internal server error.", body = ErrorBody),
    )
)]
pub async fn get_resource_info(
    core: web::Data<Arc<RbsCore>>,
    path: web::Path<String>,
) -> HttpResponse {
    let uri = path.into_inner();
    match core.resource().info(&uri).await {
        Ok(Some(resp)) => HttpResponse::Ok().json(resp),
        Ok(None) => HttpResponse::NotFound().json(ErrorBody::new(RbsError::ResourceNotFound.external_message())),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

/// `POST /rbs/v0/{uri}/retrieve`: Retrieve resource with attestation.
#[utoipa::path(
    post,
    path = "/rbs/v0/{uri}/retrieve",
    operation_id = "retrieveResource",
    summary = "Retrieve resource content with attestation evidence",
    tags = ["Resource"],
    security(()),
    params(
        ("uri" = String, Path, description = "Resource URI")
    ),
    request_body = ResourceRetrieveRequest,
    responses(
        (status = 200, description = "Resource content (JSON).", body = ResourceContentResponse),
        (status = 400, description = "Invalid URI or request.", body = ErrorBody),
        (status = 404, description = "Resource not found.", body = ErrorBody),
        (status = 409, description = "Resource conflict.", body = ErrorBody),
        (status = 429, description = "Rate limit exceeded.", body = ErrorBody),
        (status = 503, description = "Provider not found or unavailable.", body = ErrorBody),
        (status = 500, description = "Internal server error.", body = ErrorBody),
    )
)]
pub async fn retrieve_resource(
    core: web::Data<Arc<RbsCore>>,
    path: web::Path<String>,
    _body: web::Json<ResourceRetrieveRequest>,
) -> HttpResponse {
    let uri = path.into_inner();
    // TODO: Verify attestation token before retrieval
    match core.resource().get(&uri).await {
        Ok(Some(resp)) => HttpResponse::Ok().json(resp),
        Ok(None) => HttpResponse::NotFound().json(ErrorBody::new(RbsError::ResourceNotFound.external_message())),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

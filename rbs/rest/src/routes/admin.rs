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

//! Admin / user management routes (`/rbs/v0/users`).

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, http::StatusCode};
use rbs_api_types::{ErrorBody, Role, UserCreateRequest, UserListQuery, UserListResponse, UserResponse, UserUpdateRequest, validate_username};
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
        log::error!("Admin HTTP error response: status={}, error='{}'", status, msg);
    } else if status >= 400 {
        log::error!("Admin HTTP error response: status={}, error='{}'", status, msg);
    }
    HttpResponse::build(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .json(ErrorBody::new(msg))
}

/// `GET /rbs/v0/users`: List users (admin only).
#[utoipa::path(
    get,
    path = "/rbs/v0/users",
    operation_id = "listUsers",
    summary = "List users (admin only)",
    tags = ["Admin"],
    security(("bearerAuth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "Page size (1..100, default 10)"),
        ("offset" = Option<i64>, Query, description = "Offset (0..100000, default 0)"),
        ("role" = Option<Role>, Query, description = "Filter by role (admin or user)"),
        ("enabled" = Option<bool>, Query, description = "Filter by enabled status"),
    ),
    responses(
        (status = 200, description = "Paginated user list", body = UserListResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn list_users(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    query: web::Query<UserListQuery>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    log::info!("Admin list_users HTTP request received: user='{}'", ctx.sub());

    // Apply defaults before validation
    let mut query = query.into_inner();
    query.limit = Some(query.limit.unwrap_or(10));
    query.offset = Some(query.offset.unwrap_or(0));

    if let Err(e) = Validate::validate(&query) {
        log::error!("Admin list_users validation error: {}", e);
        return HttpResponse::BadRequest().json(ErrorBody { error: e.to_string() });
    }

    match core.admin().list_users(&query, &ctx).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => error_response(e.external_message(), e.http_status()),
    }
}

/// `POST /rbs/v0/users`: Create user (admin only).
#[utoipa::path(
    post,
    path = "/rbs/v0/users",
    operation_id = "createUser",
    summary = "Create a user (admin only)",
    tags = ["Admin"],
    security(("bearerAuth" = [])),
    request_body = UserCreateRequest,
    responses(
        (status = 201, description = "User created", body = UserResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Username already exists", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn create_user(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    body: web::Json<UserCreateRequest>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    log::info!("Admin create_user HTTP request received: user='{}'", ctx.sub());

    match core.admin().create_user(&body.into_inner(), &ctx).await {
        Ok(resp) => HttpResponse::Created().json(resp),
        Err(e) => error_response(e.external_message(), e.http_status()),
    }
}

/// `GET /rbs/v0/users/{username}`: Get user (admin or self).
#[utoipa::path(
    get,
    path = "/rbs/v0/users/{username}",
    operation_id = "getUser",
    summary = "Get a user (admin or self)",
    tags = ["Admin"],
    security(("bearerAuth" = [])),
    params(
        ("username" = String, Path, description = "Username"),
    ),
    responses(
        (status = 200, description = "User found", body = UserResponse),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "User not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn get_user(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let username = path.into_inner();
    log::info!("Admin get_user HTTP request received: username='{}', user='{}'", username, ctx.sub());

    if let Err(msg) = validate_username(&username) {
        log::error!("Admin get_user validation error: {}", msg);
        return HttpResponse::BadRequest().json(ErrorBody { error: msg });
    }

    match core.admin().get_user(&username, &ctx).await {
        Ok(Some(resp)) => HttpResponse::Ok().json(resp),
        Ok(None) => HttpResponse::NotFound().json(ErrorBody { error: "User not found".to_string() }),
        Err(e) => error_response(e.external_message(), e.http_status()),
    }
}

/// `PUT /rbs/v0/users/{username}`: Update user (admin or self).
#[utoipa::path(
    put,
    path = "/rbs/v0/users/{username}",
    operation_id = "updateUser",
    summary = "Update a user (admin or self)",
    tags = ["Admin"],
    security(("bearerAuth" = [])),
    params(
        ("username" = String, Path, description = "Username"),
    ),
    request_body = UserUpdateRequest,
    responses(
        (status = 200, description = "User updated", body = UserResponse),
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "User not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn update_user(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<UserUpdateRequest>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let username = path.into_inner();
    log::info!("Admin update_user HTTP request received: username='{}', user='{}'", username, ctx.sub());

    if let Err(msg) = validate_username(&username) {
        log::error!("Admin update_user validation error: {}", msg);
        return HttpResponse::BadRequest().json(ErrorBody { error: msg });
    }

    match core.admin().update_user(&username, &body.into_inner(), &ctx).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => error_response(e.external_message(), e.http_status()),
    }
}

/// `DELETE /rbs/v0/users/{username}`: Delete user (admin only).
#[utoipa::path(
    delete,
    path = "/rbs/v0/users/{username}",
    operation_id = "deleteUser",
    summary = "Delete a user (admin only)",
    tags = ["Admin"],
    security(("bearerAuth" = [])),
    params(
        ("username" = String, Path, description = "Username"),
    ),
    responses(
        (status = 204, description = "User deleted (no body)"),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "User not found", body = ErrorBody),
        (status = 500, description = "Internal error", body = ErrorBody),
    )
)]
pub async fn delete_user(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let ctx = match require_auth(&req) { Ok(c) => c, Err(r) => return r };
    let username = path.into_inner();
    log::info!("Admin delete_user HTTP request received: username='{}', user='{}'", username, ctx.sub());

    if let Err(msg) = validate_username(&username) {
        log::error!("Admin delete_user validation error: {}", msg);
        return HttpResponse::BadRequest().json(ErrorBody { error: msg });
    }

    match core.admin().delete_user(&username, &ctx).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => error_response(e.external_message(), e.http_status()),
    }
}
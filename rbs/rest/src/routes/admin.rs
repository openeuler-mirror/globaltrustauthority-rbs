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

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use rbs_api_types::{ErrorBody, Role, UserCreateRequest, UserListQuery, UserListResponse, UserResponse, UserUpdateRequest, validate_username};
use rbs_core::RbsCore;
use std::sync::Arc;

use crate::middleware::OptAuthContext;

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
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());

    // Apply defaults before validation
    let mut query = query.into_inner();
    query.limit = Some(query.limit.unwrap_or(10));
    query.offset = Some(query.offset.unwrap_or(0));

    if let Err(e) = validator::Validate::validate(&query) {
        return HttpResponse::BadRequest().json(ErrorBody { error: e.to_string() });
    }

    match auth_ctx {
        Some(ctx) => match core.admin().list_users(&query, &ctx).await {
            Ok(resp) => HttpResponse::Ok().json(resp),
            Err(e) => map_err(e),
        },
        None => HttpResponse::Unauthorized().json(ErrorBody { error: "Unauthorized".to_string() }),
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
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());

    match auth_ctx {
        Some(ctx) => match core.admin().create_user(&body.into_inner(), &ctx).await {
            Ok(resp) => HttpResponse::Created().json(resp),
            Err(e) => map_err(e),
        },
        None => HttpResponse::Unauthorized().json(ErrorBody { error: "Unauthorized".to_string() }),
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
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let username = path.into_inner();
    if let Err(msg) = validate_username(&username) {
        return HttpResponse::BadRequest().json(ErrorBody { error: msg });
    }

    match auth_ctx {
        Some(ctx) => match core.admin().get_user(&username, &ctx).await {
            Ok(Some(resp)) => HttpResponse::Ok().json(resp),
            Ok(None) => HttpResponse::NotFound().json(ErrorBody { error: "User not found".to_string() }),
            Err(e) => map_err(e),
        },
        None => HttpResponse::Unauthorized().json(ErrorBody { error: "Unauthorized".to_string() }),
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
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let username = path.into_inner();
    if let Err(msg) = validate_username(&username) {
        return HttpResponse::BadRequest().json(ErrorBody { error: msg });
    }

    match auth_ctx {
        Some(ctx) => match core.admin().update_user(&username, &body.into_inner(), &ctx).await {
            Ok(resp) => HttpResponse::Ok().json(resp),
            Err(e) => map_err(e),
        },
        None => HttpResponse::Unauthorized().json(ErrorBody { error: "Unauthorized".to_string() }),
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
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let username = path.into_inner();
    if let Err(msg) = validate_username(&username) {
        return HttpResponse::BadRequest().json(ErrorBody { error: msg });
    }

    match auth_ctx {
        Some(ctx) => match core.admin().delete_user(&username, &ctx).await {
            Ok(()) => HttpResponse::NoContent().finish(),
            Err(e) => map_err(e),
        },
        None => HttpResponse::Unauthorized().json(ErrorBody { error: "Unauthorized".to_string() }),
    }
}

fn map_err(e: rbs_core::RbsError) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(e.http_status())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    HttpResponse::build(status).json(ErrorBody {
        error: e.external_message().to_string(),
    })
}

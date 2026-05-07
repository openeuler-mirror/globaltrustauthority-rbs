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
use rbs_api_types::{ErrorBody, UserCreateRequest, UserUpdateRequest};
use rbs_core::RbsCore;
use std::sync::Arc;

use crate::middleware::OptAuthContext;

/// `GET /rbs/v0/users`: List users (admin only).
pub async fn list_users(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    query: web::Query<UserListQuery>,
) -> HttpResponse {
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());

    let limit = match query.limit {
        Some(l) if l < 1 || l > 100 => {
            return HttpResponse::BadRequest().json(ErrorBody { error: "limit must be between 1 and 100".to_string() });
        }
        Some(l) => l,
        None => 50,
    };

    let offset = match query.offset {
        Some(o) if o < 0 => {
            return HttpResponse::BadRequest().json(ErrorBody { error: "offset must be non-negative".to_string() });
        }
        Some(o) => o,
        None => 0,
    };

    match auth_ctx {
        Some(ctx) => match core.admin().list_users(limit, offset, &ctx).await {
            Ok(resp) => HttpResponse::Ok().json(resp),
            Err(e) => map_err(e),
        },
        None => HttpResponse::Unauthorized().json(ErrorBody { error: "Unauthorized".to_string() }),
    }
}

#[derive(serde::Deserialize)]
pub struct UserListQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

/// `POST /rbs/v0/users`: Create user (admin only).
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
pub async fn get_user(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let username = path.into_inner();

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
pub async fn update_user(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<UserUpdateRequest>,
) -> HttpResponse {
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let username = path.into_inner();

    match auth_ctx {
        Some(ctx) => match core.admin().update_user(&username, &body.into_inner(), &ctx).await {
            Ok(resp) => HttpResponse::Ok().json(resp),
            Err(e) => map_err(e),
        },
        None => HttpResponse::Unauthorized().json(ErrorBody { error: "Unauthorized".to_string() }),
    }
}

/// `DELETE /rbs/v0/users/{username}`: Delete user (admin only).
pub async fn delete_user(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let username = path.into_inner();

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

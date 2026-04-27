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
use rbs_api_types::ErrorBody;
use rbs_core::policy::{PolicyCreateRequest, PolicyUpdateRequest};
use rbs_core::RbsCore;
use std::sync::Arc;

use crate::middleware::OptAuthContext;

/// `GET /rbs/v0/resource/policy`: List policies.
pub async fn list_policies(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    query: web::Query<PolicyListQuery>,
) -> HttpResponse {
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let limit = query.limit.unwrap_or(10).max(1);
    let offset = query.offset.unwrap_or(0).max(0);
    let ids = query.ids.as_deref();

    match core.policy().list(ids, limit, offset, auth_ctx).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

#[derive(serde::Deserialize)]
pub struct PolicyListQuery {
    ids: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// `POST /rbs/v0/resource/policy`: Create policy.
pub async fn create_policy(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    body: web::Json<PolicyCreateRequest>,
) -> HttpResponse {
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());

    match core.policy().create(&body.into_inner(), auth_ctx).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

/// `GET /rbs/v0/resource/policy/{policy_id}`: Get policy.
pub async fn get_policy(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let policy_id = path.into_inner();

    match core.policy().get(&policy_id, auth_ctx).await {
        Ok(Some(resp)) => HttpResponse::Ok().json(resp),
        Ok(None) => HttpResponse::NotFound().json(ErrorBody { error: "Policy not found".to_string() }),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

/// `PUT /rbs/v0/resource/policy/{policy_id}`: Update policy.
pub async fn update_policy(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<PolicyUpdateRequest>,
) -> HttpResponse {
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let policy_id = path.into_inner();

    match core.policy().update(&policy_id, &body.into_inner(), auth_ctx).await {
        Ok(Some(resp)) => HttpResponse::Ok().json(resp),
        Ok(None) => HttpResponse::NotFound().json(ErrorBody { error: "Policy not found".to_string() }),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

/// `DELETE /rbs/v0/resource/policy/{policy_id}`: Delete policy.
pub async fn delete_policy(
    core: web::Data<Arc<RbsCore>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let auth_ctx = req.extensions().get::<OptAuthContext>().and_then(|ctx| ctx.0.clone());
    let policy_id = path.into_inner();

    match core.policy().delete(&policy_id, auth_ctx).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::build(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
            .json(ErrorBody::new(e.external_message())),
    }
}

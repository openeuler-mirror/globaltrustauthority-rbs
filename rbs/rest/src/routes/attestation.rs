/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
 * PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Attestation routes (`/rbs/v0/challenge`).

use actix_web::{web, http::StatusCode, HttpResponse};
use rbs_api_types::{AttestRequest, AttestResponse, AuthChallengeResponse, ChallengeRequest, ErrorBody};
use rbs_core::RbsCore;
use std::sync::Arc;

/// `GET /rbs/v0/challenge`: 200 with `AuthChallengeResponse` JSON (nonce).
#[utoipa::path(
    get,
    path = "/rbs/v0/challenge",
    operation_id = "getAuthChallenge",
    summary = "Obtain an attestation challenge (nonce)",
    tags = ["Attestation"],
    security(()),
    params(
        ("as_provider" = Option<String>, Query, description = "Target provider ID for challenge")
    ),
    responses(
        (status = 200, description = "Challenge payload with nonce (JSON).", body = AuthChallengeResponse),
        (status = 503, description = "Attestation provider unavailable.", body = ErrorBody),
        (status = 500, description = "Internal server error.", body = ErrorBody),
    )
)]
pub async fn get_challenge(
    core: web::Data<Arc<RbsCore>>,
    query: web::Query<ChallengeRequest>,
) -> HttpResponse {
    let as_provider = query.as_provider.as_deref();
    match core.attestation().get_auth_challenge(as_provider).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => HttpResponse::build(
            StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        )
        .json(ErrorBody::new(e.external_message())),
    }
}

/// `POST /rbs/v0/attest`: 200 with `AttestResponse` JSON (token).
#[utoipa::path(
    post,
    path = "/rbs/v0/attest",
    operation_id = "postAttest",
    summary = "Submit attestation evidence and obtain token",
    tags = ["Attestation"],
    security(()),
    request_body = AttestRequest,
    responses(
        (status = 200, description = "Attestation token (JSON).", body = AttestResponse),
        (status = 400, description = "Invalid request.", body = ErrorBody),
        (status = 404, description = "Provider not found.", body = ErrorBody),
        (status = 500, description = "Internal server error.", body = ErrorBody),
    )
)]
pub async fn attest(
    core: web::Data<Arc<RbsCore>>,
    body: web::Json<AttestRequest>,
) -> HttpResponse {
    match core.attestation().attest(body.into_inner()).await {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => HttpResponse::build(
            StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        )
        .json(ErrorBody::new(e.external_message())),
    }
}
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

//! Version route (`GET /rbs/version`, no auth).

use actix_web::{web, HttpResponse};
use rbs_api_types::RbsVersion;
use rbs_core::RbsCore;
use std::sync::Arc;

/// `GET /rbs/version`: 200 with `RbsVersion` JSON (see `OpenAPI` `RbsVersion` / `BuildMetadata`).
#[utoipa::path(
    get,
    path = "/rbs/version",
    operation_id = "rbsVersion",
    summary = "Get service name, API version, and build metadata",
    tags = ["System"],
    security(()),
    responses(
        (status = 200, description = "Version payload: service name, API contract version, and build metadata (JSON).", body = RbsVersion),
    )
)]
pub async fn version(core: web::Data<Arc<RbsCore>>) -> HttpResponse {
    HttpResponse::Ok().json(core.system().version())
}

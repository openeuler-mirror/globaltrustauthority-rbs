/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
 * PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Health check endpoints (`/livez`, `/readyz`) served on the dedicated health listener.
//!
//! Plain HTTP, no TLS, no auth, and intentionally no middleware (no access logging,
//! no URI guard, no auth, no rate limit): kubelet probes are low-frequency and must
//! not enter the business middleware chain. The endpoints are not part of the OpenAPI
//! contract.

use std::time::Duration;

use actix_web::{web, HttpResponse};
use rbs_core::rdb::{self, DbError};
use serde::Serialize;

/// Timeout for the readiness probe. Independent of the business `storage.timeout`
/// (default 30s) so a slow dependency fails fast instead of hanging the probe.
const READYZ_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// TCP accept backlog for the health listener. Independent of `rest.listen_backlog`;
/// probe traffic is tiny.
pub(crate) const HEALTH_LISTEN_BACKLOG: u32 = 128;

/// Readiness failure reasons. Fixed dependency-name-level strings only — no connection
/// strings, paths, or dynamic error content may appear in probe responses.
const REASON_POOL_NOT_INITIALIZED: &str = "sqlite: connection pool not initialized";
const REASON_PING_FAILED: &str = "sqlite: ping failed";
const REASON_TIMEOUT: &str = "sqlite: probe timeout";

#[derive(Serialize)]
struct HealthOk {
    status: &'static str,
}

#[derive(Serialize)]
struct HealthErrorBody {
    status: &'static str,
    reason: String,
}

/// Register the health routes (`/livez`, `/readyz`) on a plain `App` (no middleware).
/// Shared by the dedicated health listener in `server::http` and integration tests.
///
/// Routes are registered via `web::resource().route(web::get()..)` rather than
/// `cfg.route(.., web::get()..)`: the latter hoists the method guard to the resource
/// level, which turns non-GET requests into 404; with resource-level registration a
/// method mismatch falls through to the resource's default service, which yields the
/// designed 405 (with an `Allow` header).
pub fn configure_health_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/livez").route(web::get().to(livez)))
        .service(web::resource("/readyz").route(web::get().to(readyz)));
}

/// Liveness: always 200 while the process can respond; no dependency checks — a dead
/// dependency must not trigger container restarts.
async fn livez() -> HttpResponse {
    HttpResponse::Ok().json(HealthOk { status: "ok" })
}

/// Readiness: SQLite availability via one pooled read query, bounded by a 2s timeout
/// (pool saturation also surfaces here: `pool.acquire` queues behind busy connections).
async fn readyz() -> HttpResponse {
    match tokio::time::timeout(READYZ_PROBE_TIMEOUT, rdb::ping()).await {
        Ok(Ok(())) => HttpResponse::Ok().json(HealthOk { status: "ok" }),
        Ok(Err(DbError::ConfigError(_))) => {
            log::warn!("readiness probe failed: connection pool not initialized");
            HttpResponse::ServiceUnavailable().json(HealthErrorBody {
                status: "error",
                reason: REASON_POOL_NOT_INITIALIZED.to_string(),
            })
        }
        Ok(Err(e)) => {
            log::warn!("readiness probe failed: {}", e);
            HttpResponse::ServiceUnavailable().json(HealthErrorBody {
                status: "error",
                reason: REASON_PING_FAILED.to_string(),
            })
        }
        Err(_) => {
            log::warn!("readiness probe timed out after {:?}", READYZ_PROBE_TIMEOUT);
            HttpResponse::ServiceUnavailable().json(HealthErrorBody {
                status: "error",
                reason: REASON_TIMEOUT.to_string(),
            })
        }
    }
}

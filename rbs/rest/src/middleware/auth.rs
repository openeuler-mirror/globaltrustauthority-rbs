/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You can use a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Authentication middleware.

use actix_web::{
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpMessage,
};
use rbs_api_types::ErrorBody;
use rbs_core::auth::{Auth, AuthContext};

/// Paths that do NOT require authentication
const PUBLIC_PATHS: &[&str] = &["/rbs/v0/challenge", "/rbs/v0/attest"];

/// Authentication middleware that extracts and verifies Bearer tokens.
///
/// For public paths (challenge, attest), no authentication is performed.
/// For other paths, extracts token from Authorization header and verifies it.
pub async fn auth_middleware(
    req: ServiceRequest,
    next: actix_web::middleware::Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let path = req.path().to_string();

    // Skip authentication for public paths
    if PUBLIC_PATHS.iter().any(|p| path.starts_with(p)) {
        return next.call(req).await;
    }

    // Extract Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            // Non-public path requires authentication
            let res = req.into_response(actix_web::HttpResponse::Unauthorized().json(ErrorBody {
                error: "Unauthorized".to_string(),
            }));
            return Ok(res.map_body(|_, b| actix_web::body::BoxBody::new(b)));
        }
    };

    // Get Authenticator from app_data
    let auth = req
        .app_data::<actix_web::web::Data<Arc<dyn Auth>>>()
        .map(|a| a.as_ref().clone());

    match auth {
        Some(auth) => {
            match auth.authenticate(token).await {
                Ok(auth_ctx) => {
                    req.extensions_mut().insert(OptAuthContext(Some(auth_ctx)));
                }
                Err(e) => {
                    log::debug!("Authentication failed: {}", e);
                    // Store error for handler to retrieve
                    req.extensions_mut().insert(AuthError(e));
                }
            }
        }
        None => {
            log::warn!("Authenticator not configured");
        }
    }

    next.call(req).await
}

/// Wrapper to store optional AuthContext in request extensions
#[derive(Clone, Debug)]
pub struct OptAuthContext(pub Option<AuthContext>);

/// Wrapper to store authentication error in request extensions
#[derive(Clone, Debug)]
pub struct AuthError(pub rbs_core::auth::AuthError);

use std::sync::Arc;

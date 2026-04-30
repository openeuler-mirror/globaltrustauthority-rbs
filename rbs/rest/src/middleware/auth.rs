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
use rbs_core::auth::{Auth, AuthContext, TokenType};

/// Paths that do NOT require authentication (exact match)
const PUBLIC_PATHS: &[&str] = &["/rbs/v0/challenge", "/rbs/v0/attest"];

/// Check if the path is a public endpoint (no authentication required)
///
/// Public endpoints:
/// - /rbs/v0/challenge
/// - /rbs/v0/attest
/// - /rbs/v0/{uri}/retrieve
fn is_public_path(path: &str) -> bool {
    // Exact match for static paths
    if PUBLIC_PATHS.contains(&path) {
        return true;
    }

    // Pattern match for retrieve endpoint: /rbs/v0/{uri}/retrieve
    if path.starts_with("/rbs/v0/") && path.ends_with("/retrieve") {
        let relative = &path["/rbs/v0/".len()..];
        // Ensure there's a {uri} before /retrieve
        return relative != "retrieve" && relative.ends_with("/retrieve");
    }

    false
}

/// Check if the path is a resource get endpoint (allows both Attest and Bearer token)
///
/// Resource Get endpoints:
/// - GET /rbs/v0/{uri}
/// - GET /rbs/v0/{uri}/info
///
/// Excluded (BearerToken only):
/// - /rbs/v0/resource/policy
/// - /rbs/v0/resource/policy/{policy_id}
fn is_resource_get_path(path: &str, method: &actix_web::http::Method) -> bool {
    // Resource Get only supports GET method
    if method != actix_web::http::Method::GET {
        return false;
    }

    // Must start with /rbs/v0/
    if !path.starts_with("/rbs/v0/") {
        return false;
    }

    // Get the relative path after /rbs/v0/
    let relative = &path["/rbs/v0/".len()..];

    // Empty path is not valid
    if relative.is_empty() {
        return false;
    }

    // Exclude policy management routes (BearerToken only)
    // Exact match: /rbs/v0/resource/policy
    // Prefix match: /rbs/v0/resource/policy/{policy_id}
    if relative == "resource/policy" || relative.starts_with("resource/policy/") {
        return false;
    }

    // All other GET requests are Resource Get endpoints
    // This includes:
    // - /rbs/v0/{uri} (matches any non-policy path)
    // - /rbs/v0/{uri}/info
    true
}

/// Authentication middleware that extracts and verifies Bearer tokens.
///
/// For public paths (challenge, attest, retrieve), no authentication is performed.
/// For resource get endpoints, both Attest and Bearer tokens are allowed.
/// For other paths, only Bearer tokens are allowed.
pub async fn auth_middleware(
    req: ServiceRequest,
    next: actix_web::middleware::Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let path = req.path().to_string();
    let method = req.method().clone();

    // Skip authentication for public paths
    if is_public_path(&path) {
        return next.call(req).await;
    }

    // Determine if AttestToken is allowed for this endpoint
    let attest_allowed = is_resource_get_path(&path, &method);

    // Extract Authorization header and determine token type
    let (token, token_type) = match req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(header) if header.starts_with("Bearer ") => (&header[7..], TokenType::Bearer),
        Some(header) if header.starts_with("Attest ") => {
            if !attest_allowed {
                let res = req.into_response(
                    actix_web::HttpResponse::Unauthorized().json(ErrorBody {
                        error: "AttestToken not allowed for this endpoint".to_string(),
                    }),
                );
                return Ok(res.map_body(|_, b| BoxBody::new(b)));
            }
            (&header[7..], TokenType::Attest)
        }
        _ => {
            // Non-public path requires authentication
            let res = req.into_response(actix_web::HttpResponse::Unauthorized().json(ErrorBody {
                error: "Unauthorized".to_string(),
            }));
            return Ok(res.map_body(|_, b| BoxBody::new(b)));
        }
    };

    // Get Authenticator from app_data
    let auth = match req
        .app_data::<actix_web::web::Data<Arc<dyn Auth>>>()
        .map(|a| a.as_ref().clone())
    {
        Some(auth) => auth,
        None => {
            log::error!("Authenticator not configured - rejecting request");
            let res = req.into_response(
                actix_web::HttpResponse::InternalServerError().json(ErrorBody {
                    error: "Internal server error".to_string(),
                }),
            );
            return Ok(res.map_body(|_, b| BoxBody::new(b)));
        }
    };

    match auth.authenticate(token, token_type).await {
        Ok(auth_ctx) => {
            req.extensions_mut().insert(OptAuthContext(Some(auth_ctx)));
        }
        Err(e) => {
            log::debug!("Authentication failed: {}", e);
            let res = req.into_response(
                actix_web::HttpResponse::Unauthorized().json(ErrorBody {
                    error: e.to_string(),
                }),
            );
            return Ok(res.map_body(|_, b| BoxBody::new(b)));
        }
    }

    next.call(req).await
}

/// Wrapper to store optional AuthContext in request extensions
#[derive(Clone, Debug)]
pub struct OptAuthContext(pub Option<AuthContext>);

use std::sync::Arc;

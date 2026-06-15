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

//! JSON error responses (`ErrorBody`) for framework-level HTTP errors (404, 414, 429).
//! Also includes `RequestDeserializeError` for logging request body/query
//! deserialization failures (e.g. invalid enum values, malformed JSON).

use actix_web::{HttpRequest, HttpResponse, ResponseError};
use rbs_api_types::ErrorBody;

/// No matching route under `/rbs` or `/rbs/v0`.
pub async fn not_found() -> HttpResponse {
    HttpResponse::NotFound().json(ErrorBody {
        error: "Not Found".to_string(),
    })
}

/// Custom error type for request body/query deserialization failures.
///
/// Logs the deserialization error and returns a `400 BadRequest` with
/// an `ErrorBody` JSON payload, so invalid auth_type, role, enabled,
/// jwk format etc. are properly recorded.
#[derive(Debug)]
pub struct RequestDeserializeError {
    message: String,
}

impl RequestDeserializeError {
    /// Create a new deserialization error from any actix-web payload error.
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for RequestDeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl ResponseError for RequestDeserializeError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::BadRequest().json(ErrorBody {
            error: self.message.clone(),
        })
    }
}

/// Error handler for `web::Json<T>` deserialization failures.
/// Logs the error at `warn` level (client-caused) and returns our `ErrorBody` format.
pub fn json_error_handler(err: actix_web::error::JsonPayloadError, _req: &HttpRequest) -> actix_web::Error {
    let msg = err.to_string();
    log::error!("Request body deserialization failed: {}", msg);
    RequestDeserializeError::new(msg).into()
}

/// Error handler for `web::Query<T>` deserialization failures.
/// Logs the error at `warn` level (client-caused) and returns our `ErrorBody` format.
pub fn query_error_handler(err: actix_web::error::QueryPayloadError, _req: &HttpRequest) -> actix_web::Error {
    let msg = err.to_string();
    log::error!("Query parameter deserialization failed: {}", msg);
    RequestDeserializeError::new(msg).into()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    #[actix_web::test]
    async fn not_found_returns_404_with_error_body() {
        let resp = super::not_found().await;
        assert_eq!(resp.status(), 404);
        let body_bytes = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let v: Value = serde_json::from_slice(&body_bytes).expect("body must be JSON");
        assert_eq!(v.get("error").and_then(|x| x.as_str()), Some("Not Found"));
    }
}

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

use actix_web::HttpResponse;
use rbs_api_types::ErrorBody;

/// No matching route under `/rbs` or `/rbs/v0`.
pub async fn not_found() -> HttpResponse {
    HttpResponse::NotFound().json(ErrorBody {
        error: "Not Found".to_string(),
    })
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

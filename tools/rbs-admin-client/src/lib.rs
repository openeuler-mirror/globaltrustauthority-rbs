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
pub mod attestation;
mod client;
mod error;
pub mod res_policy;
pub mod resource;
pub mod user;

use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::{info, warn};

pub use client::AdminClient;
pub use error::RbsAdminClientError;
pub use user::{UserClient, UserService};

/// Reject input that would change URL path semantics when appended as one path segment.
pub(crate) fn validate_path_segment(value: &str, field_name: &str) -> Result<(), RbsAdminClientError> {
    if value.trim().is_empty() {
        return Err(RbsAdminClientError::ClientError(format!("{field_name} must not be empty")));
    }
    if value == "."
        || value == ".."
        || value.contains(['/', '?', '#', '\\', '%'])
        || value.chars().any(char::is_control)
    {
        return Err(RbsAdminClientError::ClientError(format!(
            "{field_name} must not contain URL path control characters"
        )));
    }
    Ok(())
}

pub(crate) async fn send_empty<B>(
    client: &AdminClient,
    method: Method,
    url: Url,
    body: Option<&B>,
) -> Result<(), RbsAdminClientError>
where
    B: Serialize + ?Sized,
{
    send_raw(client, method, url, body).await.map(|_| ())
}

pub(crate) async fn send_json<T, B>(
    client: &AdminClient,
    method: Method,
    url: Url,
    body: Option<&B>,
) -> Result<T, RbsAdminClientError>
where
    T: DeserializeOwned,
    B: Serialize + ?Sized,
{
    let body = send_raw(client, method, url, body).await?;
    serde_json::from_str(&body).map_err(|err| {
        warn!(body_len = body.len(), error = %err, "failed to deserialize admin response");
        RbsAdminClientError::ClientError(
            "The service returned an unexpected response. Please try again later.".to_string(),
        )
    })
}

async fn send_raw<B>(
    client: &AdminClient,
    method: Method,
    url: Url,
    body: Option<&B>,
) -> Result<String, RbsAdminClientError>
where
    B: Serialize + ?Sized,
{
    let method_name = method.as_str().to_string();
    let url_text = url.to_string();
    info!(
        method = %method_name,
        url = %url_text,
        body_type = ?body.as_ref().map(|_| std::any::type_name::<B>()),
        "sending admin request"
    );
    let mut request = client.http_client.request(method, url).bearer_auth(client.bearer_token());
    if let Some(body) = body {
        request = request.json(body);
    }

    let response = request.send().await.map_err(|err| {
        warn!(method = %method_name, url = %url_text, error = %err, "admin request send failed");
        RbsAdminClientError::ClientError("Unable to connect to the service. Please try again later.".to_string())
    })?;
    let status = response.status();
    info!(method = %method_name, url = %url_text, status = %status, "received admin response");
    let body = response.text().await.map_err(|err| {
        warn!(method = %method_name, url = %url_text, status = %status, error = %err, "failed to read admin response body");
        RbsAdminClientError::ClientError("Unable to read the service response. Please try again later.".to_string())
    })?;

    if status.is_success() {
        Ok(body)
    } else {
        warn!(method = %method_name, url = %url_text, status = %status, body_len = body.len(), "admin request returned error");
        Err(http_error(status, &body))
    }
}

pub(crate) fn http_error(status: StatusCode, body: &str) -> RbsAdminClientError {
    let _ = body;
    RbsAdminClientError::ClientError(
        match status {
            StatusCode::BAD_REQUEST => "The request could not be completed. Please check your input and try again.",
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => "You do not have permission to perform this action.",
            StatusCode::NOT_FOUND => "The requested item was not found.",
            StatusCode::CONFLICT => "The request could not be completed. Please refresh and try again.",
            StatusCode::TOO_MANY_REQUESTS => "Too many requests. Please try again later.",
            status if status.is_server_error() => "The service is temporarily unavailable. Please try again later.",
            _ => "The request could not be completed. Please try again later.",
        }
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_maps_status_codes_to_sanitized_messages() {
        assert_eq!(
            http_error(StatusCode::BAD_REQUEST, "").to_string(),
            "The request could not be completed. Please check your input and try again."
        );
        assert_eq!(
            http_error(StatusCode::FORBIDDEN, "").to_string(),
            "You do not have permission to perform this action."
        );
        assert_eq!(http_error(StatusCode::NOT_FOUND, "").to_string(), "The requested item was not found.");
        assert_eq!(
            http_error(StatusCode::INTERNAL_SERVER_ERROR, "").to_string(),
            "The service is temporarily unavailable. Please try again later."
        );
    }

    #[test]
    fn path_segment_validator_rejects_ambiguous_values() {
        for value in ["../admin", "ops/user", "ops?debug=true", "ops#fragment", "ops\\user", "%2e%2e"] {
            assert!(validate_path_segment(value, "username").is_err(), "{value} should fail");
        }
    }
}

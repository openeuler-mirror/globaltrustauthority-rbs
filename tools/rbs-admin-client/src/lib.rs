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
mod client;
mod error;
pub mod user;

use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub use client::AdminClient;
pub use error::RbsAdminClientError;
pub use user::{
    CreateUserRequest, JwtVerification, ListUsersParams, UpdateUserRequest, User, UserClient, UserListResponse,
    UserService,
};

pub(crate) async fn send_empty(
    client: &crate::client::AdminClient,
    method: Method,
    url: Url,
) -> Result<(), RbsAdminClientError> {
    let response =
        client.http_client.request(method, url).bearer_auth(client.bearer_token()).send().await.map_err(|_| {
            RbsAdminClientError::ClientError("Unable to connect to the service. Please try again later.".to_string())
        })?;
    let status = response.status();
    let body = response.text().await.map_err(|_| {
        RbsAdminClientError::ClientError("Unable to read the service response. Please try again later.".to_string())
    })?;

    if status.is_success() {
        Ok(())
    } else {
        Err(http_error(status, &body))
    }
}

pub(crate) async fn send_empty_json<B>(
    client: &crate::client::AdminClient,
    method: Method,
    url: Url,
    body: &B,
) -> Result<(), RbsAdminClientError>
where
    B: Serialize + ?Sized,
{
    let response =
        client.http_client.request(method, url).bearer_auth(client.bearer_token()).json(body).send().await.map_err(
            |_| {
                RbsAdminClientError::ClientError(
                    "Unable to connect to the service. Please try again later.".to_string(),
                )
            },
        )?;
    let status = response.status();
    let body = response.text().await.map_err(|_| {
        RbsAdminClientError::ClientError("Unable to read the service response. Please try again later.".to_string())
    })?;

    if status.is_success() {
        Ok(())
    } else {
        Err(http_error(status, &body))
    }
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
    let mut request = client.http_client.request(method, url).bearer_auth(client.bearer_token());
    if let Some(body) = body {
        request = request.json(body);
    }

    let response = request.send().await.map_err(|_| {
        RbsAdminClientError::ClientError("Unable to connect to the service. Please try again later.".to_string())
    })?;
    let status = response.status();
    let body = response.text().await.map_err(|_| {
        RbsAdminClientError::ClientError("Unable to read the service response. Please try again later.".to_string())
    })?;

    if !status.is_success() {
        return Err(http_error(status, &body));
    }

    serde_json::from_str(&body).map_err(|_| {
        RbsAdminClientError::ClientError(
            "The service returned an unexpected response. Please try again later.".to_string(),
        )
    })
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

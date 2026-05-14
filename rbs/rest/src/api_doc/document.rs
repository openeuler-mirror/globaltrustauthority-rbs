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

#![allow(clippy::needless_for_each)] // utoipa `OpenApi` derive

use rbs_api_types::{
    API_VERSION, AttestRequest, AttestResponse, AuthChallengeResponse, BuildMetadata,
    ChallengeRequest, CreatePolicyRequest, CreateResourceRequest, ErrorBody,
    PolicyListResponse, PolicyResponse, RbsVersion, ResourceContentResponse,
    ResourceInfoResponse, ResourceResponse, UpdatePolicyRequest, UpdateResourceRequest,
    UserCreateRequest, UserListResponse, UserResponse, UserUpdateRequest,
};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearerAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("JWT Bearer Token. Obtain via Admin API or attestation."))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "attestAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("Attest")
                        .description(Some("Attest Token. Obtain via POST /rbs/v0/attest."))
                        .build(),
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "RBS REST API",
        version = API_VERSION,
        description = "Resource Broker Service (RBS) HTTP API.",
        license(name = "Mulan Permissive Software License, Version 2", url = "http://license.coscl.org.cn/MulanPSL2"),
        contact(name = "RBS open-source community", url = "https://gitcode.com/openeuler/globaltrustauthority-rbs"),
    ),
    servers(
        (url = "http://localhost:6666", description = "Default local development (see `rbs.yaml` `rest.listen_addr`)"),
    ),
    tags(
        (name = "System", description = "`RbsCore::system` — service identity and API/build version via `GET /rbs/version` (system metadata). Does not require authentication."),
        (name = "Admin", description = "User management CRUD — `GET/POST/PUT/DELETE /rbs/v0/users` (admin or self). Requires BearerToken."),
        (name = "Policy", description = "Policy CRUD — `GET/POST/PUT/DELETE /rbs/v0/resource/policy`. Requires BearerToken."),
        (name = "Resource", description = "Resource CRUD — `GET/POST/PUT/DELETE /rbs/v0/{provider}/{repo}/{type}/{name}`. Supports AttestToken and BearerToken."),
        (name = "Attestation", description = "Attestation challenge and token issuance via `GET /rbs/v0/challenge` and `POST /rbs/v0/attest`. No authentication required."),
    ),
    modifiers(&SecurityAddon),
    paths(
        crate::routes::version::version,
        crate::routes::admin::list_users,
        crate::routes::admin::create_user,
        crate::routes::admin::get_user,
        crate::routes::admin::update_user,
        crate::routes::admin::delete_user,
        crate::routes::attestation::get_challenge,
        crate::routes::attestation::attest,
        crate::routes::policy::list_policies,
        crate::routes::policy::create_policy,
        crate::routes::policy::get_policy,
        crate::routes::policy::update_policy,
        crate::routes::policy::delete_policy,
        crate::routes::policy::batch_delete_policies,
        crate::routes::resource::create_resource,
        crate::routes::resource::get_resource,
        crate::routes::resource::update_resource,
        crate::routes::resource::delete_resource,
        crate::routes::resource::get_resource_info,
        crate::routes::resource::retrieve_resource,
    ),
    components(schemas(
        RbsVersion, BuildMetadata, ErrorBody,
        UserCreateRequest, UserUpdateRequest, UserResponse, UserListResponse,
        CreatePolicyRequest, UpdatePolicyRequest, PolicyResponse, PolicyListResponse,
        CreateResourceRequest, UpdateResourceRequest, ResourceResponse,
        ResourceContentResponse, ResourceInfoResponse,
        AttestRequest, AttestResponse, AuthChallengeResponse, ChallengeRequest,
    ))
)]
pub struct ApiDoc;

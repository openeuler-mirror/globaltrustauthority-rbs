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
    ResourceListResponse, ResourceResponse, UpdatePolicyRequest,
    UpdateResourceRequest,
    UserCreateRequest, UserListResponse, UserResponse, UserUpdateRequest,
    AttestationDeleteType, AttestationPolicy,
    CertCreateRequest, CertDeleteRequest, CertListResponse,
    CertMutationResponse, CertRecord, CertUpdateRequest, CrlRecord, PolicyCreateRequest,
    PolicyDeleteRequest, PolicyDeleteType, PolicyMutationResponse, PolicyUpdateRequest,
    RefValue, RefValueCreateRequest, RefValueDeleteRequest,
    RefValueListResponse, RefValueMutationResponse, RefValueUpdateRequest,
};
use rbs_api_types::attestation_mgmt::AttestationPolicyListResponse;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

struct ContractAddon;

impl Modify for ContractAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearerAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some(
                            "JWT Bearer token. Send as `Authorization: Bearer <token>`. Sign with the JWT key configured for the user.",
                        ))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "attestAuth",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "Authorization",
                    "Enter the complete header value: `Attest <token>`. Obtain the token via \
                     `POST /rbs/v0/attest`.",
                ))),
            );
        }
        // These guards apply to every route, including public endpoints.
        for item in openapi.paths.paths.values_mut() {
            for operation in [
                &mut item.get, &mut item.post, &mut item.put, &mut item.delete,
                &mut item.patch, &mut item.head, &mut item.options, &mut item.trace,
            ].into_iter().flatten() {
                for (status, description) in [
                    ("414", "Request path and query string exceed the URI length limit"),
                    ("429", "Rate limit exceeded when per-IP rate limiting is enabled; retry later"),
                ] {
                    operation.responses.responses.entry(status.to_string()).or_insert_with(|| {
                        utoipa::openapi::ResponseBuilder::new()
                            .description(description)
                            .content("application/json", utoipa::openapi::Content::new(
                                Some(utoipa::openapi::Ref::from_schema_name("ErrorBody")),
                            ))
                            .build().into()
                    });
                }
            }
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
        (url = "http://127.0.0.1:6666", description = "Default local development (see `rbs.yaml` `rest.listen_addr`)"),
    ),
    tags(
        (name = "System", description = "`RbsCore::system` — service identity and API/build version via `GET /rbs/version` (system metadata). Does not require authentication."),
        (name = "Admin", description = "User management CRUD — `GET/POST/PUT/DELETE /rbs/v0/users` (admin or self). Requires BearerToken."),
        (name = "Policy", description = "Policy CRUD — `GET/POST/PUT/DELETE /rbs/v0/resource/policy`. Requires BearerToken."),
        (name = "Resource", description = "Resource CRUD — `GET/POST/PUT/DELETE /rbs/v0/{provider}/{repo}/{type}/{name}`. Supports AttestToken and BearerToken."),
        (name = "Attestation", description = "Attestation challenge/token issuance (`GET /rbs/v0/challenge`, `POST /rbs/v0/attest`, no auth) and attestation management CRUD for ref_value/cert/policy (`/rbs/v0/attestation/{as_provider}/{type}`, Bearer + admin only)."),
    ),
    modifiers(&ContractAddon),
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
        crate::routes::resource::list_resources,
        crate::routes::resource::create_resource,
        crate::routes::resource::get_resource,
        crate::routes::resource::update_resource,
        crate::routes::resource::delete_resource,
        crate::routes::resource::get_resource_info,
        crate::routes::resource::retrieve_resource,
        // Attestation management — ref_value (AR-001)
        crate::routes::attestation_mgmt::list_ref_values,
        crate::routes::attestation_mgmt::list_ref_values_default,
        crate::routes::attestation_mgmt::get_ref_value,
        crate::routes::attestation_mgmt::get_ref_value_default,
        crate::routes::attestation_mgmt::create_ref_value,
        crate::routes::attestation_mgmt::create_ref_value_default,
        crate::routes::attestation_mgmt::update_ref_value,
        crate::routes::attestation_mgmt::update_ref_value_default,
        crate::routes::attestation_mgmt::delete_ref_values,
        crate::routes::attestation_mgmt::delete_ref_values_default,
        crate::routes::attestation_mgmt::delete_ref_value,
        crate::routes::attestation_mgmt::delete_ref_value_default,
        // Attestation management — cert (AR-002)
        crate::routes::attestation_mgmt::list_certs,
        crate::routes::attestation_mgmt::list_certs_default,
        crate::routes::attestation_mgmt::get_cert,
        crate::routes::attestation_mgmt::get_cert_default,
        crate::routes::attestation_mgmt::create_cert,
        crate::routes::attestation_mgmt::create_cert_default,
        crate::routes::attestation_mgmt::update_cert,
        crate::routes::attestation_mgmt::update_cert_default,
        crate::routes::attestation_mgmt::delete_certs,
        crate::routes::attestation_mgmt::delete_certs_default,
        crate::routes::attestation_mgmt::delete_cert,
        crate::routes::attestation_mgmt::delete_cert_default,
        // Attestation management — policy (AR-003)
        crate::routes::attestation_mgmt::list_attestation_policies,
        crate::routes::attestation_mgmt::list_attestation_policies_default,
        crate::routes::attestation_mgmt::get_attestation_policy,
        crate::routes::attestation_mgmt::get_attestation_policy_default,
        crate::routes::attestation_mgmt::create_attestation_policy,
        crate::routes::attestation_mgmt::create_attestation_policy_default,
        crate::routes::attestation_mgmt::update_attestation_policy,
        crate::routes::attestation_mgmt::update_attestation_policy_default,
        crate::routes::attestation_mgmt::delete_attestation_policies,
        crate::routes::attestation_mgmt::delete_attestation_policies_default,
        crate::routes::attestation_mgmt::delete_attestation_policy,
        crate::routes::attestation_mgmt::delete_attestation_policy_default,
    ),
    components(schemas(
        RbsVersion, BuildMetadata, ErrorBody,
        UserCreateRequest, UserUpdateRequest, UserResponse, UserListResponse,
        CreatePolicyRequest, UpdatePolicyRequest, PolicyResponse, PolicyListResponse,
        CreateResourceRequest, UpdateResourceRequest, ResourceResponse,
        ResourceContentResponse, ResourceListResponse,
        AttestRequest, AttestResponse, AuthChallengeResponse, ChallengeRequest,
        // Attestation management schemas
        RefValue, RefValueListResponse,
        RefValueCreateRequest, RefValueUpdateRequest,
        RefValueMutationResponse,
        AttestationDeleteType, AttestationPolicy,
        CertRecord, CrlRecord, CertListResponse,
        CertCreateRequest, CertDeleteRequest, CertUpdateRequest, CertMutationResponse,
        AttestationPolicyListResponse,
        PolicyCreateRequest, PolicyDeleteRequest, PolicyDeleteType, PolicyUpdateRequest,
        PolicyMutationResponse,
        RefValueDeleteRequest,
    ))
)]
pub struct ApiDoc;

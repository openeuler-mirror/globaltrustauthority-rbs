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

//! Aggregate routes, mount under /rbs/v0.

use actix_web::web;

pub mod admin;
pub mod attestation;
pub mod attestation_mgmt;
pub mod error;
pub mod policy;
pub mod resource;
pub mod version;

pub use error::{not_found, json_error_handler, query_error_handler};

/// Configures routes under /rbs/v0 (scope is already /v0 when called from server).
///
/// Every method-specific endpoint is registered as a `web::resource` whose
/// `default_service` returns 404. Without this, an unsupported HTTP method on
/// such a path matches the path pattern but not any route, and actix falls
/// through to the greedy wildcard `GET/POST/PUT/DELETE /{uri:.+}` below — which
/// then runs the wrong handler (create/get/update/delete_resource) and yields
/// a misleading 401 (auth skipped for public paths, then `require_auth`
/// fails) or 400 (`validate_uri` rejects the extra `/info`|`/retrieve`
/// segment). The 404 `default_service` keeps the request within the matched
/// resource so unsupported methods simply report "not found".
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg
        // Attestation: challenge is GET-only (public), attest is POST-only (public).
        .service(
            web::resource("/challenge")
                .route(web::get().to(attestation::get_challenge))
                .default_service(web::to(not_found)),
        )
        .service(
            web::resource("/attest")
                .route(web::post().to(attestation::attest))
                .default_service(web::to(not_found)),
        )
        // Policy routes
        .service(
            web::resource("/resource/policy")
                .route(web::get().to(policy::list_policies))
                .route(web::post().to(policy::create_policy))
                .route(web::delete().to(policy::batch_delete_policies))
                .default_service(web::to(not_found)),
        )
        .service(
            web::resource("/resource/policy/{policy_id}")
                .route(web::get().to(policy::get_policy))
                .route(web::put().to(policy::update_policy))
                .route(web::delete().to(policy::delete_policy))
                .default_service(web::to(not_found)),
        )
        // Admin / user management routes (MUST be before wildcard routes)
        .service(
            web::resource("/users")
                .route(web::get().to(admin::list_users))
                .route(web::post().to(admin::create_user))
                .default_service(web::to(not_found)),
        )
        .service(
            web::resource("/users/{username}")
                .route(web::get().to(admin::get_user))
                .route(web::put().to(admin::update_user))
                .route(web::delete().to(admin::delete_user))
                .default_service(web::to(not_found)),
        )
        // Attestation management routes (MUST be before wildcard routes)
        // ref_value — with as_provider
        .service(
            web::resource("/attestation/{as_provider}/ref_value")
                .route(web::get().to(attestation_mgmt::list_ref_values))
                .route(web::post().to(attestation_mgmt::create_ref_value))
                .route(web::put().to(attestation_mgmt::update_ref_value))
                .route(web::delete().to(attestation_mgmt::delete_ref_values))
                .default_service(web::to(not_found)),
        )
        .service(
            web::resource("/attestation/{as_provider}/ref_value/{id}")
                .route(web::get().to(attestation_mgmt::get_ref_value))
                .route(web::delete().to(attestation_mgmt::delete_ref_value))
                .default_service(web::to(not_found)),
        )
        // ref_value — without as_provider (default gta)
        .service(
            web::resource("/attestation/ref_value")
                .route(web::get().to(attestation_mgmt::list_ref_values_default))
                .route(web::post().to(attestation_mgmt::create_ref_value_default))
                .route(web::put().to(attestation_mgmt::update_ref_value_default))
                .route(web::delete().to(attestation_mgmt::delete_ref_values_default))
                .default_service(web::to(not_found)),
        )
        .service(
            web::resource("/attestation/ref_value/{id}")
                .route(web::get().to(attestation_mgmt::get_ref_value_default))
                .route(web::delete().to(attestation_mgmt::delete_ref_value_default))
                .default_service(web::to(not_found)),
        )
        // cert — with as_provider
        .service(
            web::resource("/attestation/{as_provider}/cert")
                .route(web::get().to(attestation_mgmt::list_certs))
                .route(web::post().to(attestation_mgmt::create_cert))
                .route(web::put().to(attestation_mgmt::update_cert))
                .route(web::delete().to(attestation_mgmt::delete_certs))
                .default_service(web::to(not_found)),
        )
        .service(
            web::resource("/attestation/{as_provider}/cert/{id}")
                .route(web::get().to(attestation_mgmt::get_cert))
                .route(web::delete().to(attestation_mgmt::delete_cert))
                .default_service(web::to(not_found)),
        )
        // cert — without as_provider (default gta)
        .service(
            web::resource("/attestation/cert")
                .route(web::get().to(attestation_mgmt::list_certs_default))
                .route(web::post().to(attestation_mgmt::create_cert_default))
                .route(web::put().to(attestation_mgmt::update_cert_default))
                .route(web::delete().to(attestation_mgmt::delete_certs_default))
                .default_service(web::to(not_found)),
        )
        .service(
            web::resource("/attestation/cert/{id}")
                .route(web::get().to(attestation_mgmt::get_cert_default))
                .route(web::delete().to(attestation_mgmt::delete_cert_default))
                .default_service(web::to(not_found)),
        )
        // attestation policy — with as_provider
        .service(
            web::resource("/attestation/{as_provider}/policy")
                .route(web::get().to(attestation_mgmt::list_attestation_policies))
                .route(web::post().to(attestation_mgmt::create_attestation_policy))
                .route(web::put().to(attestation_mgmt::update_attestation_policy))
                .route(web::delete().to(attestation_mgmt::delete_attestation_policies))
                .default_service(web::to(not_found)),
        )
        .service(
            web::resource("/attestation/{as_provider}/policy/{id}")
                .route(web::get().to(attestation_mgmt::get_attestation_policy))
                .route(web::delete().to(attestation_mgmt::delete_attestation_policy))
                .default_service(web::to(not_found)),
        )
        // attestation policy — without as_provider (default gta)
        .service(
            web::resource("/attestation/policy")
                .route(web::get().to(attestation_mgmt::list_attestation_policies_default))
                .route(web::post().to(attestation_mgmt::create_attestation_policy_default))
                .route(web::put().to(attestation_mgmt::update_attestation_policy_default))
                .route(web::delete().to(attestation_mgmt::delete_attestation_policies_default))
                .default_service(web::to(not_found)),
        )
        .service(
            web::resource("/attestation/policy/{id}")
                .route(web::get().to(attestation_mgmt::get_attestation_policy_default))
                .route(web::delete().to(attestation_mgmt::delete_attestation_policy_default))
                .default_service(web::to(not_found)),
        )
        // Resource routes (wildcard - must be last)
        .service(
            web::resource("/{uri:.+}/info")
                .route(web::get().to(resource::get_resource_info))
                .default_service(web::to(not_found)),
        )
        // retrieve is a public POST-only endpoint.
        .service(
            web::resource("/{uri:.+}/retrieve")
                .route(web::post().to(resource::retrieve_resource))
                .default_service(web::to(not_found)),
        )
        .route("/{uri:.+}", web::post().to(resource::create_resource))
        .route("/{uri:.+}", web::get().to(resource::get_resource))
        .route("/{uri:.+}", web::put().to(resource::update_resource))
        .route("/{uri:.+}", web::delete().to(resource::delete_resource))
        .default_service(web::to(not_found));
}

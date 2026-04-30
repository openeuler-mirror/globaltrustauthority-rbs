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

pub mod auth;
pub mod error;
pub mod policy;
pub mod resource;
pub mod version;

pub use error::not_found;

/// Configures routes under /rbs/v0 (scope is already /v0 when called from server).
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.route("/challenge", web::get().to(auth::get_challenge))
    .route("/attest", web::post().to(auth::attest))
    // Policy routes
    .route("/resource/policy", web::get().to(policy::list_policies))
    .route("/resource/policy", web::post().to(policy::create_policy))
    .route("/resource/policy/{policy_id}", web::get().to(policy::get_policy))
    .route("/resource/policy/{policy_id}", web::put().to(policy::update_policy))
    .route("/resource/policy/{policy_id}", web::delete().to(policy::delete_policy))
    // Resource routes
    .route("/{uri:.+}/info", web::get().to(resource::get_resource_info))
    .route("/{uri:.+}/retrieve", web::post().to(resource::retrieve_resource))
    .route("/{uri:.+}", web::get().to(resource::get_resource))
    .route("/{uri:.+}", web::put().to(resource::upsert_resource))
    .route("/{uri:.+}", web::delete().to(resource::delete_resource))
    .default_service(web::to(not_found));
}

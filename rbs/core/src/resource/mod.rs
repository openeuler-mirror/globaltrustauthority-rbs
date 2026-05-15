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

//! Resource Manager and Provider management.

pub mod adapter;
pub mod config;
pub mod error;
pub mod repository;
pub mod service;
pub mod validator;

pub use config::ResourceConfig;
pub use error::ResourceError;
pub use repository::{ResourceEntity, ResourceRepository, SeaOrmResourceRepository};
pub use rbs_api_types::{
    CreateResourceRequest, ResourceContentResponse, ResourceInfoResponse, ResourceResponse,
    UpdateResourceRequest, ATTEST_TEE_PUBKEY_KEY, BEARER_ENC_PUBKEY_KEY,
};
pub use service::ResourceService;
pub use validator::{ParsedUri, ResourceValidator};

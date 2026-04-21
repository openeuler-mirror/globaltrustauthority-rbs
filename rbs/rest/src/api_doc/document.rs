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

use rbs_api_types::{API_VERSION, BuildMetadata, ErrorBody, RbsVersion};
use utoipa::OpenApi;

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
    ),
    paths(
        crate::routes::version::version,
    ),
    components(schemas(RbsVersion, BuildMetadata, ErrorBody))
)]
pub struct ApiDoc;

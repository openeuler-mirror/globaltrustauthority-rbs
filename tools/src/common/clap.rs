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
use crate::common::validate::validate_i64;
use crate::common::DEFAULT_PAGE_LIMIT;
use crate::common::DEFAULT_PAGE_OFFSET;
use crate::common::MAX_PAGE_LIMIT;
use crate::common::MAX_PAGE_OFFSET;
use crate::common::MIN_PAGE_LIMIT;
use crate::common::MIN_PAGE_OFFSET;
use clap::Args;

#[derive(Args, Debug, Clone)]
pub struct Page {
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT, value_parser = |limit: &str| validate_i64(limit, MIN_PAGE_LIMIT, MAX_PAGE_LIMIT, "limit"), help = "Maximum number of users to return")]
    pub limit: i64,

    #[arg(long, default_value_t = DEFAULT_PAGE_OFFSET, value_parser = |offset: &str| validate_i64(offset, MIN_PAGE_OFFSET, MAX_PAGE_OFFSET, "offset"), help = "Pagination offset")]
    pub offset: i64,
}

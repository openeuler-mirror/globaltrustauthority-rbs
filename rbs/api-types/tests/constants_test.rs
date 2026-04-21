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

//! Integration tests for constants.

use rbs_api_types::{API_PREFIX, RESOURCE_TYPES};

#[test]
fn test_api_prefix() {
    assert_eq!(API_PREFIX, "/rbs/v0");
}

#[test]
fn test_resource_types() {
    assert_eq!(RESOURCE_TYPES.len(), 3);
    assert!(RESOURCE_TYPES.contains(&"key"));
    assert!(RESOURCE_TYPES.contains(&"secret"));
    assert!(RESOURCE_TYPES.contains(&"cert"));
}

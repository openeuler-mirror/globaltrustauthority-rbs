/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Integration test: `RbsVersion` serde JSON round-trip (shape for `GET /rbs/version`).

use rbs_api_types::{
    API_VERSION, BUILD_DATE_PLACEHOLDER, GIT_HASH_PLACEHOLDER, RbsVersion, SERVICE_NAME,
};

#[test]
fn rbs_version_json_roundtrip_preserves_fixture() {
    let fixture = serde_json::json!({
        "service_name": SERVICE_NAME,
        "api_version": API_VERSION,
        "build": {
            "version": "9.8.7",
            "git_hash": GIT_HASH_PLACEHOLDER,
            "build_date": BUILD_DATE_PLACEHOLDER
        }
    });
    let decoded: RbsVersion = serde_json::from_value(fixture.clone()).expect("deserialize");
    assert_eq!(decoded.service_name, SERVICE_NAME);
    assert_eq!(decoded.api_version, API_VERSION);
    assert_eq!(decoded.build.version, "9.8.7");
    let encoded = serde_json::to_value(&decoded).expect("serialize");
    assert_eq!(encoded, fixture);
}

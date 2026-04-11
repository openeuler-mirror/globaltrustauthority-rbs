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

//! Integration tests for `rbs_core` version API (`core.system().version()`, `RbsVersion`, constants).

use rbs_api_types::{API_VERSION, RbsVersion, SERVICE_NAME};
use rbs_core::RbsCore;

fn version_info() -> RbsVersion {
    RbsCore::default().system().version()
}

#[test]
fn version_returns_expected_service_and_api_version() {
    let info = version_info();
    assert_eq!(info.service_name, SERVICE_NAME);
    assert_eq!(info.api_version, API_VERSION);
}

#[test]
fn version_build_release_version_is_always_set() {
    let info = version_info();
    assert!(!info.build.version.is_empty(), "build.version must come from Cargo");
}

#[test]
fn version_serializes_to_json_with_expected_keys() {
    let info = version_info();
    let json = serde_json::to_value(&info).expect("RbsVersion must serialize to JSON");
    assert_eq!(json.get("service_name").and_then(|v| v.as_str()), Some(SERVICE_NAME));
    assert_eq!(json.get("api_version").and_then(|v| v.as_str()), Some(API_VERSION));
    let build = json.get("build").expect("build must be present");
    assert!(!build.get("version").and_then(|v| v.as_str()).unwrap_or("").is_empty());
    assert!(build.get("git_hash").and_then(|v| v.as_str()).is_some());
    assert!(build.get("build_date").and_then(|v| v.as_str()).is_some());
}

#[test]
fn version_is_consistent_across_calls() {
    let a = version_info();
    let b = version_info();
    assert_eq!(a.service_name, b.service_name);
    assert_eq!(a.api_version, b.api_version);
    assert_eq!(a.build.version, b.build.version);
    assert_eq!(a.build.git_hash, b.build.git_hash);
    assert_eq!(a.build.build_date, b.build.build_date);
}

#[test]
fn version_json_round_trips() {
    let info = version_info();
    let json = serde_json::to_value(&info).expect("serialize");
    let parsed: RbsVersion = serde_json::from_value(json.clone()).expect("deserialize");
    assert_eq!(parsed.service_name, info.service_name);
    assert_eq!(parsed.api_version, info.api_version);
    assert_eq!(parsed.build.version, info.build.version);
    assert_eq!(parsed.build.git_hash, info.build.git_hash);
    assert_eq!(parsed.build.build_date, info.build.build_date);
}

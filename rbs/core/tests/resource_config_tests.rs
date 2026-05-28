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

//! Unit tests for `ResourceConfig` -- default values.

use rbs_core::resource::config::ResourceConfig;

// ===========================================================================
// Default values
// ===========================================================================

#[test]
fn test_default_max_resource_name_len() {
    assert_eq!(ResourceConfig::default().max_resource_name_len, 32);
}

#[test]
fn test_default_max_repo_name_len() {
    assert_eq!(ResourceConfig::default().max_repo_name_len, 32);
}

#[test]
fn test_default_max_additional_info_len() {
    assert_eq!(ResourceConfig::default().max_additional_info_len, 512);
}

#[test]
fn test_default_allowed_resource_types() {
    let types = ResourceConfig::default().allowed_resource_types;
    assert_eq!(types.len(), 2);
    assert!(types.contains(&"secret".to_string()));
    assert!(types.contains(&"cert".to_string()));
}

#[test]
fn test_default_allowed_content_types() {
    let types = ResourceConfig::default().allowed_content_types;
    assert!(types.contains(&"jwt".to_string()));
    assert!(types.contains(&"json".to_string()));
    assert!(types.contains(&"text".to_string()));
    assert!(types.contains(&"binary".to_string()));
    assert!(types.contains(&"jwk".to_string()));
    assert!(types.contains(&"jwe".to_string()));
    // "xml" is not allowed (existing test UT-RV-009 confirms this)
    assert!(!types.contains(&"xml".to_string()));
}

#[test]
fn test_default_allowed_export_modes() {
    let modes = ResourceConfig::default().allowed_export_modes;
    assert_eq!(modes.len(), 1);
    assert!(modes.contains(&"jwe".to_string()));
}

#[test]
fn test_default_configured_backends() {
    let backends = ResourceConfig::default().configured_backends;
    assert_eq!(backends.len(), 1);
    assert!(backends.contains(&"vault".to_string()));
}

#[test]
fn test_clone() {
    let cfg = ResourceConfig::default();
    let cloned = cfg.clone();
    assert_eq!(cloned.max_resource_name_len, cfg.max_resource_name_len);
    assert_eq!(cloned.allowed_resource_types, cfg.allowed_resource_types);
}
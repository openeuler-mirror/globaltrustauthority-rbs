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

//! Unit tests for `PolicyConfig` -- default values.

use rbs_core::policy::config::PolicyConfig;

// ===========================================================================
// Default values
// ===========================================================================

#[test]
fn test_default_max_per_user() {
    assert_eq!(PolicyConfig::default().max_per_user, 10);
}

#[test]
fn test_default_max_content_size_kb() {
    assert_eq!(PolicyConfig::default().max_content_size_kb, 128);
}

#[test]
fn test_default_max_page_size() {
    assert_eq!(PolicyConfig::default().max_page_size, 100);
}

#[test]
fn test_default_name_blacklist_not_empty() {
    assert!(!PolicyConfig::default().name_blacklist.is_empty());
}

#[test]
fn test_default_max_name_len() {
    assert_eq!(PolicyConfig::default().max_name_len, 255);
}

#[test]
fn test_name_blacklist_contains_default_forbidden_chars() {
    let blacklist: Vec<char> = PolicyConfig::default().name_blacklist;
    // Default blacklist: < > " ' & | \ / * ?
    assert!(blacklist.contains(&'<'));
    assert!(blacklist.contains(&'>'));
    assert!(blacklist.contains(&'"'));
    assert!(blacklist.contains(&'\''));
    assert!(blacklist.contains(&'&'));
}
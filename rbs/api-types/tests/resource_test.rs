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

//! Integration tests for resource types.

use rbs_api_types::{
    CreateResourceRequest, ResourceContentResponse, ResourceInfoResponse,
    ResourceResponse, ResourceRetrieveRequest, UpdateResourceRequest,
};

#[test]
fn test_resource_content_response() {
    let json = serde_json::json!({
        "uri": "/rbs/v0/vault/repo1/secret/mykey",
        "content": "SGVsbG9Xb3JsZA==",
        "content_type": "application/json",
        "export_mode": "jwe"
    });
    let resp: ResourceContentResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.uri, "/rbs/v0/vault/repo1/secret/mykey");
    assert_eq!(resp.content, "SGVsbG9Xb3JsZA==");
    assert_eq!(resp.content_type.as_deref(), Some("application/json"));
    assert_eq!(resp.export_mode, "jwe");
}

#[test]
fn test_resource_info_response() {
    let json = serde_json::json!({
        "uri": "/rbs/v0/provider1/repo1/key/mykey",
        "user_id": "user1",
        "policy_id": "pol-001",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
        "content_type": "application/json",
        "export_mode": "jwe"
    });
    let resp: ResourceInfoResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.uri, "/rbs/v0/provider1/repo1/key/mykey");
    assert_eq!(resp.user_id, "user1");
    assert_eq!(resp.export_mode, "jwe");
}

#[test]
fn test_resource_retrieve_request_is_attest_request() {
    let json = serde_json::json!({
        "rbc_evidences": {
            "measurements": [{"nonce": "test-nonce"}]
        }
    });
    let req: ResourceRetrieveRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.rbc_evidences.measurements[0].nonce, "test-nonce");
}

#[test]
fn test_create_resource_request() {
    let json = serde_json::json!({
        "policy_id": "pol-001",
        "content_type": "json",
        "export_mode": "jwe"
    });
    let req: CreateResourceRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.policy_id, "pol-001");
    assert_eq!(req.export_mode.as_deref(), Some("jwe"));
}

#[test]
fn test_create_resource_request_defaults() {
    let json = serde_json::json!({
        "policy_id": "pol-001"
    });
    let req: CreateResourceRequest = serde_json::from_value(json).unwrap();
    assert!(req.export_mode.is_none());
    assert!(req.content_type.is_none());
}

#[test]
fn test_update_resource_request() {
    let json = serde_json::json!({
        "policy_id": "pol-002",
        "export_mode": "jwe"
    });
    let req: UpdateResourceRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req.policy_id.as_deref(), Some("pol-002"));
    assert_eq!(req.export_mode.as_deref(), Some("jwe"));
}

#[test]
fn test_update_resource_request_policy_id_length_bounds() {
    use validator::Validate;

    // `policy_id` is optional on update, but when present the length bounds
    // (1..=36, mirroring the UUID-v4 policy id) must still be enforced.
    let ok = UpdateResourceRequest { policy_id: None, content_type: None, export_mode: None, additional_info: None, content: None };
    assert!(ok.validate().is_ok(), "None policy_id should pass");

    let empty = UpdateResourceRequest { policy_id: Some(String::new()), content_type: None, export_mode: None, additional_info: None, content: None };
    assert!(empty.validate().is_err(), "empty policy_id should fail min=1");

    let too_long = UpdateResourceRequest { policy_id: Some("x".repeat(37)), content_type: None, export_mode: None, additional_info: None, content: None };
    assert!(too_long.validate().is_err(), "37-char policy_id should fail max=36");

    let max = UpdateResourceRequest { policy_id: Some("x".repeat(36)), content_type: None, export_mode: None, additional_info: None, content: None };
    assert!(max.validate().is_ok(), "36-char policy_id should pass");
}

#[test]
fn test_resource_response() {
    let json = serde_json::json!({
        "uri": "/rbs/v0/vault/repo1/secret/mykey",
        "provider_name": "vault",
        "repository_name": "repo1",
        "resource_type": "secret",
        "resource_name": "mykey",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
        "content_type": "json",
        "export_mode": "jwe",
        "policy_id": "pol-001"
    });
    let resp: ResourceResponse = serde_json::from_value(json).unwrap();
    assert_eq!(resp.uri, "/rbs/v0/vault/repo1/secret/mykey");
    assert_eq!(resp.repository_name, "repo1");
    assert_eq!(resp.export_mode, "jwe");
    assert_eq!(resp.policy_id, "pol-001");
}

// ── T6: tagged enum serde round-trip & defaults ──

#[test]
fn tc001_vault_variant_serde_roundtrip() {
    use rbs_api_types::config::ResourceProviderConfig;
    let json = serde_json::json!({
        "type": "vault",
        "url": "https://v:8200",
        "token": "x",
        "mount_path": "secret",
        "allowed_resource_types": ["secret", "cert"]
    });
    let cfg: ResourceProviderConfig = serde_json::from_value(json).unwrap();
    assert!(matches!(cfg, ResourceProviderConfig::Vault(_)));
    let back = serde_json::to_value(&cfg).unwrap();
    assert_eq!(back["type"], "vault");
}

#[test]
fn tc002_ca_variant_serde_roundtrip() {
    use rbs_api_types::config::ResourceProviderConfig;
    let json = serde_json::json!({
        "type": "ca",
        "url": "https://ca:8080",
        "message_protection_cert_file": "/c.crt",
        "message_protection_key_file": "/c.key",
        "response_protection_trust_anchors_file": "/a.pem",
        "allowed_resource_types": ["cert"]
    });
    let cfg: ResourceProviderConfig = serde_json::from_value(json).unwrap();
    assert!(matches!(cfg, ResourceProviderConfig::Ca(_)));
    let back = serde_json::to_value(&cfg).unwrap();
    assert_eq!(back["type"], "ca");
}

#[test]
fn tc003_hsm_variant_serde_roundtrip() {
    use rbs_api_types::config::ResourceProviderConfig;
    let json = serde_json::json!({
        "type": "hsm",
        "module_path": "/softhsm.so",
        "slot": {"label": "rbs"},
        "credentials": {"pin_env": "RBS_HSM_PIN"},
        "allowed_resource_types": ["key", "secret"]
    });
    let cfg: ResourceProviderConfig = serde_json::from_value(json).unwrap();
    assert!(matches!(cfg, ResourceProviderConfig::Hsm(_)));
    let back = serde_json::to_value(&cfg).unwrap();
    assert_eq!(back["type"], "hsm");
}

#[test]
fn tc025_caconfig_defaults() {
    use rbs_api_types::config::{CaConfig, ResourceProviderConfig};
    let json = serde_json::json!({
        "type": "ca",
        "url": "https://ca:8080",
        "message_protection_cert_file": "/c.crt",
        "message_protection_key_file": "/c.key",
        "response_protection_trust_anchors_file": "/a.pem",
        "allowed_resource_types": ["cert"]
    });
    let cfg: ResourceProviderConfig = serde_json::from_value(json).unwrap();
    if let ResourceProviderConfig::Ca(ca) = cfg {
        assert_eq!(ca.max_response_bytes, 1_048_576);
        assert_eq!(ca.idempotency.max_entries, 1000);
        assert_eq!(ca.idempotency.ttl_seconds, 300);
        assert_eq!(ca.timeout, 30);
    } else { panic!("expected Ca variant"); }
}

#[test]
fn tc026_hsmconfig_pin_env_is_name() {
    use rbs_api_types::config::{HsmConfig, ResourceProviderConfig};
    let json = serde_json::json!({
        "type": "hsm",
        "module_path": "/softhsm.so",
        "slot": {"label": "rbs"},
        "credentials": {"pin_env": "RBS_HSM_PIN"},
        "allowed_resource_types": ["key", "secret"]
    });
    let cfg: ResourceProviderConfig = serde_json::from_value(json).unwrap();
    if let ResourceProviderConfig::Hsm(h) = cfg {
        assert_eq!(h.credentials.pin_env, "RBS_HSM_PIN");
        assert_eq!(h.max_key_bytes, 1_048_576);
        assert_eq!(h.timeout, 30);
    } else { panic!("expected Hsm variant"); }
}

#[test]
fn tc027_unknown_type_rejected() {
    use rbs_api_types::config::ResourceProviderConfig;
    let json = serde_json::json!({"type": "etcd", "url": "x"});
    let result: Result<ResourceProviderConfig, _> = serde_json::from_value(json);
    assert!(result.is_err());
}

#[test]
fn tc028_missing_type_rejected() {
    use rbs_api_types::config::ResourceProviderConfig;
    let json = serde_json::json!({"url": "https://v:8200"});
    let result: Result<ResourceProviderConfig, _> = serde_json::from_value(json);
    assert!(result.is_err());
}

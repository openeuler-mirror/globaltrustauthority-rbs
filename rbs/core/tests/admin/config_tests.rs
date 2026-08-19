/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! AdminConfig validation tests.

use std::collections::HashMap;

use rbs_api_types::config::{
    AdminConfig, AdminKeyConfig, AttestationBackendConfig, AttestationBackendMode,
    AttestationBuiltinConfig, AttestationConfig, AttestationCredentials, AttestationRestConfig,
    AuthConfig, BearerTokenVerificationConfig, AttestTokenVerificationConfig, LoggingConfig,
    PolicyLimitsConfig, RbsConfig, Sensitive,
};

fn make_valid_rbs_config() -> RbsConfig {
    let mut backends = HashMap::new();
    backends.insert(
        "gta".to_string(),
        AttestationBackendConfig {
            mode: AttestationBackendMode::Rest,
            rest: AttestationRestConfig {
                base_url: "https://gta.example.com".to_string(),
                timeout_secs: 30,
                retries: 3,
                tls_verify: true,
                ca_file: String::new(),
                client_cert_path: String::new(),
                client_key_path: String::new(),
                credentials: AttestationCredentials {
                    user_id: "valid-user-1".to_string(),
                    main_api_key: Sensitive::new(String::new()),
                    sub_api_key: Sensitive::new(String::new()),
                },
            },
            builtin: AttestationBuiltinConfig::default(),
        },
    );
    RbsConfig {
        rest: None,
        logging: LoggingConfig::default(),
        storage: None,
        attestation: AttestationConfig {
            default_as_provider: "gta".to_string(),
            backends,
        },
        auth: AuthConfig {
            attest_token: AttestTokenVerificationConfig {
                public_key_path: Some("/tmp/dummy_attest.pem".to_string()),
                jwks_file: None,
                issuer: "Global Trust Authority".to_string(),
                audience: Some("rbs".to_string()),
            },
            bearer_token: BearerTokenVerificationConfig {
                issuer: "Global Trust Authority".to_string(),
                audience: "rbs".to_string(),
            },
        },
        admin: AdminConfig {
            max_users: 10,
            admin_key: AdminKeyConfig {
                public_key_path: Some("/tmp/dummy_admin.pem".to_string()),
                jwks_file: None,
            },
        },
        policy: PolicyLimitsConfig::default(),
        resource: None,
    }
}

// ===========================================================================
// RUST_GTA_RBS_TP_USER_Config_001 — 配置验证-正常与异常和边界值
// ===========================================================================

/// test_point_id: RUST_GTA_RBS_TP_USER_Config_001
/// max_users=1 (minimum valid) passes config validation.
#[test]
fn test_user_config_001_max_users_1_passes() {
    let mut config = make_valid_rbs_config();
    config.admin.max_users = 1;
    config.validate();
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Config_001
/// max_users=100 (maximum valid) passes config validation.
#[test]
fn test_user_config_001_max_users_100_passes() {
    let mut config = make_valid_rbs_config();
    config.admin.max_users = 100;
    config.validate();
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Config_001
/// max_users=0 (below minimum) fails config validation.
#[test]
#[should_panic(expected = "max_users")]
fn test_user_config_001_max_users_0_panics() {
    let mut config = make_valid_rbs_config();
    config.admin.max_users = 0;
    config.validate();
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Config_001
/// max_users=101 (above maximum) fails config validation.
#[test]
#[should_panic(expected = "max_users")]
fn test_user_config_001_max_users_101_panics() {
    let mut config = make_valid_rbs_config();
    config.admin.max_users = 101;
    config.validate();
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Config_001
/// admin_key with neither public_key_path nor jwks_file fails validation.
#[test]
#[should_panic(expected = "either public_key_path or jwks_file")]
fn test_user_config_001_admin_key_empty_panics() {
    let mut config = make_valid_rbs_config();
    config.admin.admin_key = AdminKeyConfig {
        public_key_path: None,
        jwks_file: None,
    };
    config.validate();
}

/// test_point_id: RUST_GTA_RBS_TP_USER_Config_001
/// admin_key with both public_key_path and jwks_file fails validation (mutually exclusive).
#[test]
#[should_panic(expected = "mutually exclusive")]
fn test_user_config_001_admin_key_both_panics() {
    let mut config = make_valid_rbs_config();
    config.admin.admin_key = AdminKeyConfig {
        public_key_path: Some("/tmp/pub.pem".to_string()),
        jwks_file: Some("/tmp/jwks.json".to_string()),
    };
    config.validate();
}

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

//! Tests for `RbsCoreBuilder` wiring: provider registration, resource backend
//! registration, and the `RbsCore` accessors/Debug implementation.

use std::collections::HashMap;
use std::sync::{Arc, Once};

use rbs_api_types::config::{
    AttestationBackendConfig, AttestationBackendMode, AttestationBuiltinConfig, AttestationRestConfig, CoreConfig,
    Database, ResourceProviderConfig, ResourceProvidersConfig, Sensitive, VaultConfig,
};
use rbs_core::RbsCoreBuilder;

static INIT: Once = Once::new();

fn ensure_db() {
    INIT.call_once(|| {
        std::thread::spawn(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let path = std::env::temp_dir().join("rbs_core_builder.sqlite");
                for suffix in ["", "-wal", "-shm"] {
                    let _ = std::fs::remove_file(format!("{}{}", path.to_string_lossy(), suffix));
                }
                let config = Database {
                    db_type: "sqlite".to_string(),
                    url: format!("sqlite:{}?mode=rwc", path.to_string_lossy()),
                    max_connections: 2,
                    timeout: 30,
                    sql_file_path: String::new(),
                };
                let db = rbs_core::rdb::init_pool(&config).await.expect("init pool");
                rbs_core::rdb::migrate_core_tables(&db).await.expect("migrate core tables");
            });
        })
        .join()
        .expect("db init thread");
    });
}

fn rest_backend() -> AttestationBackendConfig {
    AttestationBackendConfig {
        mode: AttestationBackendMode::Rest,
        rest: AttestationRestConfig {
            base_url: "https://gta.example.com".to_string(),
            credentials: rbs_api_types::config::AttestationCredentials {
                user_id: "test-user".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
        builtin: AttestationBuiltinConfig::default(),
    }
}

fn config_with_backends() -> CoreConfig {
    let mut config = CoreConfig::default();
    config.attestation.default_as_provider = "gta".to_string();
    config.attestation.backends.insert("gta".to_string(), rest_backend());
    config.attestation.backends.insert(
        "builtin".to_string(),
        AttestationBackendConfig {
            mode: AttestationBackendMode::Builtin,
            rest: AttestationRestConfig::default(),
            builtin: AttestationBuiltinConfig::default(),
        },
    );
    config
}

#[test]
fn builder_registers_attestation_providers_and_accessors() {
    ensure_db();
    let core = RbsCoreBuilder::new(config_with_backends()).build();

    assert_eq!(core.attestation().default_name(), "gta");
    assert!(core.attestation().ref_value_for(Some("gta")).is_ok());
    assert!(core.attestation().cert_for(Some("builtin")).is_err());
    assert!(core.attestation().ref_value_for(Some("missing")).is_err());

    // Every accessor returns the corresponding service handle.
    assert_eq!(core.system().version().api_version, rbs_core::API_VERSION);
    let debug = format!("{:?}", core);
    assert!(debug.contains("RbsCore"), "debug={debug}");
    let _ = core.resource();
    let _ = core.policy();
    let _ = core.admin();
}

#[test]
fn builder_registers_vault_resource_backend() {
    ensure_db();
    let mut config = config_with_backends();
    let mut backends = HashMap::new();
    backends.insert(
        "vault".to_string(),
        ResourceProviderConfig::Vault(VaultConfig {
            url: "http://localhost:8200".to_string(),
            token: Sensitive::new("token".to_string()),
            mount_path: "secret".to_string(),
            kv_version: "v2".to_string(),
            verify_ssl: false,
            timeout: 10,
            max_connections: 5,
            max_retries: 1,
            max_response_body_bytes: 1024 * 1024,
            allowed_resource_types: vec!["secret".to_string()],
        }),
    );
    config.resource = Some(ResourceProvidersConfig { max_per_user: 5, backends });

    let core = RbsCoreBuilder::new(config).build();
    // The resource section overrides the per-user limit and backend set.
    assert_eq!(core.resource().validator.max_per_user(), 5);
    assert!(core.resource().validator.validate_res_provider("vault").is_ok());
}

#[test]
fn builder_without_resource_section_still_builds() {
    ensure_db();
    let core = RbsCoreBuilder::new(config_with_backends()).build();
    assert_eq!(core.resource().validator.max_per_user(), 10);
}

#[test]
fn rbs_core_new_and_getters_roundtrip() {
    ensure_db();
    let built = Arc::new(RbsCoreBuilder::new(config_with_backends()).build());
    assert_eq!(built.attestation().default_name(), "gta");
}

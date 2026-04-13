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

use rbc::sdk::{Config, ProviderRawConfig, ProviderType};

#[test]
fn test_config_builder() {
    let config = Config::builder()
        .endpoint("https://rbs.example.com")
        .timeout_secs(60)
        .evidence_provider(ProviderRawConfig {
            provider_type: ProviderType::Native,
            rest: Default::default(),
        })
        .token_provider(ProviderRawConfig {
            provider_type: ProviderType::Rbs,
            rest: Default::default(),
        })
        .build()
        .unwrap();

    assert_eq!(config.endpoint, "https://rbs.example.com");
    assert_eq!(config.timeout_secs, Some(60));
    assert_eq!(config.evidence_provider.provider_type, ProviderType::Native);
    assert_eq!(config.token_provider.provider_type, ProviderType::Rbs);
}

#[test]
fn test_config_builder_requires_endpoint() {
    let result = Config::builder()
        .evidence_provider(ProviderRawConfig {
            provider_type: ProviderType::Native,
            rest: Default::default(),
        })
        .token_provider(ProviderRawConfig {
            provider_type: ProviderType::Rbs,
            rest: Default::default(),
        })
        .build();

    assert!(result.is_err());
}

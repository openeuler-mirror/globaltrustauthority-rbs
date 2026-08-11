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

//! E2E dynamic-library entry point for GTA's real unified TPM attester plugin.

use gta_tpm_attester::attester::TpmPlugin;
use plugin_manager::{AgentPlugin, QueryConfigurationFn};

/// Keep GTA's implementation, including its exported `create_plugin`, in this dynamic library.
#[doc(hidden)]
pub fn link_tpm_plugin(
    query_configuration: QueryConfigurationFn,
    plugin_type: &str,
) -> Result<Box<dyn AgentPlugin>, plugin_manager::PluginError> {
    TpmPlugin::new(plugin_type.to_string(), query_configuration)
        .map(|plugin| Box::new(plugin) as Box<dyn AgentPlugin>)
}

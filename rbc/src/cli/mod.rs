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

pub mod args;
pub mod context;
pub mod execute;
pub mod output;

pub use args::{
    AttestArgs, AttesterArgs, ChallengeArgs, ClientAction, ClientCli, CollectEvidenceArgs, GetResourceArgs,
    GetTokenArgs, PolicyIdsArgs,
};
pub use context::{ClientCommandContext, ExecutionOptions};
pub use execute::{execute_action, CliError};
pub use output::{ClientOutput, OutputFormat};

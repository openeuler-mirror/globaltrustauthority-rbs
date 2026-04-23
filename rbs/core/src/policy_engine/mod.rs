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

//! Policy Engine module.
//!
//! Wraps the GTA `policy_engine` crate for Rego policy evaluation.

mod error;

pub use error::PolicyEngineError;

use policy_engine::evaluate_policy as gta_evaluate_policy;
use serde_json::Value;

/// Evaluate a Rego policy against input data.
///
/// # Arguments
///
/// * `input` - The JSON input data (evidence) to evaluate
/// * `policy` - The Rego policy string
/// * `is_safe_mode` - Whether to enable security checks (dangerous builtins, custom functions, cartesian products)
///
/// # Returns
///
/// Returns the evaluation result as a JSON Value, or an error if evaluation fails.
pub fn evaluate_policy(
    input: &Value,
    policy: &str,
    is_safe_mode: bool,
) -> Result<Value, PolicyEngineError> {
    gta_evaluate_policy(input, policy, is_safe_mode).map_err(|e| {
        PolicyEngineError::PolicyEvaluationError(e.to_string())
    })
}

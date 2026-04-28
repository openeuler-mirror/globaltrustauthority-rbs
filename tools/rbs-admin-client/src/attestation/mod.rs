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
pub mod cert;
pub mod policy;
pub mod ref_value;

pub use cert::CertClient;
pub use policy::PolicyClient;
pub use ref_value::RefValueClient;

const POLICY_SEGMENT: &str = "policy";
const REF_VALUE_SEGMENT: &str = "ref_value";
const CERT_SEGMENT: &str = "cert";
const DEFAULT_AS_PROVIDER: &str = "gta";

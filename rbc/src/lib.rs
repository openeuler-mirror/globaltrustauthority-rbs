/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Resource Broker Client (RBC) Library
//!

pub mod client;
pub mod evidence;
pub mod sdk;
pub mod token;
pub mod tools;
pub mod error;
pub mod ffi;

pub use error::RbcError;
pub use sdk::{Client, Config, ConfigBuilder, ProviderType, ProviderRawConfig, Session, GetResourceRequest, Resource};
pub use evidence::EvidenceProvider;
pub use token::TokenProvider;

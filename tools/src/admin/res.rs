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

use clap::{Args, Subcommand};
use rbs_admin_client::resource::{
    ResourceClient, ResourceCreateRequest, ResourceInfoResponse, ResourceMutationResponse, ResourcePath,
    ResourceResponse, ResourceService, ResourceUpdateRequest,
};
use rbs_admin_client::AdminClient;
use serde::Serialize;
use rbs_api_types::constants::RESOURCE_TYPES;

use crate::common::formatter::{Formatter, TextOutput};
use crate::common::utils::read_path_file;
use crate::common::validate::{validate_resource_segment, validate_trimmed_string_max_len};
use crate::config::GlobalOptions;
use crate::error::CliError;
const RESOURCE_CONTENT_TYPES: [&str; 6] = ["jwt", "json", "text", "binary", "jwk", "jwe"];
const EXPORT_MODES: [&str; 2] = ["plain", "jwe"];
const RESOURCE_SEGMENT_MAX_LEN: usize = 256;
const POLICY_ID_MAX_LEN: usize = 64;

#[derive(Args, Debug, Clone)]
#[command(about = "Manage key, secret, and cert resources")]
pub struct ResCli {
    #[command(subcommand)]
    pub command: ResCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ResCommand {
    #[command(
        about = "Get resource content",
        long_about = "Get resource content by resource path.\n\nExample:\n  rbs-cli res get vault default secret my-secret"
    )]
    Get(PathArgs),
    #[command(
        name = "get-res-info",
        alias = "info",
        about = "Get resource metadata",
        long_about = "Get resource metadata without returning resource content.\n\nExample:\n  rbs-cli res get-res-info vault default secret my-secret"
    )]
    GetResInfo(PathArgs),
    #[command(
        about = "Create a resource binding",
        long_about = "Create resource metadata for a key, secret, or cert resource.\n\nExample:\n  rbs-cli res create vault default secret my-secret --policy-id policy-1 --content-type text --export-mode plain"
    )]
    Create(MutateArgs),
    #[command(
        about = "Update a resource binding",
        long_about = "Update resource metadata for a key, secret, or cert resource.\n\nExample:\n  rbs-cli res update vault default secret my-secret --policy-id policy-1 --content-type text --export-mode jwe"
    )]
    Update(MutateArgs),
    #[command(
        about = "Delete a resource",
        long_about = "Delete a key, secret, or cert resource.\n\nExample:\n  rbs-cli res delete vault default secret my-secret"
    )]
    Delete(PathArgs),
}

#[derive(Args, Debug, Clone)]
pub struct PathArgs {
    #[arg(long, value_parser = |s: &str| validate_resource_segment(s, RESOURCE_SEGMENT_MAX_LEN), help = "Resource provider, for example vault")]
    pub res_provider: String,

    #[arg(long, value_parser = |s: &str| validate_resource_segment(s, RESOURCE_SEGMENT_MAX_LEN), help = "Repository or namespace name")]
    pub repository_name: String,

    #[arg(long, value_parser = RESOURCE_TYPES, help = "Type of the resource")]
    pub resource_type: String,

    #[arg(long, value_parser = |s: &str| validate_resource_segment(s, RESOURCE_SEGMENT_MAX_LEN), help = "Resource name")]
    pub resource_name: String,
}

#[derive(Args, Debug, Clone)]
pub struct MutateArgs {
    #[command(flatten)]
    pub path: PathArgs,

    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_ID_MAX_LEN, "policy_id"), help = "Bound resource policy ID")]
    pub policy_id: String,

    #[arg(long, value_parser = read_path_file, help = "Optional Base64 additional_info value or @file path")]
    pub additional_info: Option<String>,

    #[arg(long, value_parser = RESOURCE_CONTENT_TYPES, help = "Resource content type: jwt, json, text, binary, jwk, or jwe")]
    pub content_type: Option<String>,

    #[arg(long, value_parser = EXPORT_MODES, help = "Export mode: plain or jwe")]
    pub export_mode: Option<String>,
}

pub fn run(cli: &ResCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|err| CliError::Message(format!("failed to create async runtime: {err}")))?;
    let token = global
        .token
        .as_deref()
        .ok_or_else(|| CliError::InvalidArgument("missing required bearer token".to_string()))?;
    let service = ResourceClient::new(AdminClient::new(&global.base_url, token, &global.cert)?);
    runtime.block_on(execute_res_command(cli, &service))
}

async fn execute_res_command(cli: &ResCli, service: &ResourceClient) -> Result<Box<dyn Formatter>, CliError> {
    match &cli.command {
        ResCommand::Get(args) => {
            let resp = service.get_resource(&build_path(args)).await?;
            Ok(Box::new(ResourceOutput(resp)))
        },
        ResCommand::GetResInfo(args) => {
            let resp = service.get_resource_info(&build_path(args)).await?;
            Ok(Box::new(ResourceInfoOutput(resp)))
        },
        ResCommand::Create(args) => {
            let resp = service
                .create_resource(
                    &build_path(&args.path),
                    &ResourceCreateRequest {
                        policy_id: args.policy_id.clone(),
                        additional_info: args.additional_info.clone(),
                        content_type: args.content_type.clone(),
                        export_mode: args.export_mode.clone(),
                    },
                )
                .await?;
            Ok(Box::new(ResourceMutationOutput(resp)))
        },
        ResCommand::Update(args) => {
            let resp = service
                .update_resource(
                    &build_path(&args.path),
                    &ResourceUpdateRequest {
                        policy_id: args.policy_id.clone(),
                        additional_info: args.additional_info.clone(),
                        content_type: args.content_type.clone(),
                        export_mode: args.export_mode.clone(),
                    },
                )
                .await?;
            Ok(Box::new(ResourceMutationOutput(resp)))
        },
        ResCommand::Delete(args) => {
            let path = build_path(args);
            service.delete_resource(&path).await?;
            Ok(Box::new(TextOutput::new(format!("deleted resource: {}", resource_uri(&path)))))
        },
    }
}

fn build_path(args: &PathArgs) -> ResourcePath {
    ResourcePath {
        res_provider: args.res_provider.clone(),
        repository_name: args.repository_name.clone(),
        resource_type: args.resource_type.clone(),
        resource_name: args.resource_name.clone(),
    }
}

fn resource_uri(path: &ResourcePath) -> String {
    format!("{}/{}/{}/{}", path.res_provider, path.repository_name, path.resource_type, path.resource_name)
}

#[derive(Debug, Serialize)]
struct ResourceOutput(ResourceResponse);

impl Formatter for ResourceOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = vec![format!("uri: {}", self.0.uri), format!("content: {}", self.0.content)];
        if let Some(content_type) = &self.0.content_type {
            lines.push(format!("content_type: {content_type}"));
        }
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct ResourceInfoOutput(ResourceInfoResponse);

impl Formatter for ResourceInfoOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = vec![format!("uri: {}", self.0.uri)];
        if let Some(res_provider) = &self.0.res_provider {
            lines.push(format!("res_provider: {res_provider}"));
        }
        if let Some(repository_name) = &self.0.repository_name {
            lines.push(format!("repository_name: {repository_name}"));
        }
        if let Some(resource_type) = &self.0.resource_type {
            lines.push(format!("resource_type: {resource_type}"));
        }
        if let Some(resource_name) = &self.0.resource_name {
            lines.push(format!("resource_name: {resource_name}"));
        }
        if let Some(policy_id) = &self.0.policy_id {
            lines.push(format!("policy_id: {policy_id}"));
        }
        if let Some(content_type) = &self.0.content_type {
            lines.push(format!("content_type: {content_type}"));
        }
        if let Some(export_mode) = &self.0.export_mode {
            lines.push(format!("export_mode: {export_mode}"));
        }
        if let Some(content_length) = self.0.content_length {
            lines.push(format!("content_length: {content_length}"));
        }
        if let Some(created_at) = &self.0.created_at {
            lines.push(format!("created_at: {created_at}"));
        }
        if let Some(updated_at) = &self.0.updated_at {
            lines.push(format!("updated_at: {updated_at}"));
        }
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct ResourceMutationOutput(ResourceMutationResponse);

impl Formatter for ResourceMutationOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = Vec::new();
        if let Some(uri) = &self.0.uri {
            lines.push(format!("uri: {uri}"));
        }
        if let Some(res_provider) = &self.0.res_provider {
            lines.push(format!("res_provider: {res_provider}"));
        }
        if let Some(repository_name) = &self.0.repository_name {
            lines.push(format!("repository_name: {repository_name}"));
        }
        if let Some(resource_type) = &self.0.resource_type {
            lines.push(format!("resource_type: {resource_type}"));
        }
        if let Some(resource_name) = &self.0.resource_name {
            lines.push(format!("resource_name: {resource_name}"));
        }
        if let Some(policy_id) = &self.0.policy_id {
            lines.push(format!("policy_id: {policy_id}"));
        }
        if let Some(content_type) = &self.0.content_type {
            lines.push(format!("content_type: {content_type}"));
        }
        if let Some(export_mode) = &self.0.export_mode {
            lines.push(format!("export_mode: {export_mode}"));
        }
        if let Some(created_at) = &self.0.created_at {
            lines.push(format!("created_at: {created_at}"));
        }
        if let Some(updated_at) = &self.0.updated_at {
            lines.push(format!("updated_at: {updated_at}"));
        }
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

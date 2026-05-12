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
    ResourceClient, ResourceCreateRequest, ResourceInfoResponse, ResourcePath, ResourceResponse, ResourceService,
    ResourceUpdateRequest,
};
use rbs_admin_client::AdminClient;
use rbs_api_types::constants::RESOURCE_TYPES;
use serde::Serialize;

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
        long_about = "Get resource content by resource path.\n\nExample:\n  rbs-cli res get --res-provider vault --repository-name default --resource-type secret --resource-name my-secret"
    )]
    Get(PathArgs),
    #[command(
        name = "get-res-info",
        alias = "info",
        about = "Get resource metadata",
        long_about = "Get resource metadata without returning resource content.\n\nExample:\n  rbs-cli res get-res-info --res-provider vault --repository-name default --resource-type secret --resource-name my-secret"
    )]
    GetResInfo(PathArgs),
    #[command(
        about = "Create a resource binding",
        long_about = "Create resource metadata for a key, secret, or cert resource.\n\nExample:\n  rbs-cli res create --res-provider vault --repository-name default --resource-type secret --resource-name my-secret --policy-id policy-1 --content-type text --export-mode plain"
    )]
    Create(CreateArgs),
    #[command(
        about = "Update a resource binding",
        long_about = "Update resource metadata for a key, secret, or cert resource.\n\nExample:\n  rbs-cli res update --res-provider vault --repository-name default --resource-type secret --resource-name my-secret --policy-id policy-1 --content-type text --export-mode jwe"
    )]
    Update(UpdateArgs),
    #[command(
        about = "Delete a resource",
        long_about = "Delete a key, secret, or cert resource.\n\nExample:\n  rbs-cli res delete --res-provider vault --repository-name default --resource-type secret --resource-name my-secret"
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
pub struct CreateArgs {
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

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    #[command(flatten)]
    pub path: PathArgs,

    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_ID_MAX_LEN, "policy_id"), help = "Bound resource policy ID")]
    pub policy_id: Option<String>,

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
            Ok(Box::new(ResourceMetadataOutput(resp)))
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
            Ok(Box::new(ResourceMetadataOutput(resp)))
        },
        ResCommand::Update(args) => {
            validate_update_args(args)?;
            let resp = service
                .update_resource(
                    &build_path(&args.path),
                    &ResourceUpdateRequest {
                        policy_id: args.policy_id.clone().unwrap_or_default(),
                        additional_info: args.additional_info.clone(),
                        content_type: args.content_type.clone(),
                        export_mode: args.export_mode.clone(),
                    },
                )
                .await?;
            Ok(Box::new(ResourceMetadataOutput(resp)))
        },
        ResCommand::Delete(args) => {
            let path = build_path(args);
            service.delete_resource(&path).await?;
            Ok(Box::new(TextOutput::new(format!("Delete succeeded: resource removed: {}", resource_uri(&path)))))
        },
    }
}

fn validate_update_args(args: &UpdateArgs) -> Result<(), CliError> {
    if args.policy_id.is_none()
        && args.additional_info.is_none()
        && args.content_type.is_none()
        && args.export_mode.is_none()
    {
        return Err(CliError::InvalidArgument(
            "at least one updatable field must be set: policy_id, additional_info, content_type, export_mode"
                .to_string(),
        ));
    }
    Ok(())
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
        let lines = vec![
            format!("{:<20}{}", "uri:", self.0.uri),
            format!("{:<20}{}", "content:", self.0.content),
            format!("{:<20}{}", "content_type:", self.0.content_type.as_deref().unwrap_or("")),
        ];
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct ResourceMetadataOutput(ResourceInfoResponse);

impl Formatter for ResourceMetadataOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let resource = &self.0;
        Ok([
            format!("{:<20}{}", "uri:", resource.uri),
            format!("{:<20}{}", "res_provider:", resource.res_provider.as_deref().unwrap_or("")),
            format!("{:<20}{}", "repository_name:", resource.repository_name.as_deref().unwrap_or("")),
            format!("{:<20}{}", "resource_type:", resource.resource_type.as_deref().unwrap_or("")),
            format!("{:<20}{}", "resource_name:", resource.resource_name.as_deref().unwrap_or("")),
            format!("{:<20}{}", "policy_id:", resource.policy_id.as_deref().unwrap_or("")),
            format!("{:<20}{}", "content_type:", resource.content_type.as_deref().unwrap_or("")),
            format!("{:<20}{}", "export_mode:", resource.export_mode.as_deref().unwrap_or("")),
            format!(
                "{:<20}{}",
                "content_length:",
                resource.content_length.map(|value| value.to_string()).unwrap_or_default()
            ),
            format!("{:<20}{}", "created_at:", resource.created_at.as_deref().unwrap_or("")),
            format!("{:<20}{}", "updated_at:", resource.updated_at.as_deref().unwrap_or("")),
        ]
        .join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

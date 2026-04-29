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
use rbs_admin_client::attestation::ref_value::{
    RefValueClient, RefValueCreateRequest, RefValueDeleteRequest, RefValueListParams, RefValueListResponse,
    RefValueMutationResponse, RefValueService, RefValueUpdateRequest,
};
use rbs_admin_client::AdminClient;
use serde::Serialize;

use crate::admin::GTA_ID_MAX_LEN;
use crate::common::formatter::{Formatter, TextOutput};
use crate::common::utils::read_path_file;
use crate::common::validate::{validate_file_size, validate_string_max_len};
use crate::config::GlobalOptions;
use crate::error::CliError;

const SUPPORTED_ATTESTER_TYPES: [&str; 5] = ["tpm", "tpm_ima", "virt_cca", "ascend_npu", "cca"];
const DELETE_REF_VALUE_ID: &str = "id";
const DELETE_REF_VALUE_TYPE: &str = "type";
const DELETE_REF_VALUE_ALL: &str = "all";
const DELETE_REF_VALUE_TYPES: [&str; 3] = [DELETE_REF_VALUE_ALL, DELETE_REF_VALUE_ID, DELETE_REF_VALUE_TYPE];
const MAX_CONTENT_SIZE: u64 = 1024 * 1024 * 100;

#[derive(Args, Debug, Clone)]
#[command(about = "Manage attestation ref values")]
pub struct RefValueCli {
    #[command(subcommand)]
    pub command: RefValueCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RefValueCommand {
    #[command(
        about = "List ref values",
        long_about = "List current user's ref values.\n\nExamples:\n  rbs-cli ref-value list\n  rbs-cli ref-value list --attester-type tpm\n  rbs-cli ref-value list --ids rv_id_1,rv_id_2"
    )]
    List(ListArgs),
    #[command(
        about = "Create a ref value",
        long_about = "Create a ref value.\nThe content must be a JWT string. Use @file to read content from a file.\n\nExample:\n  rbs-cli ref-value create --name rv_name_1 --attester-type tpm --content @ref.jwt"
    )]
    Create(CreateArgs),
    #[command(
        about = "Update a ref value",
        long_about = "Update a ref value. At least one updatable field must be provided.\nIf content is set, it must still be a valid JWT string.\n\nExample:\n  rbs-cli ref-value update --id rv_id_1 --name rv_name_1_new --content @ref.jwt"
    )]
    Update(UpdateArgs),
    #[command(
        about = "Delete ref values",
        long_about = "Delete ref values by id, by attester type, or delete all ref values.\n\nExamples:\n  rbs-cli ref-value delete --delete-type id --ids rv_id_1,rv_id_2\n  rbs-cli ref-value delete --delete-type type --attester-type tpm\n  rbs-cli ref-value delete --delete-type all"
    )]
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[arg(
        long,
        value_delimiter = ',',
        value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN),
        help = "Comma-separated ref value IDs"
    )]
    pub ids: Option<Vec<String>>,

    #[arg(
        short = 't',
        long = "attester-type",
        value_parser = SUPPORTED_ATTESTER_TYPES,
        help = "Attester type filter"
    )]
    pub attester_type: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, 255), help = "Ref value name")]
    pub name: String,

    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, 512), help = "Optional description")]
    pub description: Option<String>,

    #[arg(
        short = 't',
        long = "attester-type",
        value_parser = SUPPORTED_ATTESTER_TYPES,
        help = "Attester type: tpm, tpm_ima, virt_cca, or ascend_npu"
    )]
    pub attester_type: String,

    #[arg(
        long,
        value_parser = |s: &str| validate_file_size(s, MAX_CONTENT_SIZE),
        help = "JWT content or @file path; max size 100MB"
    )]
    pub content: String,
}

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN), required = true, help = "Ref value ID")]
    pub id: String,

    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, 255), help = "New ref value name")]
    pub name: Option<String>,

    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, 512), help = "New description")]
    pub description: Option<String>,

    #[arg(
        short = 't',
        long = "attester-type",
        value_parser = SUPPORTED_ATTESTER_TYPES,
        help = "New attester type"
    )]
    pub attester_type: Option<String>,

    #[arg(long, value_parser = validate_and_read_ref_value, help = "New JWT content or @file path; max size 100MB")]
    pub content: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DeleteArgs {
    #[arg(long, value_parser = DELETE_REF_VALUE_TYPES, help = "Delete mode: all, id, or type")]
    pub delete_type: String,

    #[arg(
        long,
        value_delimiter = ',',
        value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN),
        help = "Comma-separated ref value IDs; required when --delete-type id"
    )]
    pub ids: Vec<String>,

    #[arg(
        short = 't',
        long = "attester-type",
        value_parser = SUPPORTED_ATTESTER_TYPES,
        help = "Attester type; required when --delete-type type"
    )]
    pub attester_type: Option<String>,
}

pub fn run(cli: &RefValueCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|err| CliError::Message(format!("failed to create async runtime: {err}")))?;
    let token = global
        .token
        .as_deref()
        .ok_or_else(|| CliError::InvalidArgument("missing required bearer token".to_string()))?;
    let service = RefValueClient::new(AdminClient::new(&global.base_url, token, &global.cert)?, None);
    runtime.block_on(execute_ref_value_command(cli, &service))
}

async fn execute_ref_value_command(
    cli: &RefValueCli,
    service: &RefValueClient,
) -> Result<Box<dyn Formatter>, CliError> {
    match &cli.command {
        RefValueCommand::List(args) => {
            let resp = service
                .list_ref_values(&RefValueListParams {
                    ids: args.ids.clone(),
                    attester_type: args.attester_type.clone(),
                })
                .await?;
            Ok(Box::new(RefValueListOutput(resp)))
        },
        RefValueCommand::Create(args) => {
            let resp = service
                .create_ref_value(&RefValueCreateRequest {
                    name: args.name.clone(),
                    description: args.description.clone(),
                    attester_type: args.attester_type.clone(),
                    content: read_path_file(&args.content)?,
                })
                .await?;
            Ok(Box::new(RefValueMutationOutput(resp)))
        },
        RefValueCommand::Update(args) => {
            validate_update_args(args)?;
            let resp = service
                .update_ref_value(&RefValueUpdateRequest {
                    id: args.id.clone(),
                    name: args.name.clone(),
                    description: args.description.clone(),
                    attester_type: args.attester_type.clone(),
                    content: args.content.as_ref().map(|value| read_path_file(value)).transpose()?,
                })
                .await?;
            Ok(Box::new(RefValueMutationOutput(resp)))
        },
        RefValueCommand::Delete(args) => {
            let request = build_delete_request(args)?;
            let message = delete_message(&request);
            service.delete_ref_values(&request).await?;
            Ok(Box::new(TextOutput::new(message)))
        },
    }
}

fn validate_update_args(args: &UpdateArgs) -> Result<(), CliError> {
    if args.name.is_none() && args.description.is_none() && args.attester_type.is_none() && args.content.is_none() {
        return Err(CliError::InvalidArgument(
            "at least one updatable field must be set: name, description, attester_type, content".to_string(),
        ));
    }
    Ok(())
}

fn build_delete_request(args: &DeleteArgs) -> Result<RefValueDeleteRequest, CliError> {
    let ids = (!args.ids.is_empty()).then(|| args.ids.clone());

    match args.delete_type.as_str() {
        DELETE_REF_VALUE_ID => {
            if ids.is_none() {
                return Err(CliError::InvalidArgument("ids are required when delete_type is `id`".to_string()));
            }
            Ok(RefValueDeleteRequest { delete_type: DELETE_REF_VALUE_ID.to_string(), ids, attester_type: None })
        },
        DELETE_REF_VALUE_TYPE => {
            if args.attester_type.is_none() {
                return Err(CliError::InvalidArgument(
                    "attester_type is required when delete_type is `type`".to_string(),
                ));
            }
            Ok(RefValueDeleteRequest {
                delete_type: DELETE_REF_VALUE_TYPE.to_string(),
                ids: None,
                attester_type: args.attester_type.clone(),
            })
        },
        DELETE_REF_VALUE_ALL => {
            if ids.is_some() || args.attester_type.is_some() {
                return Err(CliError::InvalidArgument(
                    "ids and attester_type must not be set when delete_type is `all`".to_string(),
                ));
            }
            Ok(RefValueDeleteRequest { delete_type: DELETE_REF_VALUE_ALL.to_string(), ids: None, attester_type: None })
        },
        _ => unreachable!(),
    }
}

fn delete_message(request: &RefValueDeleteRequest) -> String {
    match request.delete_type.as_str() {
        DELETE_REF_VALUE_ID => {
            format!("deleted ref values: {}", request.ids.clone().unwrap_or_default().join(","))
        },
        DELETE_REF_VALUE_TYPE => {
            format!("deleted ref values by attester_type: {}", request.attester_type.clone().unwrap_or_default())
        },
        DELETE_REF_VALUE_ALL => "deleted all ref values".to_string(),
        _ => "deleted ref values".to_string(),
    }
}

#[derive(Debug, Serialize)]
struct RefValueListOutput(RefValueListResponse);

impl Formatter for RefValueListOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = vec!["ref_values:".to_string()];
        if self.0.ref_values.is_empty() {
            lines.push("  <empty>".to_string());
        } else {
            for ref_value in &self.0.ref_values {
                let mut parts = vec![
                    format!("name={}", ref_value.name),
                    format!("id={}", ref_value.id.as_deref().unwrap_or("-")),
                    format!("attester_type={}", ref_value.attester_type),
                ];
                if let Some(version) = ref_value.version {
                    parts.push(format!("version={version}"));
                }
                if let Some(description) = &ref_value.description {
                    parts.push(format!("description={description}"));
                }
                if let Some(content) = &ref_value.content {
                    parts.push(format!("content={}", content));
                }
                lines.push(format!("  - {}", parts.join(" ")));
            }
        }
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct RefValueMutationOutput(RefValueMutationResponse);

impl Formatter for RefValueMutationOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = vec![format!("name: {}", self.0.ref_value.name)];
        if let Some(id) = &self.0.ref_value.id {
            lines.push(format!("id: {id}"));
        }
        if let Some(version) = self.0.ref_value.version {
            lines.push(format!("version: {version}"));
        }
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

fn validate_and_read_ref_value(path: &str) -> Result<String, CliError> {
    validate_file_size(path, MAX_CONTENT_SIZE)?;
    let content = std::fs::read_to_string(path)?;
    Ok(content)
}

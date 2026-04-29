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
use base64::Engine;
use base64::engine::general_purpose;
use clap::{Args, Subcommand};
use rbs_admin_client::attestation::policy::{
    PolicyClient, PolicyCreateRequest, PolicyDeleteRequest, PolicyListParams, PolicyListResponse,
    PolicyMutationResponse, PolicyService, PolicyUpdateRequest,
};
use rbs_admin_client::AdminClient;
use serde::Serialize;

use crate::admin::GTA_ID_MAX_LEN;
use crate::common::formatter::{Formatter, TextOutput};
use crate::common::utils::read_path_file;
use crate::common::validate::{validate_file_size, validate_string_max_len};
use crate::config::GlobalOptions;
use crate::error::CliError;
const SUPPORTED_ATTESTER_TYPES: [&str; 9] = ["all", "tpm", "tpm_boot", "tpm_ima", "virt_cca", "ascend_npu", "itrustee", "cca", "dice"];
const SUPPORTED_CONTENT_TYPES: [&str; 2] = ["text", "jwt"];
const DELETE_POLICY_ID: &str = "id";
const DELETE_POLICY_ATTESTER_TYPE: &str = "attester_type";
const DELETE_POLICY_ALL: &str = "all";
const DELETE_POLICY_TYPES: [&str; 3] = [DELETE_POLICY_ID, DELETE_POLICY_ATTESTER_TYPE, DELETE_POLICY_ALL];
const MAX_CONTENT_SIZE: u64 = 1024 * 500;

#[derive(Args, Debug, Clone)]
#[command(about = "Manage attestation policies")]
pub struct PolicyCli {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PolicyCommand {
    #[command(
        about = "List policies",
        long_about = "List current user's policies.\n\nExamples:\n  rbs-cli policy list\n  rbs-cli policy list --attester-type tpm\n  rbs-cli policy list --ids policy_id_1,policy_id_2"
    )]
    List(ListArgs),
    #[command(
        about = "Create a policy",
        long_about = "Create a policy.\nFor content_type=text, content must be base64 encoded policy text.\nFor content_type=jwt, content must be a full JWT string.\nUse @file to read content from a file."
    )]
    Create(CreateArgs),
    #[command(
        about = "Update a policy",
        long_about = "Update a policy. At least one updatable field must be provided.\nIf content is set, content_type must also be set."
    )]
    Update(UpdateArgs),
    #[command(
        about = "Delete policies",
        long_about = "Delete policies by id, by attester type, or delete all policies.\n\nExamples:\n  rbs-cli policy delete --delete-type id --ids policy_id_1,policy_id_2\n  rbs-cli policy delete --delete-type attester_type --attester-type tpm\n  rbs-cli policy delete --delete-type all"
    )]
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[arg(
        long,
        value_delimiter = ',',
        value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN),
        help = "Comma-separated policy IDs"
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
    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, 255), help = "Policy name")]
    pub name: String,

    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, 512), help = "Optional description")]
    pub description: Option<String>,

    #[arg(
        short = 't',
        long = "attester-type",
        value_delimiter = ',',
        required = true,
        value_parser = SUPPORTED_ATTESTER_TYPES,
        help = "Applicable attester types"
    )]
    pub attester_type: Vec<String>,

    #[arg(
        long,
        value_parser = SUPPORTED_CONTENT_TYPES,
        default_value = "text",
        help = "Policy content type: text or jwt"
    )]
    pub content_type: String,

    #[arg(long, value_parser = validate_policy_content, help = "Policy content or @file path; text expects base64 policy text")]
    pub content: String,

    #[arg(long, help = "Whether to mark this policy as default")]
    pub is_default: Option<bool>,
}

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN), help = "Policy ID")]
    pub id: String,

    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, 255), help = "New policy name")]
    pub name: Option<String>,

    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, 512), help = "New description")]
    pub description: Option<String>,

    #[arg(
        short = 't',
        long = "attester-type",
        value_delimiter = ',',
        value_parser = SUPPORTED_ATTESTER_TYPES,
        help = "New attester type list"
    )]
    pub attester_type: Option<Vec<String>>,

    #[arg(long, value_parser = SUPPORTED_CONTENT_TYPES, help = "New content type: text or jwt")]
    pub content_type: Option<String>,

    #[arg(long, value_parser = validate_policy_content, help = "New policy content or @file path")]
    pub content: Option<String>,

    #[arg(long, help = "Whether to mark this policy as default")]
    pub is_default: Option<bool>,
}

#[derive(Args, Debug, Clone)]
pub struct DeleteArgs {
    #[arg(long, value_parser = DELETE_POLICY_TYPES, help = "Delete mode: id, attester_type, or all")]
    pub delete_type: String,

    #[arg(
        long,
        value_delimiter = ',',
        value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN),
        help = "Comma-separated policy IDs; required when --delete-type id"
    )]
    pub ids: Vec<String>,

    #[arg(
        short = 't',
        long = "attester-type",
        value_parser = SUPPORTED_ATTESTER_TYPES,
        help = "Attester type; required when --delete-type attester_type"
    )]
    pub attester_type: Option<String>,
}

pub fn run(cli: &PolicyCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|err| CliError::Message(format!("failed to create async runtime: {err}")))?;
    let token = global
        .token
        .as_deref()
        .ok_or_else(|| CliError::InvalidArgument("missing required bearer token".to_string()))?;
    let service = PolicyClient::new(AdminClient::new(&global.base_url, token, &global.cert)?, None);
    runtime.block_on(execute_policy_command(cli, &service))
}

async fn execute_policy_command(cli: &PolicyCli, service: &PolicyClient) -> Result<Box<dyn Formatter>, CliError> {
    match &cli.command {
        PolicyCommand::List(args) => {
            let resp = service
                .list_policies(&PolicyListParams { ids: args.ids.clone(), attester_type: args.attester_type.clone() })
                .await?;
            Ok(Box::new(PolicyListOutput(resp)))
        },
        PolicyCommand::Create(args) => {
            let mut content = read_path_file(args.content.as_str())?;
            match args.content_type.to_lowercase().as_str() {
                "text" => {
                    content = general_purpose::STANDARD.encode(content.as_bytes());
                },
                _ => {}
            }
            let resp = service
                .create_policy(&PolicyCreateRequest {
                    name: args.name.clone(),
                    description: args.description.clone(),
                    attester_type: args.attester_type.clone(),
                    content_type: args.content_type.clone(),
                    content,
                    is_default: args.is_default,
                })
                .await?;
            Ok(Box::new(PolicyMutationOutput(resp)))
        },
        PolicyCommand::Update(args) => {
            validate_update_args(args)?;
            let mut content = String::new();
            if let (Some(c_type), Some(raw_content)) = (&args.content_type, &args.content) {
                content = read_path_file(raw_content.as_str())?;
                match c_type.to_lowercase().as_str() {
                    "text" => {
                        content = general_purpose::STANDARD.encode(raw_content.as_bytes());
                    },
                    _ => {}
                }
            }
            let resp = service
                .update_policy(&PolicyUpdateRequest {
                    id: args.id.clone(),
                    name: args.name.clone(),
                    description: args.description.clone(),
                    attester_type: args.attester_type.clone(),
                    content_type: args.content_type.clone(),
                    content: Some(content),
                    is_default: args.is_default,
                })
                .await?;
            Ok(Box::new(PolicyMutationOutput(resp)))
        },
        PolicyCommand::Delete(args) => {
            let request = build_delete_request(args)?;
            let message = delete_message(&request);
            service.delete_policies(&request).await?;
            Ok(Box::new(TextOutput::new(message)))
        },
    }
}

fn validate_update_args(args: &UpdateArgs) -> Result<(), CliError> {
    if args.name.is_none()
        && args.description.is_none()
        && args.attester_type.is_none()
        && args.content_type.is_none()
        && args.content.is_none()
        && args.is_default.is_none()
    {
        return Err(CliError::InvalidArgument(
            "at least one updatable field must be set: name, description, attester_type, content_type, content, is_default"
                .to_string(),
        ));
    }

    if args.content.is_some() && args.content_type.is_none() {
        return Err(CliError::InvalidArgument("content_type must be set when content is provided".to_string()));
    }

    Ok(())
}

fn build_delete_request(args: &DeleteArgs) -> Result<PolicyDeleteRequest, CliError> {
    let ids = (!args.ids.is_empty()).then(|| args.ids.clone());

    match args.delete_type.as_str() {
        DELETE_POLICY_ID => {
            if ids.is_none() {
                return Err(CliError::InvalidArgument("ids are required when delete_type is `id`".to_string()));
            }
            Ok(PolicyDeleteRequest { delete_type: DELETE_POLICY_ID.to_string(), ids, attester_type: None })
        },
        DELETE_POLICY_ATTESTER_TYPE => {
            if args.attester_type.is_none() {
                return Err(CliError::InvalidArgument(
                    "attester_type is required when delete_type is `attester_type`".to_string(),
                ));
            }
            Ok(PolicyDeleteRequest {
                delete_type: DELETE_POLICY_ATTESTER_TYPE.to_string(),
                ids: None,
                attester_type: args.attester_type.clone(),
            })
        },
        DELETE_POLICY_ALL => {
            if ids.is_some() || args.attester_type.is_some() {
                return Err(CliError::InvalidArgument(
                    "ids and attester_type must not be set when delete_type is `all`".to_string(),
                ));
            }
            Ok(PolicyDeleteRequest { delete_type: DELETE_POLICY_ALL.to_string(), ids: None, attester_type: None })
        },
        _ => unreachable!(),
    }
}

fn delete_message(request: &PolicyDeleteRequest) -> String {
    match request.delete_type.as_str() {
        DELETE_POLICY_ID => format!("deleted policies: {}", request.ids.clone().unwrap_or_default().join(",")),
        DELETE_POLICY_ATTESTER_TYPE => {
            format!("deleted policies by attester_type: {}", request.attester_type.clone().unwrap_or_default())
        },
        DELETE_POLICY_ALL => "deleted all policies".to_string(),
        _ => "deleted policies".to_string(),
    }
}

#[derive(Debug, Serialize)]
struct PolicyListOutput(PolicyListResponse);

impl Formatter for PolicyListOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = vec!["policies:".to_string()];
        if self.0.policies.is_empty() {
            lines.push("  <empty>".to_string());
        } else {
            for policy in &self.0.policies {
                let mut parts = vec![
                    format!("name={}", policy.name),
                    format!("id={}", policy.id.as_deref().unwrap_or("-")),
                    format!("attester_type={}", policy.attester_type.join(",")),
                ];
                if let Some(version) = policy.version {
                    parts.push(format!("version={version}"));
                }
                if let Some(description) = &policy.description {
                    parts.push(format!("description={description}"));
                }
                if let Some(content) = &policy.content {
                    parts.push(format!("content={}", content.replace('\n', "\\n")));
                }
                if let Some(is_default) = policy.is_default {
                    parts.push(format!("is_default={is_default}"));
                }
                if let Some(update_time) = policy.update_time {
                    parts.push(format!("update_time={update_time}"));
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
struct PolicyMutationOutput(PolicyMutationResponse);

impl Formatter for PolicyMutationOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = vec![format!("name: {}", self.0.policy.name)];
        if let Some(id) = &self.0.policy.id {
            lines.push(format!("id: {id}"));
        }
        if let Some(version) = self.0.policy.version {
            lines.push(format!("version: {version}"));
        }
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

fn validate_policy_content(path: &str) -> Result<String, CliError> {
    if let Some(path) = path.strip_prefix('@') {
        validate_file_size(path, MAX_CONTENT_SIZE)?;
    } else {
        if path.len() > MAX_CONTENT_SIZE as usize {
            return Err(CliError::InvalidArgument(format!(
                "policy content must not exceed {MAX_CONTENT_SIZE} bytes; got {} bytes",
                path.len()
            )));
        }
    }
    Ok(path.to_string())
}

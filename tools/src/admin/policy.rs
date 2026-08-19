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
use base64::engine::general_purpose;
use base64::Engine;
use clap::{Args, Subcommand};
use rbs_admin_client::attestation::policy::{
    AttestationPolicyCreateRequest, AttestationPolicyDeleteRequest, AttestationPolicyListParams,
    AttestationPolicyUpdateRequest, PolicyClient, PolicyListResponse, PolicyMutationResponse, PolicyService,
};
use rbs_admin_client::AdminClient;
use rbs_api_types::PolicyDeleteType;
use serde::Serialize;
use tabled::settings::Style;
use tabled::Table;

use crate::admin::GTA_ID_MAX_LEN;
use crate::common::formatter::{format_epoch_timestamp, format_indented_content, Formatter};
use crate::common::utils::read_path_file;
use crate::common::validate::{validate_file_size, validate_i64, validate_string_max_len};
use crate::config::GlobalOptions;
use crate::error::CliError;
const SUPPORTED_ATTESTER_TYPES: [&str; 9] =
    ["all", "tpm", "tpm_boot", "tpm_ima", "virt_cca", "ascend_npu", "itrustee", "cca", "dice"];
const SUPPORTED_CONTENT_TYPES: [&str; 2] = ["text", "jwt"];
const DELETE_POLICY_ID: &str = "id";
const DELETE_POLICY_ATTESTER_TYPE: &str = "attester_type";
const DELETE_POLICY_ALL: &str = "all";
const DELETE_POLICY_TYPES: [&str; 3] = [DELETE_POLICY_ID, DELETE_POLICY_ATTESTER_TYPE, DELETE_POLICY_ALL];
const MAX_CONTENT_SIZE: u64 = 1024 * 500;
const LIST_MIN_LIMIT: i64 = 1;
const LIST_MAX_LIMIT: i64 = 10;
const LIST_MIN_OFFSET: i64 = 0;
const LIST_MAX_OFFSET: i64 = 100_000;

#[derive(Args, Debug, Clone)]
#[command(about = "Manage attestation policies")]
pub struct PolicyCli {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PolicyCommand {
    #[command(about = "List policies", long_about = "List current user's policies.")]
    List(ListArgs),
    #[command(about = "Get one attestation policy by ID")]
    Get(GetArgs),
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
        long_about = "Delete policies by id, by attester type, or delete all policies."
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

    #[arg(long, value_parser = |value: &str| validate_i64(value, LIST_MIN_LIMIT, LIST_MAX_LIMIT, "limit"), help = "Page size (1-10; RBS default is 10)")]
    pub limit: Option<i64>,

    #[arg(long, value_parser = |value: &str| validate_i64(value, LIST_MIN_OFFSET, LIST_MAX_OFFSET, "offset"), help = "Page offset (0-100000; RBS default is 0)")]
    pub offset: Option<i64>,
}

#[derive(Args, Debug, Clone)]
pub struct GetArgs {
    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN), help = "Policy ID")]
    pub id: String,
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
                .list_policies(&AttestationPolicyListParams {
                    ids: args.ids.clone(),
                    attester_type: args.attester_type.clone(),
                    limit: args.limit,
                    offset: args.offset,
                })
                .await?;
            Ok(Box::new(PolicyListOutput(resp)))
        },
        PolicyCommand::Get(args) => get_policy_output(service.get_policy(&args.id).await?),
        PolicyCommand::Create(args) => {
            let mut content = read_path_file(args.content.as_str())?;
            match args.content_type.to_lowercase().as_str() {
                "text" => {
                    content = general_purpose::STANDARD.encode(content.as_bytes());
                },
                _ => {},
            }
            let resp = service
                .create_policy(&AttestationPolicyCreateRequest {
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
            let content = match (&args.content_type, &args.content) {
                (Some(content_type), Some(content_input)) => {
                    let mut content = read_path_file(content_input.as_str())?;
                    match content_type.to_lowercase().as_str() {
                        "text" => {
                            content = general_purpose::STANDARD.encode(content.as_bytes());
                        },
                        _ => {},
                    }
                    Some(content)
                },
                _ => None,
            };
            let resp = service
                .update_policy(&AttestationPolicyUpdateRequest {
                    id: args.id.clone(),
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
        PolicyCommand::Delete(args) => {
            let request = build_delete_request(args)?;
            service.delete_policies(&request).await?;
            Ok(Box::new(DeletePolicyOutput { target: delete_message(&request) }))
        },
    }
}

#[derive(Debug, Serialize)]
struct DeletePolicyOutput {
    target: String,
}

impl Formatter for DeletePolicyOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(format!("Delete succeeded: {}", self.target))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(self).map_err(|_| CliError::InternalFormat)
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

fn build_delete_request(args: &DeleteArgs) -> Result<AttestationPolicyDeleteRequest, CliError> {
    let ids = (!args.ids.is_empty()).then(|| args.ids.clone());

    match args.delete_type.as_str() {
        DELETE_POLICY_ID => {
            if ids.is_none() {
                return Err(CliError::InvalidArgument("ids are required when delete_type is `id`".to_string()));
            }
            Ok(AttestationPolicyDeleteRequest { delete_type: PolicyDeleteType::Id, ids, attester_type: None })
        },
        DELETE_POLICY_ATTESTER_TYPE => {
            if args.attester_type.is_none() {
                return Err(CliError::InvalidArgument(
                    "attester_type is required when delete_type is `attester_type`".to_string(),
                ));
            }
            Ok(AttestationPolicyDeleteRequest {
                delete_type: PolicyDeleteType::AttesterType,
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
            Ok(AttestationPolicyDeleteRequest { delete_type: PolicyDeleteType::All, ids: None, attester_type: None })
        },
        _ => unreachable!(),
    }
}

fn delete_message(request: &AttestationPolicyDeleteRequest) -> String {
    match request.delete_type {
        PolicyDeleteType::Id => format!("deleted policies: {}", request.ids.clone().unwrap_or_default().join(",")),
        PolicyDeleteType::AttesterType => {
            format!("deleted policies by attester_type: {}", request.attester_type.clone().unwrap_or_default())
        },
        PolicyDeleteType::All => "deleted all policies".to_string(),
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
            lines.extend(
                Table::new(self.0.policies.iter()).with(Style::markdown()).to_string().lines().map(str::to_string),
            );
        }
        if let Some(total_count) = self.0.total_count {
            lines.push(format!("total_count: {total_count}"));
        }
        if let Some(limit) = self.0.limit {
            lines.push(format!("limit: {limit}"));
        }
        if let Some(offset) = self.0.offset {
            lines.push(format!("offset: {offset}"));
        }
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

fn get_policy_output(response: PolicyListResponse) -> Result<Box<dyn Formatter>, CliError> {
    match response.policies.as_slice() {
        [policy] => Ok(Box::new(PolicyOutput(policy.clone()))),
        _ => Err(CliError::Message("Attestation policy not found.".to_string())),
    }
}

#[derive(Debug, Serialize)]
struct PolicyOutput(rbs_admin_client::attestation::policy::AttestationPolicy);

impl Formatter for PolicyOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let policy = &self.0;
        Ok([
            format!("{:<20}{}", "policy_id:", policy.id),
            format!("{:<20}{}", "policy_name:", policy.name),
            format!("{:<20}{}", "description:", policy.description.as_deref().unwrap_or("-")),
            format!(
                "{:<20}{}",
                "attester_type:",
                serde_json::to_string(&policy.attester_type).map_err(|err| CliError::Message(err.to_string()))?
            ),
            format!("content:\n{}", format_indented_content(policy.content.as_deref())),
            format!("{:<20}{}", "is_default:", policy.is_default.map_or("-".to_string(), |value| value.to_string())),
            format!("{:<20}{}", "version:", policy.version.map_or("-".to_string(), |value| value.to_string())),
            format!("{:<20}{}", "update_time:", format_epoch_timestamp(policy.update_time)),
            format!("{:<20}{}", "valid_code:", policy.valid_code.map_or("-".to_string(), |value| value.to_string())),
        ]
        .join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct PolicyMutationOutput(PolicyMutationResponse);

impl Formatter for PolicyMutationOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok([
            format!("{:<20}{}", "policy_id:", self.0.policy.id),
            format!("{:<20}{}", "policy_name:", self.0.policy.name),
            format!("{:<20}{}", "version:", self.0.policy.version),
        ]
        .join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_update_args() -> UpdateArgs {
        UpdateArgs {
            id: "policy-1".to_string(),
            name: None,
            description: None,
            attester_type: None,
            content_type: None,
            content: None,
            is_default: None,
        }
    }

    #[test]
    fn validate_update_args_requires_at_least_one_field() {
        let err = validate_update_args(&base_update_args()).expect_err("empty update should fail");
        assert!(err.to_string().contains("at least one updatable field"));
    }

    #[test]
    fn validate_update_args_requires_content_type_with_content() {
        let mut args = base_update_args();
        args.content = Some("payload".to_string());
        let err = validate_update_args(&args).expect_err("content without type should fail");
        assert!(err.to_string().contains("content_type must be set"));
    }

    #[test]
    fn update_text_content_encodes_file_content() {
        let path = std::env::temp_dir().join(format!("policy-update-content-{}.rego", std::process::id()));
        std::fs::write(&path, "package policy").expect("write policy content");

        let mut content = read_path_file(&format!("@{}", path.display())).expect("read policy content");
        content = general_purpose::STANDARD.encode(content.as_bytes());

        assert_eq!(content, general_purpose::STANDARD.encode("package policy".as_bytes()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn build_delete_request_supports_all_modes() {
        let by_id = build_delete_request(&DeleteArgs {
            delete_type: "id".to_string(),
            ids: vec!["a".to_string(), "b".to_string()],
            attester_type: None,
        })
        .expect("id delete");
        assert_eq!(by_id.ids, Some(vec!["a".to_string(), "b".to_string()]));

        let by_type = build_delete_request(&DeleteArgs {
            delete_type: "attester_type".to_string(),
            ids: vec![],
            attester_type: Some("tpm".to_string()),
        })
        .expect("type delete");
        assert_eq!(by_type.attester_type.as_deref(), Some("tpm"));

        let all =
            build_delete_request(&DeleteArgs { delete_type: "all".to_string(), ids: vec![], attester_type: None })
                .expect("all delete");
        assert_eq!(all.delete_type, PolicyDeleteType::All);
    }

    #[test]
    fn delete_message_matches_delete_mode() {
        assert_eq!(
            delete_message(&AttestationPolicyDeleteRequest {
                delete_type: PolicyDeleteType::Id,
                ids: Some(vec!["a".to_string(), "b".to_string()]),
                attester_type: None,
            }),
            "deleted policies: a,b"
        );
        assert_eq!(
            delete_message(&AttestationPolicyDeleteRequest {
                delete_type: PolicyDeleteType::AttesterType,
                ids: None,
                attester_type: Some("tpm".to_string()),
            }),
            "deleted policies by attester_type: tpm"
        );
    }

    #[test]
    fn policy_outputs_render_text() {
        let list = PolicyListOutput(PolicyListResponse {
            policies: vec![rbs_admin_client::attestation::policy::AttestationPolicy {
                id: "policy-1".to_string(),
                name: "allow-secret".to_string(),
                description: Some("demo".to_string()),
                content: Some("package policy".to_string()),
                attester_type: vec!["tpm".to_string()],
                is_default: Some(true),
                version: Some(2),
                update_time: Some(123),
                valid_code: None,
            }],
            total_count: Some(1),
            limit: Some(10),
            offset: Some(20),
        });
        let text = list.render_text().expect("render list");
        assert!(text.contains("allow-secret"));
        assert!(text.contains("tpm"));
        assert!(!text.contains("package policy"));
        assert!(text.contains("total_count: 1"));
        assert!(text.contains("limit: 10"));
        assert!(text.contains("offset: 20"));

        let mutation = PolicyMutationOutput(PolicyMutationResponse {
            policy: rbs_admin_client::attestation::policy::PolicyMutation {
                id: "policy-1".to_string(),
                name: "allow-secret".to_string(),
                version: 2,
            },
        });
        let text = mutation.render_text().expect("render mutation");
        assert!(text.contains("policy_id:          policy-1"));
        assert!(text.contains("policy_name:        allow-secret"));
        assert!(text.contains("version:            2"));
    }

    #[test]
    fn policy_detail_output_renders_complete_indented_content() {
        let text = PolicyOutput(rbs_admin_client::attestation::policy::AttestationPolicy {
            id: "policy-1".to_string(),
            name: "allow-secret".to_string(),
            description: Some("demo".to_string()),
            content: Some("line-one\nline-two".to_string()),
            attester_type: vec!["tpm".to_string()],
            is_default: Some(true),
            version: Some(2),
            update_time: Some(1_787_051_574_065),
            valid_code: Some(0),
        })
        .render_text()
        .expect("render detail");

        assert!(text.contains("policy_id:          policy-1"));
        assert!(text.contains("content:\n    line-one\n    line-two"));
        assert!(text.contains("update_time:        2026-08-18T"));
        assert!(text.contains("valid_code:         0"));
    }

    #[test]
    fn delete_policy_output_reports_success() {
        assert_eq!(
            DeletePolicyOutput { target: "deleted policies: policy-1".to_string() }
                .render_text()
                .expect("render delete"),
            "Delete succeeded: deleted policies: policy-1"
        );
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

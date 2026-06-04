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
use crate::common::DEFAULT_PAGE_LIMIT;
use crate::common::MAX_PAGE_LIMIT;
use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use rbs_admin_client::resource_policy::{
    ResourcePolicy, ResourcePolicyClient, ResourcePolicyContentType, ResourcePolicyCreateRequest, ResourcePolicyListParams,
    ResourcePolicyListResponse, ResourcePolicyService, ResourcePolicyUpdateRequest,
};
use rbs_admin_client::AdminClient;
use serde::Serialize;
use tabled::settings::Style;
use tabled::Table;

use crate::common::formatter::{Formatter, TextOutput};
use crate::common::utils::read_path_file;
use crate::common::validate::validate_trimmed_string_max_len;
use crate::config::GlobalOptions;
use crate::error::CliError;

const POLICY_ID_MAX_LEN: usize = 256;
const POLICY_NAME_MAX_LEN: usize = 255;

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResPolicyContentTypeArg {
    #[default]
    #[value(name = "base64")]
    Base64,
}

impl From<ResPolicyContentTypeArg> for ResourcePolicyContentType {
    fn from(value: ResPolicyContentTypeArg) -> Self {
        match value {
            ResPolicyContentTypeArg::Base64 => ResourcePolicyContentType::Base64,
        }
    }
}

#[derive(Args, Debug, Clone)]
#[command(about = "Manage resource access policies")]
pub struct ResPolicyCli {
    #[command(subcommand)]
    pub command: ResPolicyCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ResPolicyCommand {
    #[command(
        about = "List resource policies",
        long_about = "List resource policies with optional ID and pagination filters.\n\nExample:\n  rbs-cli res-policy list --ids policy-1,policy-2 --limit 10 --offset 0"
    )]
    List(ListArgs),
    #[command(
        about = "Get a resource policy",
        long_about = "Get one resource policy by ID.\n\nExample:\n  rbs-cli res-policy get policy-1"
    )]
    Get(GetArgs),
    #[command(
        about = "Create a resource policy",
        long_about = "Create a resource policy. Use @file to read Base64 policy content from a file.\n\nExample:\n  rbs-cli res-policy create --name allow-secret --content @policy.txt --content-type base64"
    )]
    Create(CreateArgs),
    #[command(
        about = "Update a resource policy",
        long_about = "Replace a resource policy by ID.\n\nExample:\n  rbs-cli res-policy update policy-1 --name allow-secret-v2 --content @policy.txt --content-type base64"
    )]
    Update(UpdateArgs),
    #[command(
        about = "Delete resource policies",
        long_about = "Delete one resource policy by ID or multiple policies with --ids.\n\nExample:\n  rbs-cli res-policy delete --id policy-1\n  rbs-cli res-policy delete --ids policy-1,policy-2"
    )]
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[arg(
        long,
        value_delimiter = ',',
        value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_ID_MAX_LEN, "policy_id"),
        help = "Comma-separated resource policy IDs"
    )]
    pub ids: Option<Vec<String>>,

    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT, value_parser = clap::value_parser!(i64).range(1..=MAX_PAGE_LIMIT))]
    pub limit: i64,

    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..=MAX_PAGE_LIMIT))]
    pub offset: i64,
}

#[derive(Args, Debug, Clone)]
pub struct GetArgs {
    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_ID_MAX_LEN, "policy_id"), help = "Resource policy ID")]
    pub id: String,
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_NAME_MAX_LEN, "name"), help = "Resource policy name")]
    pub name: String,

    #[arg(long, value_parser = normalize_base64_policy_content, help = "Base64 policy content or @file path; raw content is Base64-encoded automatically")]
    pub content: String,

    #[arg(long, value_enum, default_value_t, help = "Policy content type")]
    pub content_type: ResPolicyContentTypeArg,
}

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_ID_MAX_LEN, "policy_id"), help = "Resource policy ID")]
    pub id: String,

    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_NAME_MAX_LEN, "name"), help = "Resource policy name")]
    pub name: String,

    #[arg(long, value_parser = normalize_base64_policy_content, help = "Base64 policy content or @file path; raw content is Base64-encoded automatically")]
    pub content: String,

    #[arg(long, value_enum, default_value_t, help = "Policy content type")]
    pub content_type: ResPolicyContentTypeArg,
}

#[derive(Args, Debug, Clone)]
#[command(
    group(
        ArgGroup::new("delete_target")
        .args(["id", "ids"])
        .required(true)
        .multiple(false)
    )
)]
pub struct DeleteArgs {
    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_ID_MAX_LEN, "policy_id"), help = "Single resource policy ID")]
    pub id: Option<String>,

    #[arg(
        long,
        value_delimiter = ',',
        value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_ID_MAX_LEN, "policy_id"),
        help = "Comma-separated resource policy IDs"
    )]
    pub ids: Option<Vec<String>>,
}

pub fn run(cli: &ResPolicyCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|err| CliError::Message(format!("failed to create async runtime: {err}")))?;
    let token = global
        .token
        .as_deref()
        .ok_or_else(|| CliError::InvalidArgument("missing required bearer token".to_string()))?;
    let service = ResourcePolicyClient::new(AdminClient::new(&global.base_url, token, &global.cert)?);
    runtime.block_on(execute_res_policy_command(cli, &service))
}

async fn execute_res_policy_command(
    cli: &ResPolicyCli,
    service: &ResourcePolicyClient,
) -> Result<Box<dyn Formatter>, CliError> {
    match &cli.command {
        ResPolicyCommand::List(args) => {
            let resp = service
                .list_policies(&ResourcePolicyListParams {
                    ids: args.ids.clone(),
                    limit: Some(args.limit),
                    offset: Some(args.offset),
                })
                .await?;
            Ok(Box::new(ResourcePolicyListOutput(resp)))
        },
        ResPolicyCommand::Get(args) => {
            let resp = service.get_policy(&args.id).await?;
            Ok(Box::new(ResourcePolicyMutationOutput(resp)))
        },
        ResPolicyCommand::Create(args) => {
            let resp = service
                .create_policy(&ResourcePolicyCreateRequest {
                    name: args.name.clone(),
                    content_type: args.content_type.into(),
                    content: args.content.clone(),
                })
                .await?;
            Ok(Box::new(ResourcePolicyMutationOutput(resp)))
        },
        ResPolicyCommand::Update(args) => {
            let resp = service
                .update_policy(
                    &args.id,
                    &ResourcePolicyUpdateRequest {
                        name: args.name.clone(),
                        content_type: args.content_type.into(),
                        content: args.content.clone(),
                    },
                )
                .await?;
            Ok(Box::new(ResourcePolicyMutationOutput(resp)))
        },
        ResPolicyCommand::Delete(args) => {
            let message = if let Some(id) = &args.id {
                service.delete_policy(id).await?;
                format!("Delete succeeded: resource policy removed: {id}")
            } else {
                let ids = args.ids.clone().unwrap_or_default();
                service.delete_policies(&ids).await?;
                format!("Delete succeeded: resource policies removed: {}", ids.join(","))
            };
            Ok(Box::new(TextOutput::new(message)))
        },
    }
}

#[derive(Debug, Serialize)]
struct ResourcePolicyListOutput(ResourcePolicyListResponse);

impl Formatter for ResourcePolicyListOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = vec![format!("resource_policies: total={}", self.0.total_count)];
        if !self.0.items.is_empty() {
            let table = Table::new(self.0.items.iter()).with(Style::markdown()).to_string();
            lines.extend(table.lines().map(|line| line.to_string()));
        }
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct ResourcePolicyMutationOutput(ResourcePolicy);

impl Formatter for ResourcePolicyMutationOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(format_policy_multiline(&self.0))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

fn format_policy_multiline(policy: &ResourcePolicy) -> String {
    let applied_resources = serde_json::to_string(&policy.applied_resources.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());

    [
        format!("{:<20}{}", "policy_id:", policy.policy_id),
        format!("{:<20}{}", "policy_name:", policy.policy_name),
        format!("{:<20}{}", "policy_version:", policy.policy_version),
        format!("{:<20}{}", "policy_content:", policy.policy_content),
        format!("{:<20}{}", "content_type:", policy.content_type),
        format!("{:<20}{}", "created_at:", policy.created_at),
        format!("{:<20}{}", "updated_at:", policy.updated_at),
        format!("{:<20}{}", "applied_resources:", applied_resources),
    ]
    .join("\n")
}

fn normalize_base64_policy_content(value: &str) -> Result<String, CliError> {
    let content = read_path_file(value)?;
    let trimmed = content.trim();

    if general_purpose::STANDARD.decode(trimmed).is_ok() {
        Ok(trimmed.to_string())
    } else {
        Ok(general_purpose::STANDARD.encode(content.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbs_admin_client::resource_policy::ResourcePolicyContentType;

    #[test]
    fn format_policy_multiline_includes_core_fields() {
        let policy = ResourcePolicy {
            policy_id: "policy-1".to_string(),
            policy_name: "allow-secret".to_string(),
            policy_version: 2,
            policy_content: "Zm9v".to_string(),
            content_type: ResourcePolicyContentType::Base64,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-02T00:00:00Z".to_string(),
            applied_resources: Some(vec!["vault/default/secret/demo".to_string()]),
        };

        let rendered = format_policy_multiline(&policy);
        assert!(rendered.contains("policy_id:"));
        assert!(rendered.contains("policy-1"));
        assert!(rendered.contains("allow-secret"));
        assert!(rendered.contains("vault/default/secret/demo"));
    }

    #[test]
    fn resource_policy_outputs_render_text() {
        let list = ResourcePolicyListOutput(ResourcePolicyListResponse {
            items: vec![ResourcePolicy {
                policy_id: "policy-1".to_string(),
                policy_name: "allow-secret".to_string(),
                policy_version: 1,
                policy_content: "Zm9v".to_string(),
                content_type: ResourcePolicyContentType::Base64,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-02T00:00:00Z".to_string(),
                applied_resources: None,
            }],
            total_count: 1,
        });
        let text = list.render_text().expect("render list");
        assert!(text.contains("resource_policies: total=1"));
        assert!(text.contains("allow-secret"));

        let mutation = ResourcePolicyMutationOutput(ResourcePolicy {
            policy_id: "policy-1".to_string(),
            policy_name: "allow-secret".to_string(),
            policy_version: 1,
            policy_content: "Zm9v".to_string(),
            content_type: ResourcePolicyContentType::Base64,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-02T00:00:00Z".to_string(),
            applied_resources: None,
        });
        assert!(mutation.render_text().expect("render mutation").contains("policy_name:"));
    }

    #[test]
    fn normalize_base64_policy_content_accepts_inline_and_file_values() {
        assert_eq!(normalize_base64_policy_content("Zm9v").expect("inline"), "Zm9v");

        let path = std::env::temp_dir().join(format!("res-policy-b64-{}.txt", std::process::id()));
        std::fs::write(&path, "YmFy").expect("write base64 file");
        let value = normalize_base64_policy_content(&format!("@{}", path.display())).expect("file");
        assert_eq!(value, "YmFy");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn normalize_base64_policy_content_encodes_raw_inline_content() {
        let value = normalize_base64_policy_content("plain policy").expect("raw inline content");
        assert_eq!(value, "cGxhaW4gcG9saWN5");
    }

    #[test]
    fn normalize_base64_policy_content_encodes_raw_file_content() {
        let path = std::env::temp_dir().join(format!("res-policy-raw-{}.txt", std::process::id()));
        std::fs::write(&path, "allow = true").expect("write raw policy file");
        let value = normalize_base64_policy_content(&format!("@{}", path.display())).expect("raw file");
        assert_eq!(value, "YWxsb3cgPSB0cnVl");
        let _ = std::fs::remove_file(path);
    }
}

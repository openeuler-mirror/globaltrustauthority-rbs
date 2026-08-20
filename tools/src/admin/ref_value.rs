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
use rbs_admin_client::attestation::ref_value::{
    RefValueClient, RefValueCreateRequest, RefValueDeleteRequest, RefValueListParams, RefValueListResponse,
    RefValueMutationResponse, RefValueService, RefValueUpdateRequest,
};
use rbs_admin_client::AdminClient;
use rbs_api_types::AttestationDeleteType;
use serde::Serialize;
use tabled::settings::Style;
use tabled::Table;

use crate::admin::GTA_ID_MAX_LEN;
use crate::common::formatter::{format_indented_content, Formatter};
use crate::common::utils::read_path_file;
use crate::common::validate::{
    validate_i64, validate_optional_text, validate_query_ids, validate_required_text, validate_string_max_len,
};
use crate::config::GlobalOptions;
use crate::error::CliError;

const SUPPORTED_ATTESTER_TYPES: [&str; 5] = ["tpm", "tpm_ima", "virt_cca", "ascend_npu", "cca"];
const SUPPORTED_CONTENT_TYPES: [&str; 2] = ["jwt", "base64"];
const DELETE_REF_VALUE_ID: &str = "id";
const DELETE_REF_VALUE_TYPE: &str = "type";
const DELETE_REF_VALUE_ALL: &str = "all";
const DELETE_REF_VALUE_TYPES: [&str; 3] = [DELETE_REF_VALUE_ALL, DELETE_REF_VALUE_ID, DELETE_REF_VALUE_TYPE];
const MAX_CONTENT_SIZE: usize = 10 * 1024 * 1024;
const LIST_MIN_LIMIT: i64 = 1;
const LIST_MAX_LIMIT: i64 = 10;
const LIST_MIN_OFFSET: i64 = 0;
const LIST_MAX_OFFSET: i64 = 100_000;

#[derive(Args, Debug, Clone)]
#[command(about = "Manage attestation ref values")]
pub struct RefValueCli {
    #[command(subcommand)]
    pub command: RefValueCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RefValueCommand {
    #[command(about = "List ref values", long_about = "List current user's ref values.")]
    List(ListArgs),
    #[command(about = "Get one ref value by ID")]
    Get(GetArgs),
    #[command(
        about = "Create a ref value",
        long_about = "Create a ref value. Content may be a JWT or Base64 payload. Use @file to read content from a file."
    )]
    Create(CreateArgs),
    #[command(
        about = "Update a ref value",
        long_about = "Update a ref value. At least one updatable field must be provided. Content may be a JWT or Base64 payload."
    )]
    Update(UpdateArgs),
    #[command(
        about = "Delete ref values",
        long_about = "Delete ref values by id, by attester type, or delete all ref values."
    )]
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated ref value IDs; at most 10 IDs and 500 characters total"
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
    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN), help = "Ref value ID")]
    pub id: String,
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[arg(long, help = "Ref value name")]
    pub name: String,

    #[arg(long, help = "Optional description")]
    pub description: Option<String>,

    #[arg(
        short = 't',
        long = "attester-type",
        value_parser = SUPPORTED_ATTESTER_TYPES,
        help = "Attester type: tpm, tpm_ima, virt_cca, or ascend_npu"
    )]
    pub attester_type: String,

    #[arg(long, help = "JWT or Base64 content, or @file path; size must be between 1 byte and 10 MiB")]
    pub content: String,

    #[arg(
        long,
        value_parser = SUPPORTED_CONTENT_TYPES,
        default_value = "jwt",
        help = "Reference value content encoding: jwt or base64"
    )]
    pub content_type: String,
}

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    #[arg(long, value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN), required = true, help = "Ref value ID")]
    pub id: String,

    #[arg(long, help = "New ref value name")]
    pub name: Option<String>,

    #[arg(long, help = "New description")]
    pub description: Option<String>,

    #[arg(
        short = 't',
        long = "attester-type",
        value_parser = SUPPORTED_ATTESTER_TYPES,
        help = "New attester type"
    )]
    pub attester_type: Option<String>,

    #[arg(long, help = "New JWT or Base64 content, or @file path; size must be between 1 byte and 10 MiB")]
    pub content: Option<String>,

    #[arg(long, value_parser = SUPPORTED_CONTENT_TYPES, help = "New reference value content encoding: jwt or base64")]
    pub content_type: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DeleteArgs {
    #[arg(long, value_parser = DELETE_REF_VALUE_TYPES, help = "Delete mode: all, id, or type")]
    pub delete_type: String,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated ref value IDs; at most 10 IDs and 500 characters total; required when --delete-type id"
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
            validate_query_ids(args.ids.as_deref())?;
            let resp = service
                .list_ref_values(&RefValueListParams {
                    ids: args.ids.clone(),
                    attester_type: args.attester_type.clone(),
                    limit: args.limit,
                    offset: args.offset,
                })
                .await?;
            Ok(Box::new(RefValueListOutput(resp)))
        },
        RefValueCommand::Get(args) => get_ref_value_output(service.get_ref_value(&args.id).await?),
        RefValueCommand::Create(args) => {
            validate_create_args(args)?;
            let resp = service
                .create_ref_value(&RefValueCreateRequest {
                    name: args.name.clone(),
                    description: args.description.clone(),
                    attester_type: args.attester_type.clone(),
                    content: read_ref_value_content(&args.content, &args.content_type)?,
                    content_type: Some(args.content_type.clone()),
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
                    content: args
                        .content
                        .as_ref()
                        .map(|value| read_ref_value_content(value, args.content_type.as_deref().unwrap_or("jwt")))
                        .transpose()?,
                    content_type: args.content_type.clone(),
                })
                .await?;
            Ok(Box::new(RefValueMutationOutput(resp)))
        },
        RefValueCommand::Delete(args) => {
            let request = build_delete_request(args)?;
            service.delete_ref_values(&request).await?;
            Ok(Box::new(DeleteRefValueOutput { target: delete_message(&request) }))
        },
    }
}

fn validate_update_args(args: &UpdateArgs) -> Result<(), CliError> {
    if args.name.is_none()
        && args.description.is_none()
        && args.attester_type.is_none()
        && args.content.is_none()
        && args.content_type.is_none()
    {
        return Err(CliError::InvalidArgument(
            "at least one updatable field must be set: name, description, attester_type, content, content_type"
                .to_string(),
        ));
    }

    if let Some(name) = &args.name {
        validate_required_text(name, 255, "name")?;
    }
    validate_optional_text(args.description.as_deref(), 512, "description")?;
    Ok(())
}

fn validate_create_args(args: &CreateArgs) -> Result<(), CliError> {
    validate_required_text(&args.name, 255, "name")?;
    validate_optional_text(args.description.as_deref(), 512, "description")
}

fn build_delete_request(args: &DeleteArgs) -> Result<RefValueDeleteRequest, CliError> {
    let ids = (!args.ids.is_empty()).then(|| args.ids.clone());
    validate_query_ids(ids.as_deref())?;

    match args.delete_type.as_str() {
        DELETE_REF_VALUE_ID => {
            if ids.is_none() {
                return Err(CliError::InvalidArgument("ids are required when delete_type is `id`".to_string()));
            }
            Ok(RefValueDeleteRequest { delete_type: AttestationDeleteType::Id, ids, attester_type: None })
        },
        DELETE_REF_VALUE_TYPE => {
            if args.attester_type.is_none() {
                return Err(CliError::InvalidArgument(
                    "attester_type is required when delete_type is `type`".to_string(),
                ));
            }
            Ok(RefValueDeleteRequest {
                delete_type: AttestationDeleteType::Type,
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
            Ok(RefValueDeleteRequest { delete_type: AttestationDeleteType::All, ids: None, attester_type: None })
        },
        _ => unreachable!(),
    }
}

fn delete_message(request: &RefValueDeleteRequest) -> String {
    match request.delete_type {
        AttestationDeleteType::Id => {
            format!("deleted ref values: {}", request.ids.clone().unwrap_or_default().join(","))
        },
        AttestationDeleteType::Type => {
            format!("deleted ref values by attester_type: {}", request.attester_type.clone().unwrap_or_default())
        },
        AttestationDeleteType::All => "deleted all ref values".to_string(),
    }
}

#[derive(Debug, Serialize)]
struct DeleteRefValueOutput {
    target: String,
}

impl Formatter for DeleteRefValueOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(format!("Delete succeeded: {}", self.target))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(self).map_err(|_| CliError::InternalFormat)
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
            lines.extend(
                Table::new(self.0.ref_values.iter()).with(Style::markdown()).to_string().lines().map(str::to_string),
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

fn get_ref_value_output(response: RefValueListResponse) -> Result<Box<dyn Formatter>, CliError> {
    match response.ref_values.as_slice() {
        [ref_value] => Ok(Box::new(RefValueOutput(ref_value.clone()))),
        _ => Err(CliError::Message("Reference value not found.".to_string())),
    }
}

#[derive(Debug, Serialize)]
struct RefValueOutput(rbs_admin_client::attestation::ref_value::RefValue);

impl Formatter for RefValueOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let ref_value = &self.0;
        Ok([
            format!("{:<20}{}", "id:", ref_value.id),
            format!("{:<20}{}", "uid:", ref_value.uid.as_deref().unwrap_or("-")),
            format!("{:<20}{}", "name:", ref_value.name),
            format!("{:<20}{}", "attester_type:", ref_value.attester_type),
            format!("{:<20}{}", "description:", ref_value.description.as_deref().unwrap_or("-")),
            format!("{:<20}{}", "content_type:", ref_value.content_type.as_deref().unwrap_or("-")),
            format!("content:\n{}", format_indented_content(ref_value.content.as_deref())),
            format!("{:<20}{}", "version:", ref_value.version.map_or("-".to_string(), |value| value.to_string())),
            format!("{:<20}{}", "valid_code:", ref_value.valid_code.map_or("-".to_string(), |value| value.to_string())),
        ]
        .join("\n"))
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
        lines.push(format!("id: {}", self.0.ref_value.id));
        lines.push(format!("version: {}", self.0.ref_value.version));
        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

fn read_ref_value_content(value: &str, content_type: &str) -> Result<String, CliError> {
    validate_ref_value_input_size(value)?;
    let content = read_path_file(value)?;
    validate_ref_value_content_size(&content)?;
    let is_json_file = value
        .strip_prefix('@')
        .and_then(|path| std::path::Path::new(path).extension())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));

    if content_type == "base64" && is_json_file {
        serde_json::from_str::<serde_json::Value>(&content)
            .map_err(|err| CliError::InvalidArgument(format!("invalid JSON reference value content: {err}")))?;
        let encoded = general_purpose::STANDARD.encode(content.as_bytes());
        validate_ref_value_content_size(&encoded)?;
        return Ok(encoded);
    }

    Ok(content)
}

fn validate_ref_value_input_size(value: &str) -> Result<(), CliError> {
    if let Some(path) = value.strip_prefix('@') {
        let metadata = std::fs::metadata(path).map_err(|_| {
            CliError::FileReadError(
                "unable to access ref value content file. Please check that the file exists and is readable"
                    .to_string(),
            )
        })?;
        if !metadata.is_file() {
            return Err(CliError::InvalidArgument("ref value content path must point to a file".to_string()));
        }
        if metadata.len() == 0 {
            return Err(CliError::InvalidArgument("ref value content must not be empty".to_string()));
        }
        if metadata.len() > MAX_CONTENT_SIZE as u64 {
            return Err(CliError::InvalidArgument(
                "ref value content is too large; maximum size is 10 MiB".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_ref_value_content_size(content: &str) -> Result<(), CliError> {
    if content.is_empty() {
        return Err(CliError::InvalidArgument("ref value content must not be empty".to_string()));
    }
    if content.len() > MAX_CONTENT_SIZE {
        return Err(CliError::InvalidArgument("ref value content is too large; maximum size is 10 MiB".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_create_args() -> CreateArgs {
        CreateArgs {
            name: "ref-value-1".to_string(),
            description: None,
            attester_type: "tpm".to_string(),
            content: "content".to_string(),
            content_type: "jwt".to_string(),
        }
    }

    #[test]
    fn validate_ref_value_text_fields_rejects_blank_and_oversized_values_without_echoing_them() {
        let mut args = base_create_args();
        args.name = " \t".to_string();
        assert_eq!(validate_create_args(&args).expect_err("blank name").to_string(), "name must not be empty");

        let supplied = "x".repeat(513);
        let mut args = base_create_args();
        args.description = Some(supplied.clone());
        let err = validate_create_args(&args).expect_err("long description");
        assert_eq!(err.to_string(), "description is too long; maximum length is 512 characters");
        assert!(!err.to_string().contains(&supplied));
    }

    #[test]
    fn validate_update_args_requires_some_field() {
        let err = validate_update_args(&UpdateArgs {
            id: "rv-1".to_string(),
            name: None,
            description: None,
            attester_type: None,
            content: None,
            content_type: None,
        })
        .expect_err("empty update should fail");
        assert!(err.to_string().contains("at least one updatable field"));
    }

    #[test]
    fn build_delete_request_supports_all_modes() {
        let by_id = build_delete_request(&DeleteArgs {
            delete_type: "id".to_string(),
            ids: vec!["a".to_string()],
            attester_type: None,
        })
        .expect("id delete");
        assert_eq!(by_id.delete_type, AttestationDeleteType::Id);

        let by_type = build_delete_request(&DeleteArgs {
            delete_type: "type".to_string(),
            ids: vec![],
            attester_type: Some("tpm".to_string()),
        })
        .expect("type delete");
        assert_eq!(by_type.attester_type.as_deref(), Some("tpm"));

        let all =
            build_delete_request(&DeleteArgs { delete_type: "all".to_string(), ids: vec![], attester_type: None })
                .expect("all delete");
        assert_eq!(all.delete_type, AttestationDeleteType::All);

        let err = build_delete_request(&DeleteArgs {
            delete_type: "id".to_string(),
            ids: (0..11).map(|index| format!("id-{index}")).collect(),
            attester_type: None,
        })
        .expect_err("too many IDs");
        assert_eq!(err.to_string(), "ids must contain at most 10 values");
    }

    #[test]
    fn delete_message_matches_delete_mode() {
        assert_eq!(
            delete_message(&RefValueDeleteRequest {
                delete_type: AttestationDeleteType::Id,
                ids: Some(vec!["a".to_string()]),
                attester_type: None,
            }),
            "deleted ref values: a"
        );
        assert_eq!(
            delete_message(&RefValueDeleteRequest {
                delete_type: AttestationDeleteType::Type,
                ids: None,
                attester_type: Some("tpm".to_string()),
            }),
            "deleted ref values by attester_type: tpm"
        );
    }

    #[test]
    fn delete_ref_value_output_reports_success() {
        assert_eq!(
            DeleteRefValueOutput { target: "ref values removed: rv-1".to_string() }
                .render_text()
                .expect("render delete"),
            "Delete succeeded: ref values removed: rv-1"
        );
    }

    #[test]
    fn ref_value_content_rejects_empty_inline_and_empty_file() {
        assert_eq!(
            read_ref_value_content("", "jwt").expect_err("empty inline content").to_string(),
            "ref value content must not be empty"
        );

        let path = std::env::temp_dir().join(format!("ref-value-empty-{}.jwt", std::process::id()));
        std::fs::write(&path, "").expect("write empty file");
        let input = format!("@{}", path.display());
        assert_eq!(
            read_ref_value_content(&input, "jwt").expect_err("empty file content").to_string(),
            "ref value content must not be empty"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ref_value_content_accepts_at_prefixed_file() {
        let path = std::env::temp_dir().join(format!("ref-value-{}.jwt", std::process::id()));
        std::fs::write(&path, "jwt-content").expect("write file");
        let input = format!("@{}", path.display());
        assert_eq!(read_ref_value_content(&input, "jwt").expect("read file"), "jwt-content");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ref_value_content_enforces_raw_and_encoded_size_limits_without_echoing_content() {
        let supplied = "x".repeat(MAX_CONTENT_SIZE + 1);
        let err = validate_ref_value_content_size(&supplied).expect_err("oversized raw content");
        assert_eq!(err.to_string(), "ref value content is too large; maximum size is 10 MiB");
        assert!(!err.to_string().contains(&supplied));

        let raw_path = std::env::temp_dir().join(format!("ref-value-raw-large-{}.jwt", std::process::id()));
        std::fs::File::create(&raw_path)
            .expect("create oversized file")
            .set_len((MAX_CONTENT_SIZE + 1) as u64)
            .expect("set oversized file length");
        assert_eq!(
            read_ref_value_content(&format!("@{}", raw_path.display()), "jwt")
                .expect_err("oversized raw file")
                .to_string(),
            "ref value content is too large; maximum size is 10 MiB"
        );
        let _ = std::fs::remove_file(raw_path);

        let path = std::env::temp_dir().join(format!("ref-value-large-{}.json", std::process::id()));
        let json = format!(r#"{{"referenceValues":["{}"]}}"#, "x".repeat(8 * 1024 * 1024));
        std::fs::write(&path, json).expect("write JSON file");
        let input = format!("@{}", path.display());
        assert_eq!(
            read_ref_value_content(&input, "base64").expect_err("oversized encoded content").to_string(),
            "ref value content is too large; maximum size is 10 MiB"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn base64_content_type_encodes_json_files_only() {
        let dir = std::env::temp_dir();
        let json_path = dir.join(format!("ref-value-{}.json", std::process::id()));
        let base64_path = dir.join(format!("ref-value-{}.base64", std::process::id()));
        let json = r#"{"referenceValues":[]}"#;
        let encoded = general_purpose::STANDARD.encode(json);
        std::fs::write(&json_path, json).expect("write json file");
        std::fs::write(&base64_path, &encoded).expect("write base64 file");

        assert_eq!(
            read_ref_value_content(&format!("@{}", json_path.display()), "base64").expect("encode JSON"),
            encoded
        );
        assert_eq!(
            read_ref_value_content(&format!("@{}", base64_path.display()), "base64").expect("preserve Base64"),
            encoded
        );

        let _ = std::fs::remove_file(json_path);
        let _ = std::fs::remove_file(base64_path);
    }

    #[test]
    fn ref_value_outputs_render_text() {
        let list = RefValueListOutput(RefValueListResponse {
            ref_values: vec![rbs_admin_client::attestation::ref_value::RefValue {
                id: "rv-1".to_string(),
                uid: None,
                name: "demo-rv".to_string(),
                description: Some("demo".to_string()),
                attester_type: "tpm".to_string(),
                content: Some("jwt".to_string()),
                content_type: None,
                version: Some(1),
                valid_code: None,
            }],
            total_count: Some(1),
            limit: Some(10),
            offset: Some(20),
        });
        let text = list.render_text().expect("render list");
        assert!(text.contains("demo-rv"));
        assert!(text.contains("tpm"));
        assert!(!text.contains("content"));
        assert!(text.contains("total_count: 1"));
        assert!(text.contains("limit: 10"));
        assert!(text.contains("offset: 20"));

        let mutation = RefValueMutationOutput(RefValueMutationResponse {
            ref_value: rbs_admin_client::attestation::ref_value::RefValueMutation {
                id: "rv-1".to_string(),
                name: "demo-rv".to_string(),
                version: 2,
            },
        });
        let text = mutation.render_text().expect("render mutation");
        assert!(text.contains("id: rv-1"));
        assert!(text.contains("version: 2"));
    }

    #[test]
    fn ref_value_detail_output_renders_complete_indented_content() {
        let text = RefValueOutput(rbs_admin_client::attestation::ref_value::RefValue {
            id: "rv-1".to_string(),
            uid: Some("user-1".to_string()),
            name: "demo-rv".to_string(),
            attester_type: "tpm".to_string(),
            description: Some("demo".to_string()),
            content: Some("line-one\nline-two".to_string()),
            content_type: Some("base64".to_string()),
            version: Some(2),
            valid_code: Some(0),
        })
        .render_text()
        .expect("render detail");

        assert!(text.contains("id:                 rv-1"));
        assert!(text.contains("content:\n    line-one\n    line-two"));
        assert!(text.contains("content_type:       base64"));
        assert!(text.contains("valid_code:         0"));
    }
}

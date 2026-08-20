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
use rbs_admin_client::attestation::cert::{
    CertClient, CertCreateRequest, CertDeleteRequest, CertListParams, CertListResponse, CertMutationResponse,
};
use rbs_admin_client::AdminClient;
use rbs_api_types::AttestationDeleteType;
use serde::Serialize;
use tabled::settings::Style;
use tabled::Table;

use crate::admin::GTA_ID_MAX_LEN;
use crate::common::formatter::{format_epoch_timestamp, format_indented_content, Formatter};
use crate::common::utils::read_path_file;
use crate::common::validate::{
    validate_cert_file, validate_i64, validate_optional_text, validate_query_ids, validate_required_text,
    validate_string_max_len,
};
use crate::config::GlobalOptions;
use crate::error::CliError;

const SUPPORTED_CERT_TYPES: [&str; 7] = ["refvalue", "policy", "tpm_boot", "tpm", "tpm_ima", "ascend_npu", "crl"];

const CRL: &str = "crl";
const DELETE_CERT_ID: &str = "id";
const DELETE_CERT_TYPE: &str = "type";
const DELETE_CERT_ALL: &str = "all";

const DELETE_CERT_TYPES: [&str; 3] = [DELETE_CERT_ID, DELETE_CERT_TYPE, DELETE_CERT_ALL];
const CERT_LIST_MIN_LIMIT: i64 = 1;
const CERT_LIST_MAX_LIMIT: i64 = 10;
const CERT_LIST_MIN_OFFSET: i64 = 0;
const CERT_LIST_MAX_OFFSET: i64 = 100_000;

#[derive(Args, Debug, Clone)]
#[command(about = "Manage attestation certs and CRLs")]
pub struct CertCli {
    #[command(subcommand)]
    pub command: CertCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CertCommand {
    #[command(about = "List certs or CRLs", long_about = "List current user's certs or CRLs.")]
    List(ListArgs),
    #[command(about = "Get one cert or CRL by ID")]
    Get(GetArgs),
    #[command(about = "Create a cert or CRL", long_about = "Create a normal cert or a CRL.")]
    Create(CreateArgs),
    #[command(
        about = "Update a cert",
        long_about = "Update cert metadata. At least one updatable field must be provided."
    )]
    Update(UpdateArgs),
    #[command(
        about = "Delete certs or CRLs",
        long_about = "Delete certs by id, by type, or delete all certs. CRL deletion uses --type crl and optional --ids."
    )]
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated cert or CRL IDs; at most 10 IDs and 500 characters total"
    )]
    pub ids: Option<Vec<String>>,

    #[arg(
        short = 't',
        long = "cert-type",
        value_parser = SUPPORTED_CERT_TYPES,
        help = "Filter by cert type; use `crl` to query CRLs"
    )]
    pub cert_type: Option<String>,

    #[arg(
        long,
        value_parser = |limit: &str| validate_i64(limit, CERT_LIST_MIN_LIMIT, CERT_LIST_MAX_LIMIT, "limit"),
        help = "Page size (1-10; RBS default is 10)"
    )]
    pub limit: Option<i64>,

    #[arg(
        long,
        value_parser = |offset: &str| validate_i64(offset, CERT_LIST_MIN_OFFSET, CERT_LIST_MAX_OFFSET, "offset"),
        help = "Page offset (0-100000; RBS default is 0)"
    )]
    pub offset: Option<i64>,
}

#[derive(Args, Debug, Clone)]
pub struct GetArgs {
    #[arg(short, long, value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN), help = "Cert or CRL ID")]
    pub id: String,
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[arg(short, long, help = "Cert or CRL name")]
    pub name: String,

    #[arg(short, long, help = "Optional description")]
    pub description: Option<String>,

    #[arg(
        short = 't',
        long = "type",
        value_delimiter = ',',
        required = true,
        value_parser = SUPPORTED_CERT_TYPES,
        help = "Cert type list. `crl` must be used alone"
    )]
    pub cert_type: Vec<String>,

    #[arg(
        short,
        long,
        value_parser = validate_cert_file,
        help = "Normal cert content or @file path; required for non-CRL certs"
    )]
    pub content: Option<String>,

    #[arg(
        long = "crl-content",
        value_parser = validate_cert_file,
        help = "CRL content or @file path; required when --type crl"
    )]
    pub crl_content: Option<String>,

    #[arg(long, help = "Whether to mark this cert as default")]
    pub is_default: Option<bool>,
}

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    #[arg(short, long, value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN), help = "Cert ID")]
    pub id: String,

    #[arg(short, long, help = "New cert name")]
    pub name: Option<String>,

    #[arg(short, long, help = "New description")]
    pub description: Option<String>,

    #[arg(
        short = 't',
        long = "type",
        value_delimiter = ',',
        value_parser = SUPPORTED_CERT_TYPES,
        help = "New cert type list; `crl` is not supported here"
    )]
    pub cert_type: Option<Vec<String>>,

    #[arg(long, help = "Whether to mark this cert as default")]
    pub is_default: Option<bool>,
}

#[derive(Args, Debug, Clone)]
pub struct DeleteArgs {
    #[arg(
        long,
        value_parser = DELETE_CERT_TYPES,
        help = "Delete mode for normal certs: id, type, or all"
    )]
    pub delete_type: Option<String>,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated cert or CRL IDs; at most 10 IDs and 500 characters total"
    )]
    pub ids: Vec<String>,

    #[arg(
        short = 't',
        long = "type",
        value_parser = SUPPORTED_CERT_TYPES,
        help = "Cert type for delete-by-type, or `crl` for CRL deletion"
    )]
    pub cert_type: Option<String>,
}

pub fn run(cli: &CertCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|err| CliError::Message(format!("failed to create async runtime: {err}")))?;
    let token = global
        .token
        .as_deref()
        .ok_or_else(|| CliError::InvalidArgument("missing required bearer token".to_string()))?;
    let service = CertClient::new(AdminClient::new(&global.base_url, token, &global.cert)?, None);
    runtime.block_on(execute_cert_command(cli, &service))
}

async fn execute_cert_command(cli: &CertCli, service: &CertClient) -> Result<Box<dyn Formatter>, CliError> {
    match &cli.command {
        CertCommand::List(args) => {
            validate_query_ids(args.ids.as_deref())?;
            let resp = service
                .list_certs(&CertListParams {
                    ids: args.ids.clone(),
                    cert_type: args.cert_type.clone(),
                    limit: args.limit,
                    offset: args.offset,
                })
                .await?;
            Ok(Box::new(CertListOutput(resp)))
        },
        CertCommand::Get(args) => get_cert_output(service.get_cert(&args.id).await?),
        CertCommand::Create(args) => {
            validate_create_args(args)?;
            let resp = service
                .create_cert(&CertCreateRequest {
                    name: args.name.clone(),
                    description: args.description.clone(),
                    cert_type: args.cert_type.clone(),
                    content: read_optional_path(&args.content)?,
                    crl_content: read_optional_path(&args.crl_content)?,
                    is_default: args.is_default,
                })
                .await?;
            Ok(Box::new(CertMutationOutput(resp)))
        },
        CertCommand::Update(args) => {
            validate_update_args(args)?;
            let resp = service
                .update_cert(&rbs_admin_client::attestation::cert::CertUpdateRequest {
                    id: args.id.clone(),
                    name: args.name.clone(),
                    description: args.description.clone(),
                    cert_type: args.cert_type.clone(),
                    is_default: args.is_default,
                    content: None,
                })
                .await?;
            Ok(Box::new(CertMutationOutput(resp)))
        },
        CertCommand::Delete(args) => {
            let request = build_delete_request(args)?;
            service.delete_certs(&request).await?;
            Ok(Box::new(DeleteCertOutput { target: delete_message(&request) }))
        },
    }
}

fn read_optional_path(value: &Option<String>) -> Result<Option<String>, CliError> {
    value.as_ref().map(|content| read_path_file(content)).transpose()
}

fn validate_create_args(args: &CreateArgs) -> Result<(), CliError> {
    validate_required_text(&args.name, 255, "name")?;
    validate_optional_text(args.description.as_deref(), 512, "description")?;

    if args.cert_type.is_empty() {
        return Err(CliError::InvalidArgument("type must not be empty".to_string()));
    }

    let is_crl = args.cert_type.iter().any(|item| item == CRL);
    if is_crl {
        if args.cert_type.len() != 1 {
            return Err(CliError::InvalidArgument("type `crl` must not be combined with other cert types".to_string()));
        }
        if args.crl_content.is_none() {
            return Err(CliError::InvalidArgument("crl_content is required when type is `crl`".to_string()));
        }
        if read_path_file(args.crl_content.as_deref().expect("required crl_content was checked"))
            .map(|value| value.is_empty())?
        {
            return Err(CliError::InvalidArgument("crl_content must not be empty".to_string()));
        }
    } else {
        if args.content.is_none() {
            return Err(CliError::InvalidArgument("content is required for non-CRL certs".to_string()));
        }
        if read_path_file(args.content.as_deref().expect("required content was checked"))
            .map(|value| value.is_empty())?
        {
            return Err(CliError::InvalidArgument("content must not be empty".to_string()));
        }
    }

    Ok(())
}

fn validate_update_args(args: &UpdateArgs) -> Result<(), CliError> {
    if args.name.is_none() && args.description.is_none() && args.cert_type.is_none() && args.is_default.is_none() {
        return Err(CliError::InvalidArgument(
            "at least one updatable field must be set: name, description, type, is_default".to_string(),
        ));
    }

    if let Some(name) = &args.name {
        validate_required_text(name, 255, "name")?;
    }
    validate_optional_text(args.description.as_deref(), 512, "description")?;

    if let Some(cert_type) = &args.cert_type {
        if cert_type.is_empty() {
            return Err(CliError::InvalidArgument("type must not be empty".to_string()));
        }
        if cert_type.iter().any(|item| item == CRL) {
            return Err(CliError::InvalidArgument("update does not support cert type `crl`".to_string()));
        }
    }

    Ok(())
}

fn build_delete_request(args: &DeleteArgs) -> Result<CertDeleteRequest, CliError> {
    let ids = (!args.ids.is_empty()).then(|| args.ids.clone());
    let cert_type = args.cert_type.clone();
    validate_query_ids(ids.as_deref())?;

    if matches!(cert_type.as_deref(), Some(CRL)) {
        if args.delete_type.is_some() {
            return Err(CliError::InvalidArgument("delete_type must not be set when deleting CRLs".to_string()));
        }
        let delete_type = if ids.is_some() { AttestationDeleteType::Id } else { AttestationDeleteType::Type };
        return Ok(CertDeleteRequest { delete_type, ids, cert_type });
    }

    match args.delete_type.as_deref() {
        Some(DELETE_CERT_ID) => {
            if ids.is_none() {
                return Err(CliError::InvalidArgument("ids are required when delete_type is `id`".to_string()));
            }
            Ok(CertDeleteRequest { delete_type: AttestationDeleteType::Id, ids, cert_type: None })
        },
        Some(DELETE_CERT_TYPE) => {
            if cert_type.is_none() {
                return Err(CliError::InvalidArgument("type is required when delete_type is `type`".to_string()));
            }
            Ok(CertDeleteRequest { delete_type: AttestationDeleteType::Type, ids: None, cert_type })
        },
        Some(DELETE_CERT_ALL) => {
            if ids.is_some() || cert_type.is_some() {
                return Err(CliError::InvalidArgument(
                    "ids and type must not be set when delete_type is `all`".to_string(),
                ));
            }
            Ok(CertDeleteRequest { delete_type: AttestationDeleteType::All, ids: None, cert_type: None })
        },
        None => Err(CliError::InvalidArgument(
            "delete_type is required for normal cert deletion; use --type crl for CRL deletion".to_string(),
        )),
        Some(_) => unreachable!(),
    }
}

fn delete_message(request: &CertDeleteRequest) -> String {
    if matches!(request.cert_type.as_deref(), Some(CRL)) {
        if let Some(ids) = &request.ids {
            format!("CRLs removed: {}", ids.join(","))
        } else {
            "all CRLs removed".to_string()
        }
    } else {
        match request.delete_type {
            AttestationDeleteType::Id => {
                format!("certs removed: {}", request.ids.clone().unwrap_or_default().join(","))
            },
            AttestationDeleteType::Type => {
                format!("certs removed by type: {}", request.cert_type.clone().unwrap_or_default())
            },
            AttestationDeleteType::All => "all certs removed".to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DeleteCertOutput {
    target: String,
}

impl Formatter for DeleteCertOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(format!("Delete succeeded: {}", self.target))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(self).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct CertListOutput(CertListResponse);

impl Formatter for CertListOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = vec!["certs:".to_string()];

        if self.0.certs.is_empty() {
            lines.push("  <empty>".to_string());
        } else {
            lines.extend(
                Table::new(self.0.certs.iter()).with(Style::markdown()).to_string().lines().map(str::to_string),
            );
        }

        if !self.0.crls.is_empty() {
            lines.push("crls:".to_string());
            lines
                .extend(Table::new(self.0.crls.iter()).with(Style::markdown()).to_string().lines().map(str::to_string));
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

fn get_cert_output(response: CertListResponse) -> Result<Box<dyn Formatter>, CliError> {
    match (response.certs.as_slice(), response.crls.as_slice()) {
        ([cert], []) => Ok(Box::new(CertOutput(cert.clone()))),
        ([], [crl]) => Ok(Box::new(CrlOutput(crl.clone()))),
        _ => Err(CliError::Message("Certificate or CRL not found.".to_string())),
    }
}

#[derive(Debug, Serialize)]
struct CertOutput(rbs_admin_client::attestation::cert::CertRecord);

impl Formatter for CertOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let cert = &self.0;
        Ok([
            format!("{:<20}{}", "cert_id:", cert.cert_id.as_deref().unwrap_or("-")),
            format!("{:<20}{}", "cert_name:", cert.cert_name.as_deref().unwrap_or("-")),
            format!("{:<20}{}", "description:", cert.description.as_deref().unwrap_or("-")),
            format!("content:\n{}", format_indented_content(cert.content.as_deref())),
            format!(
                "{:<20}{}",
                "cert_type:",
                serde_json::to_string(&cert.cert_type).map_err(|err| CliError::Message(err.to_string()))?
            ),
            format!("{:<20}{}", "is_default:", cert.is_default.map_or("-".to_string(), |value| value.to_string())),
            format!("{:<20}{}", "version:", cert.version.map_or("-".to_string(), |value| value.to_string())),
            format!("{:<20}{}", "create_time:", format_epoch_timestamp(cert.create_time)),
            format!("{:<20}{}", "update_time:", format_epoch_timestamp(cert.update_time)),
            format!("{:<20}{}", "valid_code:", cert.valid_code.map_or("-".to_string(), |value| value.to_string())),
            format!(
                "{:<20}{}",
                "cert_revoked_date:",
                cert.cert_revoked_date.map_or("-".to_string(), |value| value.to_string())
            ),
            format!("{:<20}{}", "cert_revoked_reason:", cert.cert_revoked_reason.as_deref().unwrap_or("-")),
        ]
        .join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct CrlOutput(rbs_admin_client::attestation::cert::CrlRecord);

impl Formatter for CrlOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let crl = &self.0;
        Ok([
            format!("{:<20}{}", "crl_id:", crl.crl_id.as_deref().unwrap_or("-")),
            format!("{:<20}{}", "crl_name:", crl.crl_name.as_deref().unwrap_or("-")),
            format!("{:<20}{}", "crl_content:", crl.crl_content.as_deref().unwrap_or("-")),
        ]
        .join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct CertMutationOutput(CertMutationResponse);

impl Formatter for CertMutationOutput {
    fn render_text(&self) -> Result<String, CliError> {
        if let Some(cert) = &self.0.cert {
            return Ok([
                format!("{:<20}{}", "cert_id:", cert.cert_id.as_deref().unwrap_or("-")),
                format!("{:<20}{}", "cert_name:", cert.cert_name.as_deref().unwrap_or("-")),
                format!("{:<20}{}", "version:", cert.version.map_or("-".to_string(), |value| value.to_string())),
            ]
            .join("\n"));
        }

        if let Some(crl) = &self.0.crl {
            return Ok([
                format!("{:<20}{}", "crl_id:", crl.crl_id.as_deref().unwrap_or("-")),
                format!("{:<20}{}", "crl_name:", crl.crl_name.as_deref().unwrap_or("-")),
            ]
            .join("\n"));
        }

        Ok("<empty>".to_string())
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_create_args() -> CreateArgs {
        CreateArgs {
            name: "cert-1".to_string(),
            description: None,
            cert_type: vec!["tpm".to_string()],
            content: Some("pem".to_string()),
            crl_content: None,
            is_default: None,
        }
    }

    #[test]
    fn validate_create_args_enforces_crl_shape() {
        let mut args = base_create_args();
        args.cert_type = vec!["crl".to_string(), "tpm".to_string()];
        let err = validate_create_args(&args).expect_err("mixed crl type should fail");
        assert!(err.to_string().contains("must not be combined"));

        let mut args = base_create_args();
        args.cert_type = vec!["crl".to_string()];
        args.content = None;
        let err = validate_create_args(&args).expect_err("missing crl content should fail");
        assert!(err.to_string().contains("crl_content is required"));

        let mut args = base_create_args();
        args.cert_type = vec!["crl".to_string()];
        args.crl_content = Some("crl-content".to_string());
        assert!(validate_create_args(&args).is_ok());
    }

    #[test]
    fn validate_create_args_rejects_empty_required_cert_and_crl_content() {
        let mut args = base_create_args();
        args.content = Some("".to_string());
        assert_eq!(
            validate_create_args(&args).expect_err("empty cert content").to_string(),
            "content must not be empty"
        );

        let empty_path = std::env::temp_dir().join(format!("empty-crl-{}.pem", std::process::id()));
        std::fs::write(&empty_path, "").expect("write empty CRL file");
        let args = CreateArgs {
            name: "crl-1".to_string(),
            description: None,
            cert_type: vec!["crl".to_string()],
            content: None,
            crl_content: Some(format!("@{}", empty_path.display())),
            is_default: None,
        };
        assert_eq!(
            validate_create_args(&args).expect_err("empty CRL content").to_string(),
            "crl_content must not be empty"
        );
        let _ = std::fs::remove_file(empty_path);
    }

    #[test]
    fn validate_cert_text_fields_rejects_blank_and_oversized_values_without_echoing_them() {
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
    fn validate_update_args_rejects_empty_or_crl_type() {
        let err = validate_update_args(&UpdateArgs {
            id: "cert-1".to_string(),
            name: None,
            description: None,
            cert_type: None,
            is_default: None,
        })
        .expect_err("empty update should fail");
        assert!(err.to_string().contains("at least one updatable field"));

        let err = validate_update_args(&UpdateArgs {
            id: "cert-1".to_string(),
            name: Some("name".to_string()),
            description: None,
            cert_type: Some(vec!["crl".to_string()]),
            is_default: None,
        })
        .expect_err("crl update should fail");
        assert!(err.to_string().contains("does not support cert type `crl`"));

        let err = validate_update_args(&UpdateArgs {
            id: "cert-1".to_string(),
            name: None,
            description: None,
            cert_type: Some(vec![]),
            is_default: None,
        })
        .expect_err("empty type should fail");
        assert_eq!(err.to_string(), "type must not be empty");
    }

    #[test]
    fn build_delete_request_supports_normal_and_crl_modes() {
        let by_id = build_delete_request(&DeleteArgs {
            delete_type: Some("id".to_string()),
            ids: vec!["a".to_string()],
            cert_type: None,
        })
        .expect("id delete");
        assert_eq!(by_id.delete_type, AttestationDeleteType::Id);

        let crl = build_delete_request(&DeleteArgs {
            delete_type: None,
            ids: vec!["crl-1".to_string()],
            cert_type: Some("crl".to_string()),
        })
        .expect("crl delete");
        assert_eq!(crl.cert_type.as_deref(), Some("crl"));

        let err = build_delete_request(&DeleteArgs {
            delete_type: Some("id".to_string()),
            ids: (0..11).map(|index| format!("id-{index}")).collect(),
            cert_type: None,
        })
        .expect_err("too many IDs");
        assert_eq!(err.to_string(), "ids must contain at most 10 values");

        assert!(build_delete_request(&DeleteArgs {
            delete_type: Some("type".to_string()),
            ids: vec![],
            cert_type: None,
        })
        .is_err());
        assert!(build_delete_request(&DeleteArgs {
            delete_type: Some("all".to_string()),
            ids: vec!["cert-1".to_string()],
            cert_type: None,
        })
        .is_err());
        assert!(build_delete_request(&DeleteArgs {
            delete_type: Some("id".to_string()),
            ids: vec![],
            cert_type: Some("crl".to_string()),
        })
        .is_err());
    }

    #[test]
    fn cert_crl_and_mutation_outputs_cover_alternate_response_shapes() {
        let crl = rbs_admin_client::attestation::cert::CrlRecord {
            crl_id: Some("crl-1".to_string()),
            crl_name: Some("demo-crl".to_string()),
            crl_content: Some("crl-data".to_string()),
        };
        let output = get_cert_output(CertListResponse {
            certs: vec![],
            crls: vec![crl.clone()],
            total_count: None,
            limit: None,
            offset: None,
        })
        .expect("one CRL");
        assert!(output.render_text().expect("CRL text").contains("crl_content:        crl-data"));
        assert!(output.render_json().expect("CRL JSON").contains("crl-1"));
        assert!(CertListOutput(CertListResponse {
            certs: vec![],
            crls: vec![crl.clone()],
            total_count: None,
            limit: None,
            offset: None,
        })
        .render_text()
        .expect("CRL list")
        .contains("crls:"));
        assert!(get_cert_output(CertListResponse {
            certs: vec![],
            crls: vec![],
            total_count: None,
            limit: None,
            offset: None,
        })
        .is_err());

        let crl_mutation = CertMutationOutput(CertMutationResponse {
            cert: None,
            crl: Some(rbs_admin_client::attestation::cert::CertMutationCrl {
                crl_id: Some("crl-1".to_string()),
                crl_name: Some("demo-crl".to_string()),
            }),
        });
        assert!(crl_mutation.render_text().expect("CRL mutation").contains("crl_id:             crl-1"));
        assert_eq!(
            CertMutationOutput(CertMutationResponse { cert: None, crl: None }).render_text().expect("empty mutation"),
            "<empty>"
        );
    }

    #[test]
    fn delete_message_describes_request() {
        assert_eq!(
            delete_message(&CertDeleteRequest {
                delete_type: AttestationDeleteType::Id,
                ids: Some(vec!["a".to_string(), "b".to_string()]),
                cert_type: None,
            }),
            "certs removed: a,b"
        );
        assert_eq!(
            delete_message(&CertDeleteRequest {
                delete_type: AttestationDeleteType::Type,
                ids: None,
                cert_type: Some("tpm".to_string()),
            }),
            "certs removed by type: tpm"
        );
        assert_eq!(
            delete_message(&CertDeleteRequest {
                delete_type: AttestationDeleteType::Id,
                ids: Some(vec!["crl-1".to_string()]),
                cert_type: Some("crl".to_string()),
            }),
            "CRLs removed: crl-1"
        );
    }

    #[test]
    fn delete_cert_output_reports_success() {
        assert_eq!(
            DeleteCertOutput { target: "certs removed: cert-1".to_string() }.render_text().expect("render delete"),
            "Delete succeeded: certs removed: cert-1"
        );
    }

    #[test]
    fn cert_list_output_uses_standard_empty_list_shape() {
        let text = CertListOutput(CertListResponse {
            certs: vec![],
            crls: vec![],
            total_count: Some(0),
            limit: Some(10),
            offset: Some(0),
        })
        .render_text()
        .expect("render empty list");

        assert_eq!(text, "certs:\n  <empty>\ntotal_count: 0\nlimit: 10\noffset: 0");
    }

    #[test]
    fn cert_detail_output_renders_aligned_fields() {
        let text = CertOutput(rbs_admin_client::attestation::cert::CertRecord {
            cert_id: Some("cert-1".to_string()),
            cert_name: Some("demo-cert".to_string()),
            description: None,
            content: Some("pem-data".to_string()),
            cert_type: Some(vec!["tpm".to_string()]),
            is_default: Some(true),
            version: Some(2),
            create_time: Some(1_700_000_000),
            update_time: Some(1_700_000_000_000),
            valid_code: Some(0),
            cert_revoked_date: None,
            cert_revoked_reason: None,
        })
        .render_text()
        .expect("render cert detail");

        assert!(text.contains("cert_id:            cert-1"));
        assert!(text.contains("cert_type:          [\"tpm\"]"));
        assert!(text.contains("content:\n    pem-data"));
        assert!(text.contains("is_default:         true"));
        assert!(text.contains("create_time:        2023-11-14T22:13:20+00:00"));
        assert!(text.contains("update_time:        2023-11-14T22:13:20+00:00"));
    }

    #[test]
    fn cert_mutation_output_uses_detail_field_order_and_alignment() {
        let text = CertMutationOutput(CertMutationResponse {
            cert: Some(rbs_admin_client::attestation::cert::CertMutationCert {
                cert_id: Some("cert-1".to_string()),
                cert_name: Some("demo-cert".to_string()),
                version: Some(2),
            }),
            crl: None,
        })
        .render_text()
        .expect("render mutation");

        assert_eq!(text, "cert_id:            cert-1\ncert_name:          demo-cert\nversion:            2");
    }
}

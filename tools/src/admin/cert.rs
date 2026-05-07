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
    CertService,
};
use rbs_admin_client::AdminClient;
use serde::Serialize;

use crate::admin::GTA_ID_MAX_LEN;
use crate::common::formatter::{Formatter, TextOutput};
use crate::common::utils::read_path_file;
use crate::common::validate::{validate_cert_file, validate_string_max_len};
use crate::config::GlobalOptions;
use crate::error::CliError;

const SUPPORTED_CERT_TYPES: [&str; 7] =
    ["refvalue", "policy", "tpm_boot", "tpm", "tpm_ima", "ascend_npu", "crl"];

const CRL: &str = "crl";
const DELETE_CERT_ID: &str = "id";
const DELETE_CERT_TYPE: &str = "type";
const DELETE_CERT_ALL: &str = "all";

const DELETE_CERT_TYPES: [&str; 3] = [DELETE_CERT_ID, DELETE_CERT_TYPE, DELETE_CERT_ALL];

#[derive(Args, Debug, Clone)]
#[command(about = "Manage attestation certs and CRLs")]
pub struct CertCli {
    #[command(subcommand)]
    pub command: CertCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CertCommand {
    #[command(
        about = "List certs or CRLs",
        long_about = "List current user's certs or CRLs.\n\nExamples:\n  rbs-cli cert list\n  rbs-cli cert list --ids abc123,def456\n  rbs-cli cert list --cert-type crl"
    )]
    List(ListArgs),
    #[command(
        about = "Create a cert or CRL",
        long_about = "Create a normal cert or a CRL.\n\nNormal cert:\n  rbs-cli cert create --name test-cert --type tpm --content @cert.pem\n\nCRL:\n  rbs-cli cert create --name test-crl --type crl --crl-content @test.crl"
    )]
    Create(CreateArgs),
    #[command(
        about = "Update a cert",
        long_about = "Update cert metadata. At least one updatable field must be provided.\n\nExample:\n  rbs-cli cert update --id abc123 --name new-name --type tpm --is-default true"
    )]
    Update(UpdateArgs),
    #[command(
        about = "Delete certs or CRLs",
        long_about = "Delete certs by id, by type, or delete all certs. CRL deletion uses --type crl and optional --ids.\n\nExamples:\n  rbs-cli cert delete --delete-type id --ids abc123,def456\n  rbs-cli cert delete --delete-type type --type tpm\n  rbs-cli cert delete --delete-type all\n  rbs-cli cert delete --type crl --ids crl-1,crl-2"
    )]
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[arg(
        long,
        value_delimiter = ',',
        value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN),
        help = "Comma-separated cert or CRL IDs"
    )]
    pub ids: Option<Vec<String>>,

    #[arg(
        short = 't',
        long = "cert-type",
        value_parser = SUPPORTED_CERT_TYPES,
        help = "Filter by cert type; use `crl` to query CRLs"
    )]
    pub cert_type: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[arg(short, long, value_parser = |s: &str| validate_string_max_len(s, 255), help = "Cert or CRL name")]
    pub name: String,

    #[arg(short, long, value_parser = |s: &str| validate_string_max_len(s, 512), help = "Optional description")]
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

    #[arg(short, long, help = "Whether to mark this cert as default")]
    pub is_default: Option<bool>,
}

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    #[arg(short, long, value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN), help = "Cert ID")]
    pub id: String,

    #[arg(short, long, value_parser = |s: &str| validate_string_max_len(s, 255), help = "New cert name")]
    pub name: Option<String>,

    #[arg(short, long, value_parser = |s: &str| validate_string_max_len(s, 512), help = "New description")]
    pub description: Option<String>,

    #[arg(
        short = 't',
        long = "type",
        value_delimiter = ',',
        value_parser = SUPPORTED_CERT_TYPES,
        help = "New cert type list; `crl` is not supported here"
    )]
    pub cert_type: Option<Vec<String>>,

    #[arg(short, long, help = "Whether to mark this cert as default")]
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
        value_parser = |s: &str| validate_string_max_len(s, GTA_ID_MAX_LEN),
        help = "Comma-separated cert or CRL IDs"
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
            let resp = service
                .list_certs(&CertListParams { ids: args.ids.clone(), cert_type: args.cert_type.clone() })
                .await?;
            Ok(Box::new(CertListOutput(resp)))
        },
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
                })
                .await?;
            Ok(Box::new(CertMutationOutput(resp)))
        },
        CertCommand::Delete(args) => {
            let request = build_delete_request(args)?;
            let message = delete_message(&request);
            service.delete_certs(&request).await?;
            Ok(Box::new(TextOutput::new(message)))
        },
    }
}

fn read_optional_path(value: &Option<String>) -> Result<Option<String>, CliError> {
    value.as_ref().map(|content| read_path_file(content)).transpose()
}

fn validate_create_args(args: &CreateArgs) -> Result<(), CliError> {
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
        if args.content.is_some() {
            return Err(CliError::InvalidArgument("content must not be set when type is `crl`".to_string()));
        }
    } else if args.content.is_none() {
        return Err(CliError::InvalidArgument("content is required for non-CRL certs".to_string()));
    }

    Ok(())
}

fn validate_update_args(args: &UpdateArgs) -> Result<(), CliError> {
    if args.name.is_none() && args.description.is_none() && args.cert_type.is_none() && args.is_default.is_none() {
        return Err(CliError::InvalidArgument(
            "at least one updatable field must be set: name, description, type, is_default".to_string(),
        ));
    }

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

    if matches!(cert_type.as_deref(), Some(CRL)) {
        if args.delete_type.is_some() {
            return Err(CliError::InvalidArgument("delete_type must not be set when deleting CRLs".to_string()));
        }
        let delete_type = if ids.is_some() { DELETE_CERT_ID } else { DELETE_CERT_TYPE };
        return Ok(CertDeleteRequest { delete_type: delete_type.to_string(), ids, cert_type });
    }

    match args.delete_type.as_deref() {
        Some(DELETE_CERT_ID) => {
            if ids.is_none() {
                return Err(CliError::InvalidArgument("ids are required when delete_type is `id`".to_string()));
            }
            Ok(CertDeleteRequest { delete_type: DELETE_CERT_ID.to_string(), ids, cert_type: None })
        },
        Some(DELETE_CERT_TYPE) => {
            if cert_type.is_none() {
                return Err(CliError::InvalidArgument("type is required when delete_type is `type`".to_string()));
            }
            Ok(CertDeleteRequest { delete_type: DELETE_CERT_TYPE.to_string(), ids: None, cert_type })
        },
        Some(DELETE_CERT_ALL) => {
            if ids.is_some() || cert_type.is_some() {
                return Err(CliError::InvalidArgument(
                    "ids and type must not be set when delete_type is `all`".to_string(),
                ));
            }
            Ok(CertDeleteRequest { delete_type: DELETE_CERT_ALL.to_string(), ids: None, cert_type: None })
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
            format!("deleted crls: {}", ids.join(","))
        } else {
            "deleted all crls".to_string()
        }
    } else {
        match request.delete_type.as_str() {
            DELETE_CERT_ID => format!("deleted certs: {}", request.ids.clone().unwrap_or_default().join(",")),
            DELETE_CERT_TYPE => {
                format!("deleted certs by type: {}", request.cert_type.clone().unwrap_or_default())
            },
            DELETE_CERT_ALL => "deleted all certs".to_string(),
            _ => "deleted certs".to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CertListOutput(CertListResponse);

impl Formatter for CertListOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let mut lines = Vec::new();

        if !self.0.certs.is_empty() {
            lines.push("certs:".to_string());
            for cert in &self.0.certs {
                let mut parts =
                    vec![format!("name={}", cert.name), format!("id={}", cert.id.as_deref().unwrap_or("-"))];
                if !cert.cert_type.is_empty() {
                    parts.push(format!("type={}", cert.cert_type.join(",")));
                }
                if let Some(version) = cert.version {
                    parts.push(format!("version={version}"));
                }
                if let Some(description) = &cert.description {
                    parts.push(format!("description={description}"));
                }
                if let Some(is_default) = cert.is_default {
                    parts.push(format!("is_default={is_default}"));
                }
                if let Some(content) = &cert.content {
                    parts.push(format!("content={}", content.replace('\n', "\\n")));
                }
                lines.push(format!("  - {}", parts.join(" ")));
            }
        }

        if !self.0.crls.is_empty() {
            lines.push("crls:".to_string());
            for crl in &self.0.crls {
                let mut parts = vec![format!("name={}", crl.name), format!("id={}", crl.id.as_deref().unwrap_or("-"))];
                if let Some(content) = &crl.content {
                    parts.push(format!("content={}", content.replace('\n', "\\n")));
                }
                lines.push(format!("  - {}", parts.join(" ")));
            }
        }

        if lines.is_empty() {
            lines.push("certs: <empty>".to_string());
        }

        Ok(lines.join("\n"))
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
            let mut lines = vec![format!("cert_name: {}", cert.name)];
            if let Some(id) = &cert.id {
                lines.push(format!("cert_id: {id}"));
            }
            if let Some(version) = cert.version {
                lines.push(format!("version: {version}"));
            }
            return Ok(lines.join("\n"));
        }

        if let Some(crl) = &self.0.crl {
            let mut lines = vec![format!("crl_name: {}", crl.name)];
            if let Some(id) = &crl.id {
                lines.push(format!("crl_id: {id}"));
            }
            return Ok(lines.join("\n"));
        }

        Ok("<empty>".to_string())
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

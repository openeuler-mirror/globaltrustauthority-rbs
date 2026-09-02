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

use std::fs;
use std::io::{self, IsTerminal, Read};

use base64::Engine as _;
use clap::{Args, Subcommand};
use rbc::cli::utils::load_private_key_pem;
use rbc::tools::tee_key::TeeKeyPair;
use rbs_admin_client::resource::{ResourceClient, ResourcePath};
use rbs_admin_client::AdminClient;
use rbs_api_types::constants::RESOURCE_TYPES;
use rbs_api_types::{CreateResourceRequest, ResourceContentResponse, ResourceResponse, UpdateResourceRequest};
use serde::Serialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::common::formatter::{Formatter, TextOutput};
use crate::common::utils::read_path_file;
use crate::common::validate::{validate_file_path, validate_resource_segment, validate_trimmed_string_max_len};
use crate::config::GlobalOptions;
use crate::error::CliError;
const RESOURCE_CONTENT_TYPES: [&str; 6] = ["jwt", "json", "text", "binary", "jwk", "jwe"];
const EXPORT_MODES: [&str; 1] = ["jwe"];
const RESOURCE_SEGMENT_MAX_LEN: usize = 256;
const POLICY_ID_MAX_LEN: usize = 64;
const PASSPHRASE_MAX_LEN: usize = 1024;

const ADDITIONAL_INFO_MAX_LEN: usize = 512;

#[derive(Args, Debug, Clone)]
#[command(about = "Manage key, secret, and cert resources")]
pub struct ResCli {
    #[command(subcommand)]
    pub command: ResCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ResCommand {
    #[command(
        about = "Get and decrypt resource content",
        long_about = "Get resource content and decrypt the JWE payload with a private key.\n\nExample:\n  rbs-cli res get --uri vault/default/secret/my-secret --private-key-file tee-private.pem"
    )]
    Get(GetContentArgs),
    #[command(
        name = "get-res-info",
        about = "Get resource metadata",
        long_about = "Get resource metadata without returning resource content.\n\nExample:\n  rbs-cli res get-res-info --uri vault/default/secret/my-secret"
    )]
    GetResInfo(PathArgs),
    #[command(
        about = "Create a resource binding",
        long_about = "Create resource metadata for a key, secret, or cert resource.\n\nExample:\n  rbs-cli res create --uri vault/default/secret/my-secret --policy-id policy-1 --content-type text --export-mode jwe\n\nWith --content, the Base64-decoded payload is stored in backends that support writes (e.g. HSM):\n  rbs-cli res create --uri hsm/default/key/my-key --policy-id policy-1 --content-type binary --content @key.b64"
    )]
    Create(CreateArgs),
    #[command(
        about = "Update a resource binding",
        long_about = "Update resource metadata for a key, secret, or cert resource.\n\nExample:\n  rbs-cli res update --uri vault/default/secret/my-secret --policy-id policy-1 --content-type text --export-mode jwe\n\nWith --content, the Base64-decoded payload replaces the stored value in backends that support writes (e.g. HSM):\n  rbs-cli res update --uri hsm/default/key/my-key --content-type binary --content @key.b64"
    )]
    Update(UpdateArgs),
    #[command(
        about = "Delete a resource",
        long_about = "Delete a key, secret, or cert resource.\n\nExample:\n  rbs-cli res delete --uri vault/default/secret/my-secret"
    )]
    Delete(PathArgs),
}

#[derive(Args, Debug, Clone)]
pub struct PathArgs {
    #[arg(long, value_parser = validate_resource_uri, help = "Resource URI in provider/repository/type/name form")]
    pub uri: String,
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[command(flatten)]
    pub path: PathArgs,

    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_ID_MAX_LEN, "policy_id"), help = "Bound resource policy ID")]
    pub policy_id: String,

    #[arg(long, value_parser = read_path_file, help = "Optional Base64 additional_info value or @file path")]
    pub additional_info: Option<String>,

    #[arg(long, value_parser = normalize_base64_content, help = "Optional Base64 content value or @file path; raw content is Base64-encoded automatically")]
    pub content: Option<String>,

    #[arg(long, value_parser = RESOURCE_CONTENT_TYPES, help = "Resource content type: jwt, json, text, binary, jwk, or jwe")]
    pub content_type: Option<String>,

    #[arg(long, value_parser = EXPORT_MODES, help = "Export mode: jwe")]
    pub export_mode: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct GetContentArgs {
    #[command(flatten)]
    pub path: PathArgs,

    #[arg(long, value_parser = validate_file_path, help = "Path to the PEM private key used to decrypt the resource JWE")]
    pub private_key_file: String,

    #[arg(
        long,
        num_args = 0..=1,
        value_name = "@PATH",
        help = "Read the private key passphrase interactively or from @PATH"
    )]
    pub private_key_passphrase: Option<Option<String>>,
}

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    #[command(flatten)]
    pub path: PathArgs,

    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, POLICY_ID_MAX_LEN, "policy-id"), help = "New policy ID to rebind the resource to; omit to keep the current binding")]
    pub policy_id: Option<String>,

    #[arg(long, value_parser = |s: &str| validate_trimmed_string_max_len(s, ADDITIONAL_INFO_MAX_LEN, "additional-info"), help = "Optional Base64 additional_info value or @file path")]
    pub additional_info: Option<String>,

    #[arg(long, value_parser = normalize_base64_content, help = "Optional Base64 content value or @file path; raw content is Base64-encoded automatically")]
    pub content: Option<String>,

    #[arg(long, value_parser = RESOURCE_CONTENT_TYPES, help = "Resource content type: jwt, json, text, binary, jwk, or jwe")]
    pub content_type: Option<String>,

    #[arg(long, value_parser = EXPORT_MODES, help = "Export mode: jwe")]
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
            let resp = service.get_resource(&args.path.uri).await?;
            Ok(Box::new(decrypt_resource_content(resp, args)?))
        },
        ResCommand::GetResInfo(args) => {
            let resp = service.get_resource_info(&build_path(args)).await?;
            Ok(Box::new(ResourceMetadataOutput(resp)))
        },
        ResCommand::Create(args) => {
            let resp = service
                .create_resource(
                    &build_path(&args.path),
                    &CreateResourceRequest {
                        policy_id: args.policy_id.clone(),
                        additional_info: args.additional_info.clone(),
                        content_type: args.content_type.clone(),
                        export_mode: args.export_mode.clone(),
                        content: args.content.clone(),
                    },
                )
                .await?;
            Ok(Box::new(ResourceMetadataOutput(resp)))
        },
        ResCommand::Update(args) => {
            let resp = service
                .update_resource(
                    &build_path(&args.path),
                    &UpdateResourceRequest {
                        policy_id: args.policy_id.clone(),
                        additional_info: args.additional_info.clone(),
                        content_type: args.content_type.clone(),
                        export_mode: args.export_mode.clone(),
                        content: args.content.clone(),
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

fn build_path(args: &PathArgs) -> ResourcePath {
    let [provider_name, repository_name, resource_type, resource_name] =
        split_resource_uri(&args.uri).expect("PathArgs.uri is validated by clap before command execution");
    ResourcePath {
        provider_name: provider_name.to_string(),
        repository_name: repository_name.to_string(),
        resource_type: resource_type.to_string(),
        resource_name: resource_name.to_string(),
    }
}

fn resource_uri(path: &ResourcePath) -> String {
    format!("{}/{}/{}/{}", path.provider_name, path.repository_name, path.resource_type, path.resource_name)
}

fn validate_resource_uri(value: &str) -> Result<String, CliError> {
    let parts = split_resource_uri(value)?;
    for part in &parts {
        validate_resource_segment(part, RESOURCE_SEGMENT_MAX_LEN)?;
    }
    if !RESOURCE_TYPES.contains(&parts[2]) {
        return Err(CliError::InvalidArgument(format!(
            "resource type must be one of {}; got `{}`",
            RESOURCE_TYPES.join(", "),
            parts[2]
        )));
    }
    Ok(value.to_string())
}

fn split_resource_uri(value: &str) -> Result<[&str; 4], CliError> {
    let mut parts = value.split('/');
    let parsed = match (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(provider), Some(repository), Some(resource_type), Some(resource_name), None) => {
            [provider, repository, resource_type, resource_name]
        },
        _ => {
            return Err(CliError::InvalidArgument(
                "resource URI must use provider/repository/type/name format, for example vault/default/secret/demo"
                    .to_string(),
            ))
        },
    };
    Ok(parsed)
}

fn decrypt_resource_content(
    resource: ResourceContentResponse,
    args: &GetContentArgs,
) -> Result<ResourceContentOutput, CliError> {
    let passphrase = load_passphrase(&args.private_key_passphrase)?;
    let private_pem = load_private_key_pem(&args.private_key_file, passphrase.as_ref().map(|value| value.as_bytes()))
        .map_err(|err| CliError::InvalidArgument(format!("failed to load private key: {err}")))?;
    let ciphertext = decode_resource_jwe(&resource.content)?;
    let key_pair = TeeKeyPair::from_private_pem(&private_pem, None)
        .map_err(|err| CliError::InvalidArgument(format!("failed to load private key for JWE decryption: {err}")))?;
    let content = key_pair
        .decrypt_jwe(&ciphertext)
        .map_err(|err| CliError::InvalidArgument(format!("failed to decrypt resource content: {err}")))?;

    Ok(ResourceContentOutput {
        uri: resource.uri,
        content,
        content_type: resource.content_type,
        export_mode: resource.export_mode,
    })
}

fn decode_resource_jwe(content: &str) -> Result<String, CliError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(content)
        .map_err(|err| CliError::InvalidArgument(format!("resource content is not valid Base64 JWE data: {err}")))?;
    String::from_utf8(decoded)
        .map_err(|_| CliError::InvalidArgument("resource content is not valid UTF-8 JWE; cannot decrypt".to_string()))
}

fn normalize_base64_content(value: &str) -> Result<String, CliError> {
    if let Some(path) = value.strip_prefix('@') {
        let bytes = fs::read(path).map_err(|_| {
            CliError::FileReadError(format!(
                "unable to read file `{path}`. Please check that the file exists and is readable"
            ))
        })?;
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let trimmed = text.trim();
            if !trimmed.is_empty() && base64::engine::general_purpose::STANDARD.decode(trimmed).is_ok() {
                return Ok(trimmed.to_string());
            }
            if trimmed.is_empty() {
                return Err(CliError::InvalidArgument("content must not be empty".to_string()));
            }
        }
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    } else {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(CliError::InvalidArgument("content must not be empty".to_string()));
        }
        if base64::engine::general_purpose::STANDARD.decode(trimmed).is_ok() {
            Ok(trimmed.to_string())
        } else {
            Ok(base64::engine::general_purpose::STANDARD.encode(value.as_bytes()))
        }
    }
}

fn load_passphrase(passphrase: &Option<Option<String>>) -> Result<Option<Zeroizing<String>>, CliError> {
    match passphrase {
        None => Ok(None),
        Some(None) => {
            if io::stdin().is_terminal() {
                let value = rpassword::prompt_password("Private key passphrase: ")
                    .map(Zeroizing::new)
                    .map_err(|_| CliError::Message("unable to read the private key passphrase".to_string()))?;
                validate_passphrase_len(&value)?;
                Ok(Some(value))
            } else {
                let mut value = Zeroizing::new(String::new());
                io::stdin()
                    .read_to_string(&mut value)
                    .map_err(|_| CliError::Message("unable to read the private key passphrase".to_string()))?;
                trim_line_end(&mut value);
                validate_passphrase_len(&value)?;
                Ok(Some(value))
            }
        },
        Some(Some(value)) => {
            let Some(path) = value.strip_prefix('@') else {
                return Err(CliError::InvalidArgument(
                    "private key passphrase must be provided as --private-key-passphrase @path or entered interactively with --private-key-passphrase".to_string(),
                ));
            };
            validate_file_path(path)?;
            let mut value = Zeroizing::new(fs::read_to_string(path).map_err(|_| {
                CliError::FileReadError(format!(
                    "unable to read private key passphrase file `{path}`. Please check that the file exists and is readable"
                ))
            })?);
            trim_line_end(&mut value);
            validate_passphrase_len(&value)?;
            Ok(Some(value))
        },
    }
}

fn trim_line_end(value: &mut String) {
    while matches!(value.chars().last(), Some('\n' | '\r')) {
        value.pop();
    }
}

fn validate_passphrase_len(value: &str) -> Result<(), CliError> {
    if value.len() <= PASSPHRASE_MAX_LEN {
        Ok(())
    } else {
        Err(CliError::InvalidArgument(format!(
            "private key passphrase must not exceed {PASSPHRASE_MAX_LEN} characters; got {}",
            value.len()
        )))
    }
}

#[derive(Debug, Serialize)]
struct ResourceMetadataOutput(ResourceResponse);

impl Formatter for ResourceMetadataOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let resource = &self.0;
        Ok([
            format!("{:<20}{}", "uri:", resource.uri),
            format!("{:<20}{}", "provider_name:", resource.provider_name),
            format!("{:<20}{}", "repository_name:", resource.repository_name),
            format!("{:<20}{}", "resource_type:", resource.resource_type),
            format!("{:<20}{}", "resource_name:", resource.resource_name),
            format!("{:<20}{}", "policy_id:", resource.policy_id),
            format!("{:<20}{}", "content_type:", resource.content_type.as_deref().unwrap_or_default()),
            format!("{:<20}{}", "export_mode:", resource.export_mode),
            format!("{:<20}{}", "created_at:", resource.created_at),
            format!("{:<20}{}", "updated_at:", resource.updated_at),
            format!("{:<20}{}", "additional_info:", resource.additional_info.as_deref().unwrap_or_default()),
        ]
        .join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct ResourceContentOutput {
    uri: String,
    #[serde(skip_serializing)]
    content: Vec<u8>,
    content_type: Option<String>,
    export_mode: String,
}

impl Formatter for ResourceContentOutput {
    fn render_text(&self) -> Result<String, CliError> {
        String::from_utf8(self.content.clone())
            .or_else(|err| Ok(base64::engine::general_purpose::STANDARD.encode(err.into_bytes())))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&json!({
            "uri": self.uri,
            "content": base64::engine::general_purpose::STANDARD.encode(&self.content),
            "content_type": self.content_type,
            "export_mode": self.export_mode,
        }))
        .map_err(|_| CliError::InternalFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_path_args() -> PathArgs {
        PathArgs { uri: "vault/default/secret/demo".to_string() }
    }

    #[test]
    fn build_path_and_resource_uri_match_command_arguments() {
        let path_args = base_path_args();
        let path = build_path(&path_args);
        assert_eq!(path.provider_name, "vault");
        assert_eq!(resource_uri(&path), "vault/default/secret/demo");
    }

    #[test]
    fn update_allows_missing_policy_id() {
        // `--policy-id` is optional on update: omitting it keeps the existing binding.
        let command = UpdateArgs::augment_args(clap::Command::new("update"));
        let matches = command
            .try_get_matches_from(["update", "--uri", "vault/default/secret/demo", "--export-mode", "jwe"])
            .expect("update should succeed without --policy-id");
        assert!(
            matches.get_one::<String>("policy_id").is_none(),
            "policy_id should be absent when --policy-id is omitted"
        );
    }

    #[test]
    fn create_and_update_accept_optional_content() {
        let command = CreateArgs::augment_args(clap::Command::new("create"));
        let matches = command
            .try_get_matches_from([
                "create",
                "--uri",
                "hsm/default/key/demo",
                "--policy-id",
                "policy-1",
                "--content",
                "QUJD",
                "--content-type",
                "binary",
            ])
            .expect("create should succeed with --content");
        assert_eq!(matches.get_one::<String>("content").map(String::as_str), Some("QUJD"));

        let command = CreateArgs::augment_args(clap::Command::new("create"));
        let matches = command
            .try_get_matches_from(["create", "--uri", "hsm/default/key/demo", "--policy-id", "policy-1"])
            .expect("create should succeed without --content");
        assert!(matches.get_one::<String>("content").is_none(), "content should be absent when --content is omitted");

        let command = UpdateArgs::augment_args(clap::Command::new("update"));
        let matches = command
            .try_get_matches_from(["update", "--uri", "hsm/default/key/demo", "--content", "QUJD"])
            .expect("update should succeed with --content");
        assert_eq!(matches.get_one::<String>("content").map(String::as_str), Some("QUJD"));
    }

    #[test]
    fn normalize_base64_content_passes_through_valid_base64() {
        assert_eq!(normalize_base64_content("QUJD").expect("inline base64"), "QUJD");
        assert_eq!(normalize_base64_content("  QUJDRA==  ").expect("inline base64 with padding"), "QUJDRA==");
    }

    #[test]
    fn normalize_base64_content_encodes_raw_input() {
        let encoded = normalize_base64_content("hello vault").expect("raw inline value");
        assert_eq!(encoded, base64::engine::general_purpose::STANDARD.encode(b"hello vault"));
    }

    #[test]
    fn normalize_base64_content_reads_files() {
        let dir = std::env::temp_dir();
        let suffix = std::process::id();

        let b64_path = dir.join(format!("tools-res-content-b64-{}.txt", suffix));
        std::fs::write(&b64_path, "QUJDRA==\n").expect("write base64 file");
        assert_eq!(normalize_base64_content(&format!("@{}", b64_path.display())).expect("base64 file"), "QUJDRA==");
        let _ = std::fs::remove_file(&b64_path);

        let raw_path = dir.join(format!("tools-res-content-raw-{}.txt", suffix));
        std::fs::write(&raw_path, "raw key material").expect("write raw file");
        assert_eq!(
            normalize_base64_content(&format!("@{}", raw_path.display())).expect("raw file"),
            base64::engine::general_purpose::STANDARD.encode(b"raw key material")
        );
        let _ = std::fs::remove_file(&raw_path);

        let bin_path = dir.join(format!("tools-res-content-bin-{}.bin", suffix));
        std::fs::write(&bin_path, [0u8, 159, 146, 150]).expect("write binary file");
        assert_eq!(
            normalize_base64_content(&format!("@{}", bin_path.display())).expect("binary file"),
            base64::engine::general_purpose::STANDARD.encode([0u8, 159, 146, 150])
        );
        let _ = std::fs::remove_file(&bin_path);
    }

    #[test]
    fn normalize_base64_content_rejects_empty_input() {
        let err = normalize_base64_content("   ").expect_err("blank inline value should fail");
        assert!(err.to_string().contains("content must not be empty"));

        let dir = std::env::temp_dir();
        let empty_path = dir.join(format!("tools-res-content-empty-{}.txt", std::process::id()));
        std::fs::write(&empty_path, "  \n").expect("write empty file");
        let err = normalize_base64_content(&format!("@{}", empty_path.display())).expect_err("empty file should fail");
        assert!(err.to_string().contains("content must not be empty"));
        let _ = std::fs::remove_file(&empty_path);
    }

    #[test]
    fn normalize_base64_content_reports_missing_file() {
        let err = normalize_base64_content("@/nonexistent/tools-res-content-missing.txt")
            .expect_err("missing file should fail");
        assert!(err.to_string().contains("unable to read file"));
    }

    #[test]
    fn validate_resource_uri_requires_four_valid_segments() {
        assert_eq!(validate_resource_uri("vault/default/secret/demo").expect("valid uri"), "vault/default/secret/demo");

        let err = validate_resource_uri("vault/default/secret").expect_err("short uri should fail");
        assert!(err.to_string().contains("provider/repository/type/name"));

        let err = validate_resource_uri("vault/default/invalid/demo").expect_err("invalid type should fail");
        assert!(err.to_string().contains("resource type must be one of"));

        let err = validate_resource_uri("vault/default/secret/demo?debug=true").expect_err("query string should fail");
        assert!(err.to_string().contains("resource path segment"));
    }

    // Cover every resource URI segment at max-1, normal, max, and max+1.
    #[test]
    fn validate_resource_uri_segment_length_matrix() {
        for length in [RESOURCE_SEGMENT_MAX_LEN - 1, RESOURCE_SEGMENT_MAX_LEN] {
            let segment = "x".repeat(length);
            let uri = format!("{segment}/repo/secret/name");
            assert!(validate_resource_uri(&uri).is_ok());
        }
        assert!(validate_resource_uri("v/r/secret/name").is_ok());
        let too_long = "x".repeat(RESOURCE_SEGMENT_MAX_LEN + 1);
        assert!(validate_resource_uri(&format!("{too_long}/repo/secret/name")).is_err());
    }

    // Check additional-info and passphrase boundaries used by resource commands.
    #[test]
    fn validate_resource_option_length_matrix() {
        for length in [ADDITIONAL_INFO_MAX_LEN - 1, ADDITIONAL_INFO_MAX_LEN] {
            assert!(validate_trimmed_string_max_len(&"a".repeat(length), ADDITIONAL_INFO_MAX_LEN, "additional-info")
                .is_ok());
        }
        assert!(validate_trimmed_string_max_len(
            &"a".repeat(ADDITIONAL_INFO_MAX_LEN + 1),
            ADDITIONAL_INFO_MAX_LEN,
            "additional-info"
        )
        .is_err());
        assert!(validate_passphrase_len(&"p".repeat(PASSPHRASE_MAX_LEN - 1)).is_ok());
        assert!(validate_passphrase_len(&"p".repeat(PASSPHRASE_MAX_LEN)).is_ok());
        assert!(validate_passphrase_len(&"p".repeat(PASSPHRASE_MAX_LEN + 1)).is_err());
    }

    #[test]
    fn decode_resource_jwe_requires_base64_utf8() {
        let jwe = "header.encrypted_key.iv.ciphertext.tag";
        let encoded = base64::engine::general_purpose::STANDARD.encode(jwe);
        assert_eq!(decode_resource_jwe(&encoded).expect("decode"), jwe);

        let err = decode_resource_jwe("not-base64").expect_err("invalid content should fail");
        assert!(err.to_string().contains("not valid Base64"));
    }

    #[test]
    fn resource_content_output_text_falls_back_to_base64_for_binary() {
        let output = ResourceContentOutput {
            uri: "vault/default/secret/demo".to_string(),
            content: vec![0, 159, 146, 150],
            content_type: Some("binary".to_string()),
            export_mode: "jwe".to_string(),
        };
        assert_eq!(
            output.render_text().expect("render text"),
            base64::engine::general_purpose::STANDARD.encode([0, 159, 146, 150])
        );
    }
}

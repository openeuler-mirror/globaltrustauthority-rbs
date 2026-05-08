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

use crate::common::formatter::Formatter;
use crate::common::utils::read_path_file;
use crate::common::validate::{validate_max_len, validate_not_empty};
use crate::common::DEFAULT_PAGE_LIMIT;
use crate::common::ROLE_ARRAY;
use crate::common::ROLE_USER;
use crate::common::{JWT, USERNAME_MAX_LEN};
use crate::config::GlobalOptions;
use crate::error::CliError;
use clap::ArgGroup;
use clap::{Args, Subcommand};
use rbs_admin_client::{AdminClient, CreateUserRequest, ListUsersParams, UpdateUserRequest, User, UserClient, UserListResponse, UserService};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;

#[derive(Args, Debug, Clone)]
pub struct UserCli {
    #[command(subcommand)]
    pub command: UserCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum UserCommand {
    List(ListArgs),
    Get(GetArgs),
    #[command(alias = "register")]
    Create(CreateArgs),
    Update(UpdateArgs),
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[arg(long, default_value_t = DEFAULT_PAGE_LIMIT, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub limit: u64,

    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u32).range(0..=1000000))]
    pub offset: u64,
}

#[derive(Args, Debug, Clone)]
pub struct GetArgs {
    #[arg(value_parser = validate_username)]
    pub username: String,
}

#[derive(Args, Debug, Clone)]
pub struct DeleteArgs {
    #[arg(value_parser = validate_username)]
    pub username: String,
}

#[derive(Args, Debug, Clone)]
#[command(
    group(
        ArgGroup::new("input")
        .args(["public_key", "jwk"])
        .required(true)
        .multiple(false)
    )
)]
pub struct CreateArgs {
    #[arg(long, value_parser = validate_username)]
    pub username: String,

    #[arg(long, default_value = ROLE_USER, value_parser = ROLE_ARRAY)]
    pub role: Option<String>,

    #[arg(long)]
    pub enabled: Option<bool>,

    #[arg(long, value_parser = read_path_file, help = "PEM public key or @file path")]
    pub public_key: Option<String>,

    #[arg(long, value_parser = read_path_file, help = "JWK JSON or @file path")]
    pub jwk: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(
    group(
        ArgGroup::new("input")
        .args(["public_key", "jwk"])
        .multiple(false)
    )
)]
pub struct UpdateArgs {
    #[arg(value_parser = validate_username)]
    pub username: String,

    #[arg(long, value_parser = ROLE_ARRAY)]
    pub role: Option<String>,

    #[arg(long)]
    pub enabled: Option<bool>,

    #[arg(long, value_parser = read_path_file, help = "PEM public key or @file path")]
    pub public_key: Option<String>,

    #[arg(long, value_parser = read_path_file, help = "JWK JSON or @file path")]
    pub jwk: Option<String>,
}

pub fn run(cli: &UserCli, global: &GlobalOptions) -> Result<Box<dyn Formatter>, CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|err| CliError::Message(format!("failed to create async runtime: {err}")))?;
    let token = global
        .token
        .as_deref()
        .ok_or_else(|| CliError::InvalidArgument("missing required bearer token".to_string()))?;
    let service = UserClient::new(AdminClient::new(&global.base_url, token, &global.cert)?);
    runtime.block_on(execute_user_command(cli, &service))
}

async fn execute_user_command(cli: &UserCli, service: &UserClient) -> Result<Box<dyn Formatter>, CliError> {
    match &cli.command {
        UserCommand::List(args) => {
            let resp = service.list(&ListUsersParams { limit: args.limit, offset: args.offset }).await?;
            Ok(Box::new(UserListOutput(resp)))
        }
        UserCommand::Get(args) => {
            let resp = service.get(&args.username).await?;
            Ok(Box::new(UserOutput(resp)))
        }
        UserCommand::Create(args) => {
            let resp = service
                .create(&CreateUserRequest {
                    username: args.username.clone(),
                    role: args.role.clone(),
                    enabled: args.enabled,
                    auth_type: JWT.to_string(),
                    public_key: args.public_key.clone(),
                    jwk: parse_jwk_input(args.jwk.as_deref())?,
                })
                .await?;
            Ok(Box::new(UserOutput(resp)))
        }
        UserCommand::Update(args) => {
            validate_update_args(args)?;
            let resp = service
                .update(
                    &args.username,
                    &UpdateUserRequest {
                        role: args.role.clone(),
                        enabled: args.enabled,
                        auth_type: Some(JWT.to_string()),
                        public_key: args.public_key.clone(),
                        jwk: parse_jwk_input(args.jwk.as_deref())?,
                    },
                )
                .await?;
            Ok(Box::new(UserOutput(resp)))
        }
        UserCommand::Delete(args) => {
            service.delete(&args.username).await?;
            Ok(Box::new(DeleteUserOutput { username: args.username.clone() }))
        }
    }
}

fn validate_update_args(args: &UpdateArgs) -> Result<(), CliError> {
    if args.role.is_none() && args.enabled.is_none() && args.public_key.is_none() && args.jwk.is_none() {
        return Err(CliError::InvalidArgument(
            "at least one updatable field must be set: role, enabled, public_key, jwk".to_string(),
        ));
    }
    Ok(())
}

fn parse_jwk_input(input: Option<&str>) -> Result<Option<Value>, CliError> {
    let Some(input) = input else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(input)
        .map_err(|err| CliError::InvalidArgument(format!("invalid JWK JSON: {err}")))?;
    if !value.is_object() {
        return Err(CliError::InvalidArgument("jwk must be a JSON object".to_string()));
    }
    Ok(Some(value))
}

#[derive(Debug, Serialize)]
struct UserOutput(User);

impl Formatter for UserOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let user = &self.0;
        Ok([
            format!("id: {}", user.id),
            format!("username: {}", user.username),
            format!("role: {}", user.role),
            format!("enabled: {}", user.enabled),
            format!("created_at: {}", user.created_at),
            format!("updated_at: {}", user.updated_at),
        ]
        .join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct UserListOutput(UserListResponse);

impl Formatter for UserListOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let resp = &self.0;
        let mut lines = vec![
            format!("total_count: {}", resp.total_count),
            format!("limit: {}", resp.limit),
            format!("offset: {}", resp.offset),
            "items:".to_string(),
        ];

        if resp.items.is_empty() {
            lines.push("  <empty>".to_string());
        } else {
            for user in &resp.items {
                lines.push(format!("  - {} role={} enabled={}", user.username, user.role, user.enabled));
            }
        }

        Ok(lines.join("\n"))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(&self.0).map_err(|_| CliError::InternalFormat)
    }
}

#[derive(Debug, Serialize)]
struct DeleteUserOutput {
    username: String,
}

impl Formatter for DeleteUserOutput {
    fn render_text(&self) -> Result<String, CliError> {
        Ok(format!("deleted user: {}", self.username))
    }

    fn render_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(self).map_err(|_| CliError::InternalFormat)
    }
}

pub fn validate_username(input: &str) -> Result<String, CliError> {
    validate_not_empty(input)?;
    validate_max_len(input, USERNAME_MAX_LEN)?;
    let username_re = Regex::new(r"^[a-zA-Z0-9_-]+$").map_err(|_| CliError::InternalFormat)?;
    if !username_re.is_match(input) {
        return Err(CliError::InvalidArgument(
            "username must match [a-zA-Z0-9_-]+".to_string(),
        ));
    }
    Ok(input.to_string())
}

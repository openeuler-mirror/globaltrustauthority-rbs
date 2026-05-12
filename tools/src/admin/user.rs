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

use crate::common::clap::Page;
use crate::common::formatter::Formatter;
use crate::common::utils::read_path_file;
use crate::common::validate::validate_pubkey_file;
use crate::common::validate::{validate_max_len, validate_not_empty};
use crate::common::ROLE_ARRAY;
use crate::common::ROLE_USER;
use crate::common::{JWT, USERNAME_MAX_LEN};
use crate::config::GlobalOptions;
use crate::error::CliError;
use clap::ArgGroup;
use clap::{Args, Subcommand};
use rbs_admin_client::{
    AdminClient, CreateUserRequest, ListUsersParams, RbsAdminClientError, UpdateUserRequest, User, UserClient,
    UserListResponse, UserService,
};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use tabled::settings::Style;
use tabled::Table;

#[derive(Args, Debug, Clone)]
#[command(about = "Manage RBS users")]
pub struct UserCli {
    #[command(subcommand)]
    pub command: UserCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum UserCommand {
    #[command(about = "List users with pagination")]
    List(ListArgs),
    #[command(about = "Get one user by username")]
    Get(GetArgs),
    #[command(about = "Create a user with a public key or JWK")]
    Create(CreateArgs),
    #[command(about = "Update a user's role, enabled flag, or key material")]
    Update(UpdateArgs),
    #[command(about = "Delete a user by username")]
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[command(flatten)]
    pub page: Page,
}

#[derive(Args, Debug, Clone)]
pub struct GetArgs {
    #[arg(short = 'u', long, value_parser = validate_username, help = "Username to query")]
    pub username: String,
}

#[derive(Args, Debug, Clone)]
pub struct DeleteArgs {
    #[arg(short = 'u', long, help = "Username to delete")]
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
    #[arg(long, value_parser = validate_username, help = "Username to create")]
    pub username: String,

    #[arg(long, default_value = ROLE_USER, value_parser = ROLE_ARRAY, help = "User role")]
    pub role: Option<String>,

    #[arg(long, help = "Whether the user is enabled after creation")]
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
    #[arg(short = 'u', long, help = "Username to update")]
    #[arg(value_parser = validate_username)]
    pub username: String,

    #[arg(long, value_parser = ROLE_ARRAY, help = "New user role")]
    pub role: Option<String>,

    #[arg(long, help = "Whether the user is enabled")]
    pub enabled: Option<bool>,

    #[arg(long, value_parser = validate_pubkey_file, help = "PEM public key or @file path")]
    pub public_key: Option<String>,

    #[arg(long, value_parser = validate_pubkey_file, help = "JWK JSON or @file path")]
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
            let resp = service.list(&ListUsersParams { limit: args.page.limit, offset: args.page.offset }).await?;
            Ok(Box::new(UserListOutput(resp)))
        },
        UserCommand::Get(args) => {
            let resp = service.get(&args.username).await?;
            Ok(Box::new(UserOutput(resp)))
        },
        UserCommand::Create(args) => {
            let (pub_key, jwk) = read_pubkey_and_jwk(&args.public_key, &args.jwk)?;
            let resp = service
                .create(&CreateUserRequest {
                    username: args.username.clone(),
                    role: args.role.clone(),
                    enabled: args.enabled,
                    auth_type: JWT.to_string(),
                    public_key: pub_key.clone(),
                    jwk: jwk.clone(),
                })
                .await?;
            Ok(Box::new(UserOutput(resp)))
        },
        UserCommand::Update(args) => {
            validate_update_args(args)?;
            let (pub_key, jwk) = read_pubkey_and_jwk(&args.public_key, &args.jwk)?;
            let resp = service
                .update(
                    &args.username,
                    &UpdateUserRequest {
                        role: args.role.clone(),
                        enabled: args.enabled,
                        auth_type: Some(JWT.to_string()),
                        public_key: pub_key.clone(),
                        jwk: jwk.clone(),
                    },
                )
                .await?;
            Ok(Box::new(UserOutput(resp)))
        },
        UserCommand::Delete(args) => {
            match service.delete(&args.username).await {
                Ok(()) => {},
                Err(RbsAdminClientError::ClientError(message)) if message == "The requested item was not found." => {
                    return Err(CliError::Message(format!("Delete failed: user not found: {}", args.username)));
                },
                Err(err) => return Err(CliError::RequestError(err)),
            }
            Ok(Box::new(DeleteUserOutput { username: args.username.clone() }))
        },
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

fn read_pubkey_and_jwk(
    public_key: &Option<String>,
    jwk: &Option<String>,
) -> Result<(Option<String>, Option<Value>), CliError> {
    let pub_key = if let Some(public_key) = public_key { Some(read_path_file(public_key)?) } else { None };
    let jwk = if let Some(jwk) = jwk {
        let jwk_data = read_path_file(jwk)?;
        let jwk_value: Value = serde_json::from_str(jwk_data.as_str())
            .map_err(|err| CliError::InvalidArgument(format!("invalid JWK JSON: {err}")))?;
        Some(jwk_value)
    } else {
        None
    };
    Ok((pub_key, jwk))
}

#[derive(Debug, Serialize)]
struct UserOutput(User);

impl Formatter for UserOutput {
    fn render_text(&self) -> Result<String, CliError> {
        let user = &self.0;
        Ok([
            format!("{:<20}{}", "id:", user.id),
            format!("{:<20}{}", "username:", user.username),
            format!("{:<20}{}", "role:", user.role),
            format!("{:<20}{}", "enabled", user.enabled),
            format!("{:<20}{}", "created_at", user.created_at),
            format!("{:<20}{}", "updated_at", user.updated_at),
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

        if !resp.items.is_empty() {
            let table = Table::new(resp.items.iter()).with(Style::psql()).to_string();
            lines.extend(table.lines().map(|line| line.to_string()));
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
        Ok(format!("Delete succeeded: user removed: {}", self.username))
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
        return Err(CliError::InvalidArgument("username must contain only letters, digits, '_' or '-'".to_string()));
    }
    Ok(input.to_string())
}

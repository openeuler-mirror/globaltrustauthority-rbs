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

//! RBS binary: load config, init logging (infra), then run REST server.

use std::path::Path;

use anyhow::Context;
use clap::Parser;
use rbs::load_config;
use rbs_core::init_logging;
use rbs_core::init_database;
use rbs_core::rdb::execute_sql_file_path;
use rbs_core::auth::LockoutTracker;

/// RBS (Resource Broker Service) binary.
#[derive(Parser)]
#[command(name = "rbs")]
struct Cli {
    /// Path to config file (default: /etc/rbs/rbs.yaml, or `RBS_CONFIG` env).
    #[arg(short, long, env = "RBS_CONFIG", default_value = "/etc/rbs/rbs.yaml")]
    config: String,
}

/// Adapter: delegates [`rbs_core::auth::UserKeyProvider`] to `core.admin()`.
struct CoreKeyProvider(std::sync::Arc<rbs_core::RbsCore>);

impl std::fmt::Debug for CoreKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CoreKeyProvider").finish()
    }
}

#[async_trait::async_trait]
impl rbs_core::auth::UserKeyProvider for CoreKeyProvider {
    async fn get_public_key(&self, sub: &str) -> std::result::Result<String, rbs_core::auth::AuthError> {
        self.0.admin().get_public_key(sub).await
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_path = &cli.config;
    let config = load_config(config_path).with_context(|| format!("load config from {}", config_path))?;
    config.validate();

    init_logging(&config.logging).context("init logging")?;
    log::info!("RBS config loaded from {}", Path::new(&config_path).display());

    if let Some(ref database) = config.storage {
        init_database(database).await.context("init database")?;
        log::info!("Database initialized successfully");

        let db_conn = rbs_core::rdb::get_db_connection()?;
        execute_sql_file_path(&*db_conn, &database.sql_file_path).await.map_err(|e| anyhow::anyhow!("execute sql: {}", e))?;
        log::info!("init table executed successfully");
    }

    #[allow(unused_variables)]
    let core_config = rbs_core::CoreConfig {
        logging: config.logging.clone(),
        attestation: config.attestation.clone(),
        auth: config.auth.clone(),
        admin: config.admin.clone(),
        resource: config.resource.clone(),
    };
    let core = std::sync::Arc::new(rbs_core::RbsCoreBuilder::new(core_config).build());

    // Bootstrap the pre-configured administrator if no users exist
    match core.admin().bootstrap_admin().await {
        Ok(()) => log::info!("Admin bootstrap check completed"),
        Err(rbs_core::RbsError::ResourceConflict) => {
            log::info!("Admin bootstrap skipped: administrator already exists (concurrent bootstrap)");
        }
        Err(e) => anyhow::bail!("bootstrap admin user: {}", e),
    }

    #[cfg(feature = "rest")]
    {
        let rest_config =
            config.rest.clone().ok_or_else(|| anyhow::anyhow!("config.rest is required when built with `rest`"))?;
        let key_provider: std::sync::Arc<dyn rbs_core::auth::UserKeyProvider> =
            std::sync::Arc::new(CoreKeyProvider(core.clone()));
        let lockout_tracker = LockoutTracker::new_shared();
        let server = rbs_rest::Server::new(core.clone(), rest_config.clone(), config.auth.clone(), key_provider, lockout_tracker);
        let bound = server.bind().await.context("bind REST server")?;
        log::info!("RBS REST server starting on {}", rest_config.listen_addr);
        bound.run().await.context("RBS REST server")?;
    }

    #[cfg(not(feature = "rest"))]
    {
        log::info!("RBS (Resource Broker Service) - rest feature disabled");
    }

    Ok(())
}

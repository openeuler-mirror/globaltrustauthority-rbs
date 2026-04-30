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

/// RBS (Resource Broker Service) binary.
#[derive(Parser)]
#[command(name = "rbs")]
struct Cli {
    /// Path to config file (default: rbs.yaml, or `RBS_CONFIG` env).
    #[arg(short, long, env = "RBS_CONFIG", default_value = "rbs.yaml")]
    config: String,
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
    };
    let core = std::sync::Arc::new(rbs_core::RbsCoreBuilder::new(core_config).build());

    #[cfg(feature = "rest")]
    {
        let rest_config =
            config.rest.clone().ok_or_else(|| anyhow::anyhow!("config.rest is required when built with `rest`"))?;
        let server = rbs_rest::Server::new(core.clone(), rest_config.clone(), config.auth.clone());
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

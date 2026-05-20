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

use std::sync::Once;
use tracing::Level;
use tracing_subscriber::EnvFilter;

static INIT_LOGGING: Once = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevelSource {
    Default,
    Verbose,
    Quiet,
    RustLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogInitResult {
    pub level: Level,
    pub source: LogLevelSource,
}

pub fn init_logging(verbose: bool, quiet: bool) -> LogInitResult {
    let (level, source) = if quiet {
        (Level::ERROR, LogLevelSource::Quiet)
    } else if verbose {
        (Level::INFO, LogLevelSource::Verbose)
    } else if std::env::var_os("RUST_LOG").is_some() {
        (Level::WARN, LogLevelSource::RustLog)
    } else {
        (Level::WARN, LogLevelSource::Default)
    };

    INIT_LOGGING.call_once(|| {
        let filter = if matches!(source, LogLevelSource::RustLog) {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"))
        } else {
            EnvFilter::new(format!(
                "warn,rbs_cli={level},rbc={level},rbs_admin_client={level}",
                level = level.as_str().to_lowercase()
            ))
        };

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
    });

    LogInitResult { level, source }
}

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

//! Server: bind and run actix-web `HttpServer`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use actix_web::{web, App, HttpServer};
use anyhow::{bail, Context};
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use rbs_api_types::config::RestConfig;
use rbs_core::RbsCore;
use socket2::{Domain, Socket, Type};

#[cfg(feature = "per-ip-rate-limit")]
use super::rate_limit;
use crate::routes::{config as routes_config, not_found, version};
use actix_web::middleware::from_fn;
use rbs_api_types::ErrorBody;

/// Build OpenSSL TLS acceptor from certificate and private key file paths (PEM format by default).
/// Errors are sanitized (no cert/key paths in the chain) so logs never expose file paths.
fn build_ssl_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<SslAcceptorBuilder> {
    let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls()).context("create SslAcceptor builder")?;
    builder
        .set_certificate_chain_file(cert_path)
        .map_err(|_e| anyhow::anyhow!("rest.https.cert_file not valid or not readable (path redacted)"))?;
    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|_e| anyhow::anyhow!("rest.https.key_file not valid or not readable (path redacted)"))?;
    Ok(builder)
}

/// Default maximum URI length (path + query) in bytes; used when not overridden by `app_data`.
const DEFAULT_MAX_URI_LEN: usize = 2048;

/// Maps config `request_timeout_secs` (0 = no limit) to `Duration` for actix.
fn request_timeout_duration(secs: u32) -> Duration {
    if secs == 0 {
        Duration::MAX
    } else {
        Duration::from_secs(secs.into())
    }
}

/// HTTP server holding `Arc<RbsCore>` and its own REST config (passed from main).
pub struct Server {
    core: Arc<RbsCore>,
    rest_config: RestConfig,
}

impl Server {
    #[must_use]
    pub fn new(core: Arc<RbsCore>, rest_config: RestConfig) -> Self {
        Self { core, rest_config }
    }

    /// Binds to the configured listen address with the configured backlog; then call `.run().await?`.
    ///
    /// # Errors
    /// Fails if HTTPS is enabled but cert/key paths are empty or files are not readable; if
    /// `listen_addr` is invalid; or if socket create, bind, listen, or `set_nonblocking` fails.
    pub async fn bind(self) -> anyhow::Result<BoundServer> {
        let rest = &self.rest_config;
        if rest.https.enabled {
            if rest.https.cert_file.trim().is_empty() {
                bail!("rest.https.enabled is true but rest.https.cert_file is empty");
            }
            if rest.https.key_file.get().trim().is_empty() {
                bail!("rest.https.enabled is true but rest.https.key_file is empty");
            }
            // Validate cert and key files exist and are readable so we fail at bind, not at run.
            // Use map_err so the io::Error (which may contain the path) is not in the chain.
            let _ = std::fs::File::open(rest.https.cert_file.trim())
                .map_err(|_e| anyhow::anyhow!("rest.https.cert_file not readable (path redacted)"))?;
            let _ = std::fs::File::open(rest.https.key_file.get().trim())
                .map_err(|_e| anyhow::anyhow!("rest.https.key_file not readable (path redacted)"))?;
        }
        let addr = rest.listen_addr.as_str();
        let socket_addr: SocketAddr = addr.parse().with_context(|| format!("invalid listen address: {}", addr))?;
        let backlog = rest.listen_backlog as i32;

        let socket = Socket::new(Domain::for_address(socket_addr), Type::STREAM, None)
            .with_context(|| format!("create socket for {}", addr))?;
        socket.bind(&socket_addr.into()).with_context(|| format!("bind to {}", addr))?;
        socket.listen(backlog).with_context(|| format!("listen with backlog {} on {}", backlog, addr))?;
        socket.set_nonblocking(true).with_context(|| "set nonblocking")?;
        let std_listener: std::net::TcpListener = socket.into();

        Ok(BoundServer { std_listener, core: self.core, rest_config: self.rest_config })
    }
}

/// Server after bind; call `.run().await?` to serve.
#[derive(Debug)]
pub struct BoundServer {
    std_listener: std::net::TcpListener,
    core: Arc<RbsCore>,
    rest_config: RestConfig,
}

impl BoundServer {
    /// Starts the HTTP server: configures app factory, applies timeouts, listens (TLS or plain), then runs.
    ///
    /// # Errors
    /// Fails if `local_addr()` fails, if TLS acceptor build fails when HTTPS is enabled, or if
    /// actix-web `listen` / `listen_openssl` or `run().await` returns an error.
    pub async fn run(self) -> anyhow::Result<()> {
        let rest = &self.rest_config;
        let addr = self.std_listener.local_addr().context("local_addr")?;
        let scheme = if rest.https.enabled { "https" } else { "http" };
        log::info!("RBS REST server listening on {}://{}", scheme, addr);

        let body_limit = rest.body_limit_bytes.min(usize::MAX as u64) as usize;
        let workers = usize::try_from(rest.workers).unwrap_or(1).max(1);
        let shutdown_timeout_secs = rest.shutdown_timeout_secs;
        let request_timeout_secs = rest.request_timeout_secs;
        let https_enabled = rest.https.enabled;
        let cert_file = rest.https.cert_file.clone();
        let key_file = rest.https.key_file.get().clone();
        let core = self.core;
        let std_listener = self.std_listener;

        #[cfg(feature = "per-ip-rate-limit")]
        let limiter_opt = if rest.rate_limit.enabled {
            Some(rate_limit::build_limiter(rest.rate_limit.requests_per_sec, rest.rate_limit.burst))
        } else {
            None
        };
        #[cfg(feature = "per-ip-rate-limit")]
        let trusted_proxy_set = rate_limit::TrustedProxySet::from_addrs(&rest.trusted_proxy.addrs);

        #[cfg(feature = "per-ip-rate-limit")]
        if let Some(ref lim) = limiter_opt {
            let lim = Arc::clone(lim);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    lim.retain_recent();
                    lim.shrink_to_fit();
                }
            });
        }

        let max_uri_len = DEFAULT_MAX_URI_LEN as u32;

        let app_factory = move || {
            let app = App::new()
                .app_data(web::Data::new(core.clone()))
                .app_data(web::PayloadConfig::new(body_limit))
                .app_data(web::Data::new(max_uri_len as usize))
                .wrap(from_fn(uri_length_guard_middleware));
            #[cfg(feature = "per-ip-rate-limit")]
            let app = {
                let app = app.app_data(web::Data::new(trusted_proxy_set.clone()));
                let app = if let Some(ref lim) = limiter_opt {
                    app.app_data(web::Data::new(Arc::clone(lim)))
                } else {
                    app
                };
                app.wrap(from_fn(rate_limit::per_ip_rate_limit_middleware))
            };
            app.service(
                web::scope("/rbs")
                    .route("/version", web::get().to(version::version))
                    .service(web::scope("/v0").configure(routes_config))
                    .default_service(web::to(not_found)),
            )
        };

        let request_timeout = request_timeout_duration(request_timeout_secs);

        let builder = HttpServer::new(app_factory)
            .workers(workers)
            .shutdown_timeout(shutdown_timeout_secs.into())
            .client_request_timeout(request_timeout);

        let server = if https_enabled {
            let acceptor = build_ssl_acceptor(cert_file.trim(), key_file.trim())?;
            builder.listen_openssl(std_listener, acceptor).context("actix_web listen_openssl")?
        } else {
            builder.listen(std_listener).context("actix_web listen")?
        };

        server.run().await.context("RBS REST server error")?;
        Ok(())
    }
}

/// Rejects requests whose path + query string exceeds configured max with 414 URI Too Long.
pub async fn uri_length_guard_middleware<B>(
    req: actix_web::dev::ServiceRequest,
    next: actix_web::middleware::Next<B>,
) -> Result<actix_web::dev::ServiceResponse<actix_web::body::BoxBody>, actix_web::Error>
where
    B: actix_web::body::MessageBody + 'static,
    B::Error: Into<actix_web::Error>,
{
    let max = req.app_data::<web::Data<usize>>().map_or(DEFAULT_MAX_URI_LEN, |d| *d.as_ref());
    let total = req.path().len() + req.query_string().len();
    if total > max {
        let res = req.into_response(actix_web::HttpResponse::UriTooLong().json(ErrorBody {
            error: "URI Too Long".to_string(),
        }));
        return Ok(res.map_body(|_, b| actix_web::body::BoxBody::new(b)));
    }
    let res = next.call(req).await?;
    Ok(res.map_body(|_, b| actix_web::body::BoxBody::new(b)))
}

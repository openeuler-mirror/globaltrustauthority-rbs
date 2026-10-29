/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Tests for the serving loop (`BoundServer::run`): plain HTTP, the dedicated
//! health listener, and the HTTPS listener path. Each test binds ephemeral
//! loopback ports, drives a real request over TCP, and aborts the server task.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rbs_api_types::config::{
    AttestTokenVerificationConfig, AuthConfig, BearerTokenVerificationConfig, HealthConfig, RestConfig, Sensitive,
};
use rbs_core::auth::{AuthError, LockoutTracker, UserAuthInfo, UserAuthProvider};
use rbs_core::RbsCore;
use rbs_rest::server::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn stub_auth_provider() -> Arc<dyn UserAuthProvider> {
    #[derive(Debug, Clone, Default)]
    struct Stub;

    #[async_trait]
    impl UserAuthProvider for Stub {
        async fn get_user_auth(&self, _sub: &str) -> Result<UserAuthInfo, AuthError> {
            Err(AuthError::TokenInvalid { reason: "stub".to_string() })
        }
    }

    Arc::new(Stub)
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral listener");
    listener.local_addr().expect("local addr").port()
}

fn server_with(rest: RestConfig, health: Option<HealthConfig>, auth: AuthConfig) -> Server {
    Server::new(Arc::new(RbsCore::default()), rest, health, auth, stub_auth_provider(), LockoutTracker::new_shared())
}

/// Auth configuration with a readable AttestToken public key so the server's
/// per-worker `Authenticator::new` succeeds.
fn auth_config(dir: &tempfile::TempDir) -> AuthConfig {
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    let key_path = dir.path().join("attest_pub.pem");
    let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
    std::fs::write(&key_path, key.public_key_to_pem().expect("public pem")).expect("write pem");
    AuthConfig {
        attest_token: AttestTokenVerificationConfig {
            public_key_path: Some(key_path.to_string_lossy().to_string()),
            jwks_file: None,
            issuer: "test-issuer".to_string(),
            audience: Some("rbs".to_string()),
        },
        bearer_token: BearerTokenVerificationConfig { issuer: "test-issuer".to_string(), audience: "rbs".to_string() },
    }
}

async fn wait_until_listening(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start listening on port {port}");
}

async fn http_get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read response");
    String::from_utf8_lossy(&response).to_string()
}

#[actix_web::test]
async fn run_serves_version_over_plain_http() {
    let port = free_port();
    let mut rest = RestConfig::default();
    rest.listen_addr = format!("127.0.0.1:{port}");
    let dir = tempfile::tempdir().expect("tempdir");
    let server = server_with(rest, None, auth_config(&dir)).bind().await.expect("bind");
    let handle = tokio::spawn(server.run());

    wait_until_listening(port).await;
    let response = http_get(port, "/rbs/version").await;
    assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");

    handle.abort();
}

#[actix_web::test]
async fn run_serves_health_probes_on_dedicated_listener() {
    let rest_port = free_port();
    let health_port = free_port();
    let mut rest = RestConfig::default();
    rest.listen_addr = format!("127.0.0.1:{rest_port}");
    let health = HealthConfig { listen_addr: format!("127.0.0.1:{health_port}") };
    let dir = tempfile::tempdir().expect("tempdir");
    let server = server_with(rest, Some(health), auth_config(&dir)).bind().await.expect("bind");
    let handle = tokio::spawn(server.run());

    wait_until_listening(health_port).await;
    let livez = http_get(health_port, "/livez").await;
    assert!(livez.starts_with("HTTP/1.1 200"), "livez: {livez}");
    assert!(livez.contains("\"status\":\"ok\""), "livez body: {livez}");

    // The pool is not initialized in this test binary -> readiness reports 503.
    let readyz = http_get(health_port, "/readyz").await;
    assert!(readyz.starts_with("HTTP/1.1 503"), "readyz: {readyz}");
    assert!(readyz.contains("connection pool not initialized"), "readyz body: {readyz}");

    handle.abort();
}

#[actix_web::test]
async fn run_accepts_https_when_certificates_are_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");
    write_self_signed_cert(&cert_path, &key_path);

    let port = free_port();
    let mut rest = RestConfig::default();
    rest.listen_addr = format!("127.0.0.1:{port}");
    rest.https.enabled = true;
    rest.https.cert_file = cert_path.to_string_lossy().to_string();
    rest.https.key_file = Sensitive::new(key_path.to_string_lossy().to_string());

    let dir = tempfile::tempdir().expect("tempdir");
    let server = server_with(rest, None, auth_config(&dir)).bind().await.expect("bind");
    let handle = tokio::spawn(server.run());

    wait_until_listening(port).await;
    // A plain TCP connect proves the TLS listener is accepting connections.
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok());

    handle.abort();
}

/// With runtime rate limiting enabled the server builds a limiter, starts its
/// periodic housekeeping task, and throttles a per-IP bucket that is already
/// exhausted.
#[actix_web::test]
async fn run_with_rate_limit_enabled_throttles_requests() {
    let port = free_port();
    let mut rest = RestConfig::default();
    rest.listen_addr = format!("127.0.0.1:{port}");
    rest.rate_limit.enabled = true;
    rest.rate_limit.requests_per_sec = 1;
    rest.rate_limit.burst = Some(1);
    let dir = tempfile::tempdir().expect("tempdir");
    let server = server_with(rest, None, auth_config(&dir)).bind().await.expect("bind");
    let handle = tokio::spawn(server.run());

    wait_until_listening(port).await;
    // The first request spends the burst token, the immediate second one is
    // rejected by the per-IP limiter installed on the app factory.
    let first = http_get(port, "/rbs/version").await;
    assert!(first.starts_with("HTTP/1.1 200"), "first response: {first}");
    let second = http_get(port, "/rbs/version").await;
    assert!(second.starts_with("HTTP/1.1 429"), "second response must be throttled: {second}");
    assert!(second.contains("Too Many Requests"), "throttle body: {second}");

    handle.abort();
}

#[actix_web::test]
async fn bind_rejects_unreadable_https_files() {
    let port = free_port();
    let mut rest = RestConfig::default();
    rest.listen_addr = format!("127.0.0.1:{port}");
    rest.https.enabled = true;
    rest.https.cert_file = "/definitely/not/here/cert.pem".to_string();
    rest.https.key_file = Sensitive::new("/definitely/not/here/key.pem".to_string());

    let dir = tempfile::tempdir().expect("tempdir");
    let err = server_with(rest, None, auth_config(&dir)).bind().await.expect_err("unreadable cert must fail");
    assert!(format!("{err:#}").contains("cert_file not readable"), "error: {err:#}");
}

fn write_self_signed_cert(cert_path: &std::path::Path, key_path: &std::path::Path) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509};

    let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_text("CN", "localhost").expect("cn");
    let name = name.build();
    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    let serial = BigNum::from_u32(1).expect("serial").to_asn1_integer().expect("serial int");
    builder.set_serial_number(&serial).expect("serial");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&key).expect("pubkey");
    builder.set_not_before(&Asn1Time::days_from_now(0).expect("not before")).expect("not before");
    builder.set_not_after(&Asn1Time::days_from_now(1).expect("not after")).expect("not after");
    builder.sign(&key, MessageDigest::sha256()).expect("sign");
    let cert = builder.build();

    std::fs::write(cert_path, cert.to_pem().expect("cert pem")).expect("write cert");
    std::fs::write(key_path, key.private_key_to_pem_pkcs8().expect("key pem")).expect("write key");
}

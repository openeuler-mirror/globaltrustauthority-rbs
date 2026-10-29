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

//! Rate limit integration tests.

use rbs_rest::server::rate_limit::{build_limiter, TrustedProxySet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn trusted_proxy_set_parses_ipv4_ipv6_and_socket() {
    let t = TrustedProxySet::from_addrs(&[
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "10.0.0.5:8080".to_string(),
        "  ".to_string(),
        "not-an-ip".to_string(),
    ]);
    assert!(t.is_trusted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(t.is_trusted(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(t.is_trusted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    assert!(!t.is_trusted(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn keyed_limiter_second_request_same_ip_fails_when_burst_one() {
    let lim = build_limiter(1, Some(1));
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    assert!(lim.check_key(&ip).is_ok(), "first request should pass");
    assert!(lim.check_key(&ip).is_err(), "second immediate request should be rate limited");
}

// ===========================================================================
// Middleware behaviour (`per_ip_rate_limit_middleware`)
// ===========================================================================

mod middleware {
    use super::*;
    use actix_web::{middleware::from_fn, test, web, App, HttpResponse};
    use rbs_rest::server::rate_limit::{per_ip_rate_limit_middleware, KeyedLimiter};
    use std::sync::Arc;

    type Limiter = Arc<KeyedLimiter>;

    async fn ok_handler() -> HttpResponse {
        HttpResponse::Ok().body("ok")
    }

    async fn call_echo(
        app: &impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
            Error = actix_web::Error,
        >,
        req: actix_web::test::TestRequest,
    ) -> (actix_web::http::StatusCode, serde_json::Value) {
        let resp = test::call_service(app, req.to_request()).await;
        let status = resp.status();
        let body = test::read_body(resp).await;
        (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
    }

    /// With no limiter in `app_data` (runtime rate limiting disabled) every
    /// request reaches the inner service.
    #[actix_web::test]
    async fn passes_through_when_limiter_is_not_configured() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(TrustedProxySet::from_addrs(&[])))
                .wrap(from_fn(per_ip_rate_limit_middleware))
                .route("/echo", web::get().to(ok_handler)),
        )
        .await;

        for _ in 0..3 {
            let resp = test::call_service(
                &app,
                test::TestRequest::get().uri("/echo").peer_addr("192.0.2.10:5000".parse().unwrap()).to_request(),
            )
            .await;
            assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        }
    }

    /// A configured limiter rejects the request once the per-IP bucket is empty.
    #[actix_web::test]
    async fn returns_429_when_bucket_is_exhausted() {
        let limiter: Limiter = build_limiter(1, Some(1));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(limiter))
                .app_data(web::Data::new(TrustedProxySet::from_addrs(&[])))
                .wrap(from_fn(per_ip_rate_limit_middleware))
                .route("/echo", web::get().to(ok_handler)),
        )
        .await;

        let peer = "192.0.2.11:5000".parse().unwrap();
        let first = test::call_service(&app, test::TestRequest::get().uri("/echo").peer_addr(peer).to_request()).await;
        assert_eq!(first.status(), actix_web::http::StatusCode::OK);

        let second = test::call_service(&app, test::TestRequest::get().uri("/echo").peer_addr(peer).to_request()).await;
        assert_eq!(second.status(), actix_web::http::StatusCode::TOO_MANY_REQUESTS);
        let body: serde_json::Value = test::read_body_json(second).await;
        assert_eq!(body, serde_json::json!({"error": "Too Many Requests"}));
    }

    /// A request without a peer address cannot be attributed to a client and is
    /// passed through instead of being rejected.
    #[actix_web::test]
    async fn passes_through_when_peer_address_is_unknown() {
        let limiter: Limiter = build_limiter(1, Some(1));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(limiter))
                .app_data(web::Data::new(TrustedProxySet::from_addrs(&[])))
                .wrap(from_fn(per_ip_rate_limit_middleware))
                .route("/echo", web::get().to(ok_handler)),
        )
        .await;

        for _ in 0..3 {
            let resp = test::call_service(&app, test::TestRequest::get().uri("/echo").to_request()).await;
            assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        }
    }

    /// Behind a trusted proxy the forwarded client IP is the limiter key, so two
    /// different clients do not share a bucket.
    #[actix_web::test]
    async fn uses_forwarded_client_ip_behind_trusted_proxy() {
        let limiter: Limiter = build_limiter(1, Some(1));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(limiter))
                .app_data(web::Data::new(TrustedProxySet::from_addrs(&["127.0.0.1".to_string()])))
                .wrap(from_fn(per_ip_rate_limit_middleware))
                .route("/echo", web::get().to(ok_handler)),
        )
        .await;

        let peer = "127.0.0.1:9000".parse().unwrap();
        let request = |client_ip: &'static str| {
            test::TestRequest::get()
                .uri("/echo")
                .peer_addr(peer)
                .insert_header(("X-Forwarded-For", client_ip))
                .to_request()
        };

        let first = test::call_service(&app, request("203.0.113.5")).await;
        assert_eq!(first.status(), actix_web::http::StatusCode::OK, "first client, first request");

        let other_client = test::call_service(&app, request("203.0.113.6")).await;
        assert_eq!(
            other_client.status(),
            actix_web::http::StatusCode::OK,
            "a different forwarded client must get its own bucket"
        );

        let same_client = test::call_service(&app, request("203.0.113.5")).await;
        assert_eq!(
            same_client.status(),
            actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            "the same forwarded client must hit the same bucket"
        );
    }

    /// From an untrusted peer the forwarded header is ignored (no spoofing): all
    /// (status, body) pairs must come from the peer-keyed bucket.
    #[actix_web::test]
    async fn ignores_forwarded_ip_from_untrusted_peer() {
        let limiter: Limiter = build_limiter(1, Some(1));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(limiter))
                .app_data(web::Data::new(TrustedProxySet::from_addrs(&["10.0.0.1".to_string()])))
                .wrap(from_fn(per_ip_rate_limit_middleware))
                .route("/echo", web::get().to(ok_handler)),
        )
        .await;

        let peer = "198.51.100.7:8000".parse().unwrap();
        let first = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/echo")
                .peer_addr(peer)
                .insert_header(("X-Forwarded-For", "203.0.113.9"))
                .to_request(),
        )
        .await;
        assert_eq!(first.status(), actix_web::http::StatusCode::OK);

        let (status, body) = call_echo(
            &app,
            test::TestRequest::get().uri("/echo").peer_addr(peer).insert_header(("X-Forwarded-For", "203.0.113.10")),
        )
        .await;
        assert_eq!(status, actix_web::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, serde_json::json!({"error": "Too Many Requests"}));
    }
}

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

//! Per-IP rate limiting middleware. Compiled only when the `per-ip-rate-limit` feature is enabled.
//! Client IP for the limiter is taken from the direct peer, or from Forwarded/X-Forwarded-For
//! when the peer is in the trusted-proxy set (to avoid spoofing by untrusted clients).

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{web, Error, HttpResponse};
use governor::{Quota, RateLimiter};
use rbs_api_types::ErrorBody;

/// Keyed rate limiter type: one token bucket per client IP.
pub type KeyedLimiter = governor::DefaultKeyedRateLimiter<std::net::IpAddr>;

/// Set of peer IPs that are trusted proxies. When the request's peer is in this set,
/// client IP is taken from Forwarded / X-Forwarded-For (realip); otherwise the peer is used.
#[derive(Clone, Default)]
pub struct TrustedProxySet(HashSet<IpAddr>);

impl TrustedProxySet {
    /// Builds from config strings (e.g. "127.0.0.1", "::1"). Invalid entries are skipped.
    #[must_use]
    pub fn from_addrs(addrs: &[String]) -> Self {
        let set: HashSet<IpAddr> = addrs
            .iter()
            .filter_map(|s| {
                let s = s.trim();
                if s.is_empty() {
                    return None;
                }
                // Allow "ip" or "ip:port".
                if let Ok(ip) = s.parse::<IpAddr>() {
                    return Some(ip);
                }
                if let Ok(sa) = s.parse::<SocketAddr>() {
                    return Some(sa.ip());
                }
                None
            })
            .collect();
        Self(set)
    }

    #[must_use]
    pub fn is_trusted(&self, peer_ip: IpAddr) -> bool {
        self.0.contains(&peer_ip)
    }
}

/// Resolves the client IP for rate limiting and audit: when the direct peer is a trusted proxy,
/// uses Forwarded/X-Forwarded-For (realip); otherwise uses the peer address.
fn client_ip_for_request(
    peer_str: Option<&str>,
    realip_str: Option<&str>,
    trusted: &TrustedProxySet,
) -> Option<IpAddr> {
    let peer_sa = peer_str.and_then(|s| s.parse::<SocketAddr>().ok())?;
    let peer_ip = peer_sa.ip();
    if trusted.is_trusted(peer_ip) {
        // Use forwarded client IP only when peer is trusted (prevents spoofing).
        if let Some(rip) = realip_str {
            if let Ok(sa) = rip.trim().parse::<SocketAddr>() {
                return Some(sa.ip());
            }
            if let Ok(ip) = rip.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    Some(peer_ip)
}

/// Builds a keyed rate limiter from REST rate_limit config.
/// `requests_per_sec` is clamped to at least 1; invalid or zero `burst` falls back to `requests_per_sec`.
pub fn build_limiter(requests_per_sec: u32, burst: Option<u32>) -> Arc<KeyedLimiter> {
    let per_sec = NonZeroU32::new(requests_per_sec.max(1)).expect("max(1) is always >= 1");
    let burst_val = burst.and_then(NonZeroU32::new).filter(|&b| b.get() >= 1).unwrap_or(per_sec);
    let quota = Quota::per_second(per_sec).allow_burst(burst_val);
    Arc::new(RateLimiter::keyed(quota))
}

/// Middleware that checks the client IP against the keyed rate limiter and returns 429 if over limit.
/// Uses `BoxBody` so both the 429 response and the inner service response have a unified body type.
pub async fn per_ip_rate_limit_middleware<B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<BoxBody>, Error>
where
    B: MessageBody + 'static,
    B::Error: Into<Error>,
{
    let limiter = match req.app_data::<web::Data<Arc<KeyedLimiter>>>() {
        Some(l) => l.get_ref().clone(),
        None => {
            let res = next.call(req).await?;
            return Ok(res.map_body(|_, b| BoxBody::new(b)));
        },
    };
    let trusted = req.app_data::<web::Data<TrustedProxySet>>().map(|d| d.get_ref().clone()).unwrap_or_default();
    let ip = {
        let conn = req.connection_info();
        let peer_str = conn.peer_addr().map(std::string::ToString::to_string);
        let realip_str = conn.realip_remote_addr().map(std::string::ToString::to_string);
        client_ip_for_request(peer_str.as_deref(), realip_str.as_deref(), &trusted)
    };
    let ip = match ip {
        Some(ip) => ip,
        None => {
            let res = next.call(req).await?;
            return Ok(res.map_body(|_, b| BoxBody::new(b)));
        },
    };
    if limiter.check_key(&ip).is_err() {
        let res = req.into_response(HttpResponse::TooManyRequests().json(ErrorBody {
            error: "Too Many Requests".to_string(),
        }));
        return Ok(res.map_body(|_, b| BoxBody::new(b)));
    }
    let res = next.call(req).await?;
    Ok(res.map_body(|_, b| BoxBody::new(b)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn trusted_proxy_from_addrs_skips_empty_and_invalid() {
        let t = TrustedProxySet::from_addrs(&[
            "".to_string(),
            "  ".to_string(),
            "not-an-ip".to_string(),
        ]);
        assert!(!t.is_trusted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn trusted_proxy_from_addrs_trims_whitespace() {
        let t = TrustedProxySet::from_addrs(&["  127.0.0.1  ".to_string()]);
        assert!(t.is_trusted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn trusted_proxy_empty_set_is_not_trusted() {
        let t = TrustedProxySet::from_addrs(&[]);
        assert!(!t.is_trusted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!t.is_trusted(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn trusted_proxy_ipv6_addr() {
        let t = TrustedProxySet::from_addrs(&["::1".to_string()]);
        assert!(t.is_trusted(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!t.is_trusted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn client_ip_trusted_peer_uses_realip_socket_addr() {
        let trusted = TrustedProxySet::from_addrs(&["127.0.0.1".to_string()]);
        let ip = client_ip_for_request(
            Some("127.0.0.1:8080"),
            Some("192.0.2.1:12345"),
            &trusted,
        );
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn client_ip_trusted_peer_uses_realip_bare_ip() {
        let trusted = TrustedProxySet::from_addrs(&["127.0.0.1".to_string()]);
        let ip = client_ip_for_request(
            Some("127.0.0.1:8080"),
            Some("192.0.2.50"),
            &trusted,
        );
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))));
    }

    #[test]
    fn client_ip_untrusted_peer_ignores_realip() {
        let trusted = TrustedProxySet::from_addrs(&["10.0.0.1".to_string()]);
        let ip = client_ip_for_request(
            Some("192.0.2.1:4321"),
            Some("10.0.0.1:80"),
            &trusted,
        );
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn client_ip_trusted_peer_no_realip_falls_back_to_peer() {
        let trusted = TrustedProxySet::from_addrs(&["127.0.0.1".to_string()]);
        let ip = client_ip_for_request(
            Some("127.0.0.1:8080"),
            None,
            &trusted,
        );
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn client_ip_no_peer_returns_none() {
        let trusted = TrustedProxySet::from_addrs(&[]);
        let ip = client_ip_for_request(None, None, &trusted);
        assert_eq!(ip, None);
    }

    #[test]
    fn build_limiter_zero_rps_clamped_to_one() {
        let lim = build_limiter(0, None);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(lim.check_key(&ip).is_ok(), "zero rps should be clamped to 1");
    }

    #[test]
    fn build_limiter_zero_burst_falls_back_to_rps() {
        let lim = build_limiter(10, Some(0));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(lim.check_key(&ip).is_ok(), "zero burst should fall back to rps");
    }

    #[test]
    fn build_limiter_none_burst_falls_back_to_rps() {
        let lim = build_limiter(10, None);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(lim.check_key(&ip).is_ok(), "None burst should fall back to rps");
    }

    #[test]
    fn build_limiter_valid_rps_and_burst() {
        let lim = build_limiter(5, Some(10));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(lim.check_key(&ip).is_ok(), "valid rps/burst should pass first request");
    }
}

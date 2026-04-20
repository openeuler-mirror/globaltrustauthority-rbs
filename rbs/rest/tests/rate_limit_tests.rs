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

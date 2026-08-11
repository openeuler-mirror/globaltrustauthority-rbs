"""E2E tests for feature-gated per-IP rate limiting."""

from helpers.rbs_server import RbsServer
from e2e.rbs.support import assert_error
import httpx
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_rate_limit_returns_429_and_uses_trusted_forwarded_client_ip(
    rbs_server: RbsServer, isolated_http_port: int
) -> None:
    """Enforce burst per client IP and isolate trusted X-Forwarded-For buckets."""
    listen = f"127.0.0.1:{isolated_http_port}"
    base_url = f"http://{listen}"
    config = rbs_server.write_config(
        listen_addr=listen,
        https_enabled=False,
        rate_limit_enabled=True,
        requests_per_sec=1,
        burst=1,
        trusted_proxy_addrs=["127.0.0.1"],
    )
    rbs_server.start(config)
    rbs_server.wait_for_version(base_url)
    with httpx.Client(trust_env=False) as client:
        responses = [client.get(f"{base_url}/rbs/version", headers={"X-Forwarded-For": "192.0.2.10"}) for _ in range(5)]
        other_client = client.get(f"{base_url}/rbs/version", headers={"X-Forwarded-For": "192.0.2.11"})
    assert responses[0].status_code == 200
    limited = next((response for response in responses if response.status_code == 429), None)
    assert limited is not None, [response.status_code for response in responses]
    assert_error(limited, 429, "Too Many Requests")
    assert other_client.status_code == 200

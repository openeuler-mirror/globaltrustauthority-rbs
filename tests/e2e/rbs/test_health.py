# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
# PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

"""RBS server e2e: health check endpoints (/livez, /readyz) on a real process."""

from __future__ import annotations

import asyncio
import socket

import httpx
import pytest

from helpers.rbs_server import RbsServer

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def _reserve_free_port() -> int:
    """Reserve a currently unused loopback port, then close the socket."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


async def _probe_concurrently(base_url: str, path: str, count: int) -> list[httpx.Response]:
    async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
        return list(await asyncio.gather(*(client.get(f"{base_url}{path}") for _ in range(count))))


def test_health_endpoints_contract(rbs_server: RbsServer, isolated_http_port: int) -> None:
    """TC19: health endpoints on a real process, unauthenticated, plus business regression."""
    rest_port = isolated_http_port
    health_port = _reserve_free_port()
    base_url = f"http://127.0.0.1:{rest_port}"
    health_url = f"http://127.0.0.1:{health_port}"

    config = rbs_server.write_config(
        listen_addr=f"127.0.0.1:{rest_port}",
        https_enabled=False,
        health_listen_addr=f"127.0.0.1:{health_port}",
        log_name="rbs_health.log",
    )
    rbs_server.start(config)
    rbs_server.wait_for_version(base_url, verify=True)

    with httpx.Client(timeout=10.0, trust_env=False) as client:
        # No Authorization header on any request: the health port is unauthenticated by contract.
        livez = client.get(f"{health_url}/livez")
        assert livez.status_code == 200
        assert livez.json() == {"status": "ok"}
        assert livez.headers["content-type"].startswith("application/json")

        readyz = client.get(f"{health_url}/readyz")
        assert readyz.status_code == 200
        assert readyz.json() == {"status": "ok"}

        # Non-GET method on the health port -> 405.
        post = client.post(f"{health_url}/livez")
        assert post.status_code == 405

        # Same-process business regression: the REST API is unaffected by the health listener.
        version = client.get(f"{base_url}/rbs/version")
        assert version.status_code == 200
        assert version.json()["service_name"] == "globaltrustauthority-rbs"


def test_health_disabled_when_section_absent(rbs_server: RbsServer, isolated_http_port: int) -> None:
    """TC14: no `health` section -> no extra listener; process behavior unchanged."""
    rest_port = isolated_http_port
    reserved = _reserve_free_port()
    base_url = f"http://127.0.0.1:{rest_port}"

    config = rbs_server.write_config(
        listen_addr=f"127.0.0.1:{rest_port}",
        https_enabled=False,
        log_name="rbs_nohealth.log",
    )
    rbs_server.start(config)
    rbs_server.wait_for_version(base_url, verify=True)

    with httpx.Client(timeout=10.0, trust_env=False) as client:
        resp = client.get(f"{base_url}/rbs/version")
        assert resp.status_code == 200

    # The reserved port stayed closed: no extra listener was started.
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.1", reserved), timeout=1.0).close()


def test_health_concurrent_probes(rbs_server: RbsServer, isolated_http_port: int) -> None:
    """TC18: concurrent readiness probes all succeed (idempotent GET, workers=1 suffices)."""
    rest_port = isolated_http_port
    health_port = _reserve_free_port()
    base_url = f"http://127.0.0.1:{rest_port}"
    health_url = f"http://127.0.0.1:{health_port}"

    config = rbs_server.write_config(
        listen_addr=f"127.0.0.1:{rest_port}",
        https_enabled=False,
        health_listen_addr=f"127.0.0.1:{health_port}",
        log_name="rbs_health_conc.log",
    )
    rbs_server.start(config)
    rbs_server.wait_for_version(base_url, verify=True)

    results = asyncio.run(_probe_concurrently(health_url, "/readyz", 10))
    assert len(results) == 10
    assert all(r.status_code == 200 and r.json() == {"status": "ok"} for r in results)

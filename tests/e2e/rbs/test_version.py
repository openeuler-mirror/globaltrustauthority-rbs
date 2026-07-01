# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""RBS server e2e: /rbs/version over HTTP and HTTPS."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import httpx
import pytest

from helpers.env import E2E_PORT_HTTP, E2E_PORT_HTTPS
from helpers.rbs_server import RbsServer

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]

_GIT_HASH_RE = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def _assert_version_response(data: dict[str, Any]) -> None:
    """Assert /rbs/version JSON matches the public contract."""
    assert data.get("service_name") == "globaltrustauthority-rbs"
    assert data.get("api_version") == "0"
    build = data.get("build")
    assert isinstance(build, dict)
    version = build.get("version")
    assert isinstance(version, str) and version

    git_hash = build.get("git_hash")
    assert isinstance(git_hash, str) and git_hash, "build.git_hash must be a non-empty string"
    if not _GIT_HASH_RE.match(git_hash):
        raise AssertionError(
            f"build.git_hash must be 40 or 64 hex chars, got {git_hash!r}"
        )

    build_date = build.get("build_date")
    assert isinstance(build_date, str) and build_date, "build.build_date must be a non-empty string"


def test_version_http(rbs_server: RbsServer) -> None:
    listen = f"127.0.0.1:{E2E_PORT_HTTP}"
    base_url = f"http://{listen}"
    config = rbs_server.write_config(listen_addr=listen, https_enabled=False)
    rbs_server.start(config)
    rbs_server.wait_for_version(base_url, verify=True)

    with httpx.Client(timeout=10.0) as client:
        resp = client.get(f"{base_url}/rbs/version")
    assert resp.status_code == 200
    _assert_version_response(resp.json())


def test_version_https(rbs_server: RbsServer, rbs_scratch_dir: Path) -> None:
    cert_path = rbs_scratch_dir / "server.pem"
    key_path = rbs_scratch_dir / "server.key"
    RbsServer.generate_self_signed_cert(cert_path, key_path)

    listen = f"127.0.0.1:{E2E_PORT_HTTPS}"
    base_url = f"https://{listen}"
    config = rbs_server.write_config(
        listen_addr=listen,
        https_enabled=True,
        cert_file=str(cert_path),
        key_file=str(key_path),
        log_name="rbs_https.log",
    )
    rbs_server.start(config)
    rbs_server.wait_for_version(base_url, verify=False)

    with httpx.Client(verify=False, timeout=10.0) as client:
        resp = client.get(f"{base_url}/rbs/version")
    assert resp.status_code == 200
    _assert_version_response(resp.json())

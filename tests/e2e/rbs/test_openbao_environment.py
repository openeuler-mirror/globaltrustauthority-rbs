# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""E2E deployment check for OpenBao dev mode followed by RBS startup."""

from __future__ import annotations

import httpx
import pytest

from helpers.openbao_server import OpenBaoServer
from helpers.rbs_server import RbsServer

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_rbs_starts_after_openbao_dev(
    rbs_server: RbsServer,
    openbao_server: OpenBaoServer,
    isolated_http_port: int,
) -> None:
    listen = f"127.0.0.1:{isolated_http_port}"
    base_url = f"http://{listen}"
    config = rbs_server.write_config(
        listen_addr=listen,
        https_enabled=False,
        openbao_base_url=openbao_server.base_url,
        openbao_token=openbao_server.root_token,
    )
    rbs_server.start(config)
    rbs_server.wait_for_version(base_url)

    with httpx.Client(timeout=10.0, trust_env=False) as client:
        health = client.get(f"{openbao_server.base_url}/v1/sys/health")
        version = client.get(f"{base_url}/rbs/version")

    assert health.status_code == 200
    assert version.status_code == 200

# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

from __future__ import annotations

import shutil
import socket
from pathlib import Path

import pytest

from helpers.openbao_server import OpenBaoServer
from helpers.rbs_server import RbsServer


@pytest.fixture
def isolated_http_port() -> int:
    """Return a currently unused loopback port for one isolated RBS scenario."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@pytest.fixture(scope="module")
def rbs_scratch_dir(tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest) -> Path:
    return tmp_path_factory.mktemp(request.module.__name__.replace(".", "_"))


@pytest.fixture(scope="module")
def rbs_server(rbs_binary: Path, rbs_scratch_dir: Path, repo_root: Path) -> RbsServer:
    """Provide an isolated server for startup, HTTPS, and rate-limit scenarios."""
    server = RbsServer(rbs_binary, rbs_scratch_dir, repo_root)
    yield server
    server.stop()


@pytest.fixture(scope="module")
def openbao_server(rbs_scratch_dir: Path) -> OpenBaoServer:
    binary = shutil.which("bao") or shutil.which("openbao")
    if binary is None:
        pytest.fail("bao or openbao is required for OpenBao E2E tests", pytrace=False)
    server = OpenBaoServer(binary, rbs_scratch_dir)
    server.start()
    yield server
    server.stop()

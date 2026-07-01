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
import subprocess
from pathlib import Path

import pytest

from helpers.rbs_build import E2eBuildError, rbs_e2e_cargo_env
from helpers.rbs_server import RbsServer


@pytest.fixture(scope="session")
def rbs_binary(repo_root: Path) -> Path:
    for tool in ("openssl", "cargo"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is required for RBS e2e tests")
    binary = repo_root / "target" / "debug" / "rbs"
    try:
        build_env = rbs_e2e_cargo_env(repo_root)
    except E2eBuildError as exc:
        pytest.skip(str(exc))
    try:
        subprocess.run(
            ["cargo", "build", "-p", "rbs", "--bin", "rbs", "--features", "rest", "--quiet"],
            cwd=repo_root,
            check=True,
            env=build_env,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"failed to build RBS binary with cargo: {exc}")
    if not binary.is_file():
        pytest.skip(f"RBS binary not found at {binary}")
    return binary


@pytest.fixture
def rbs_scratch_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def rbs_server(rbs_binary: Path, rbs_scratch_dir: Path, repo_root: Path) -> RbsServer:
    # Function scope: isolated config/process per test. Shared server fixtures can be
    # added at module/session scope later for tests that do not need a fresh instance.
    server = RbsServer(rbs_binary, rbs_scratch_dir, repo_root)
    yield server
    server.stop()

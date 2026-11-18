# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""Process-level regression tests for the API documentation drift gate."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]

DOC_PATHS = (
    "docs/proto/rbs_rest_api.yaml",
    "docs/api/rbs/md/rbs_rest_api.md",
    "docs/api/rbs/html/rbs_rest_api.html",
)


@pytest.mark.parametrize("stale_path", [None, *DOC_PATHS])
def test_api_docs_gate_detects_drift_before_cargo_tests(
    repo_root: Path, tmp_path: Path, stale_path: str | None,
) -> None:
    """A Cargo test that regenerates YAML must not erase the gate's baseline."""
    for relative in ("tests/test_all.sh", "tests/common.sh"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_root / relative, target)
    for relative in DOC_PATHS:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("stale" if relative == stale_path else "generated")

    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    cargo = binary_dir / "cargo"
    # Simulate rbs/build.rs running during cargo test, before the docs check.
    cargo.write_text('#!/bin/sh\nprintf generated > docs/proto/rbs_rest_api.yaml\n')
    cargo.chmod(0o755)
    generator = tmp_path / "scripts/generate-api-docs.sh"
    generator.parent.mkdir()
    generator.write_text("#!/bin/sh\n" + "".join(
        f"printf generated > {relative}\n" for relative in DOC_PATHS
    ))
    generator.chmod(0o755)
    env = {**os.environ, "PATH": f"{binary_dir}:{os.environ['PATH']}",
           "ENABLE_CARGO_TESTS": "1", "ENABLE_E2E_TESTS": "0"}
    result = subprocess.run(
        ["bash", str(tmp_path / "tests/test_all.sh"), "--suite", "rbs"],
        cwd=tmp_path, env=env, text=True, capture_output=True, timeout=15,
    )
    output = result.stdout + result.stderr
    if stale_path is None:
        assert result.returncode == 0, output
        assert "OpenAPI documentation is in sync" in output
    else:
        assert result.returncode != 0, output
        assert f"{stale_path} differs from generated output" in output

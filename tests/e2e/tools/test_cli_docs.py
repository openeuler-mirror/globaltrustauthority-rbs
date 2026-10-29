# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""Client documentation generation, including non-mutating drift checks."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.rbc, pytest.mark.tools]

DOC_PATHS = ("docs/api/rbc/cli.md", "docs/api/rbs-cli/cli.md", "docs/api/rbc/sdk.md")


def test_sdk_generator_default_paths_and_check(repo_root: Path, tmp_path: Path):
    script = repo_root / "scripts/gen-rbc-sdk-docs.py"
    output = tmp_path / "sdk.md"
    command = [sys.executable, str(script), "--output", str(output)]
    subprocess.run(command, cwd=tmp_path, check=True, capture_output=True)
    assert output.read_bytes() == (repo_root / "docs/api/rbc/sdk.md").read_bytes()
    subprocess.run([*command, "--check"], cwd=tmp_path, check=True, capture_output=True)
    for stale in ("stale", None):
        if stale is None:
            output.unlink()
        else:
            output.write_text(stale)
        result = subprocess.run([*command, "--check"], cwd=tmp_path, capture_output=True)
        assert result.returncode != 0
        assert (output.read_text() if output.exists() else None) == stale


def test_sdk_generator_preserves_methods_after_inline_body(repo_root: Path, tmp_path: Path):
    source = tmp_path / "sdk.rs"
    source.write_text("""pub struct Client {
}
impl Client {
    /// First method.
    pub fn first(&self) -> bool { true }
    /// Async method after an inline body.
    pub async fn second(&self) -> bool {
        true
    }
    pub const fn third(&self) -> bool { false }
}
""")
    output = tmp_path / "sdk.md"
    subprocess.run([sys.executable, str(repo_root / "scripts/gen-rbc-sdk-docs.py"),
                    str(source), "--output", str(output)], check=True, capture_output=True)
    text = output.read_text()
    for name in ("first", "second", "third"):
        assert f"#### `{name}`" in text


@pytest.mark.parametrize("stale_path", DOC_PATHS)
@pytest.mark.parametrize("missing", [False, True])
def test_cli_docs_check_rejects_drift_without_rewriting(repo_root: Path, tmp_path: Path,
                                                       stale_path: str, missing: bool):
    # Keep the real script and SDK generator; stub only the expensive Cargo renderer.
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ("generate-cli-docs.sh", "gen-rbc-sdk-docs.py"):
        shutil.copy2(repo_root / "scripts" / name, scripts / name)
    sdk = tmp_path / "rbc/src/sdk.rs"
    sdk.parent.mkdir(parents=True)
    shutil.copy2(repo_root / "rbc/src/sdk.rs", sdk)
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    cargo = binary_dir / "cargo"
    cargo.write_text("#!/bin/sh\nwhile [ \"$1\" != --output-dir ]; do shift; done\nshift\n"
                     "mkdir -p \"$1/docs/api/rbc\" \"$1/docs/api/rbs-cli\"\n"
                     "printf generated > \"$1/docs/api/rbc/cli.md\"\n"
                     "printf generated > \"$1/docs/api/rbs-cli/cli.md\"\n")
    cargo.chmod(0o755)
    env = {**os.environ, "PATH": f"{binary_dir}:{os.environ['PATH']}", "PYTHON_BIN": sys.executable}
    command = ["bash", str(scripts / "generate-cli-docs.sh")]
    subprocess.run(command, cwd=tmp_path, env=env, check=True, capture_output=True)
    subprocess.run([*command, "--check"], cwd=tmp_path, env=env, check=True, capture_output=True)
    target = tmp_path / stale_path
    if missing:
        target.unlink()
    else:
        target.write_text("stale")
    before = {path: (tmp_path / path).read_bytes() if (tmp_path / path).exists() else None
              for path in DOC_PATHS}
    result = subprocess.run([*command, "--check"], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert stale_path in result.stderr
    assert before == {path: (tmp_path / path).read_bytes() if (tmp_path / path).exists() else None
                      for path in DOC_PATHS}


@pytest.mark.parametrize("suite", ["rbc", "tools"])
def test_client_suite_gate_propagates_document_drift(repo_root: Path, tmp_path: Path, suite: str):
    for relative in ("tests/test_all.sh", "tests/common.sh"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_root / relative, target)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    generator = scripts / "generate-cli-docs.sh"
    generator.write_text('#!/bin/sh\n[ "$1" = "--check" ] || exit 2\necho "client document drift" >&2\nexit 1\n')
    generator.chmod(0o755)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    cargo = binaries / "cargo"
    cargo.write_text("#!/bin/sh\nexit 0\n")
    cargo.chmod(0o755)
    env = {**os.environ, "PATH": f"{binaries}:{os.environ['PATH']}",
           "ENABLE_CARGO_TESTS": "1", "ENABLE_E2E_TESTS": "0"}
    result = subprocess.run(["bash", str(tmp_path / "tests/test_all.sh"), "--suite", suite],
                            cwd=tmp_path, env=env, text=True, capture_output=True, timeout=15)
    assert result.returncode != 0
    assert "client document drift" in result.stderr

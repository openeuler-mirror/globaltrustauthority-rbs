# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""RBS e2e cargo build helpers (compile-time GIT_HASH / BUILD_DATE)."""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path


class E2eBuildError(Exception):
    """RBS e2e binary cannot be built with required compile-time metadata."""


def rbs_e2e_cargo_env(repo_root: Path) -> dict[str, str]:
    """Env vars for `cargo build` so /rbs/version embeds git_hash and build_date."""
    env = os.environ.copy()
    if "GIT_HASH" not in env:
        try:
            env["GIT_HASH"] = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_root,
                text=True,
            ).strip()
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            raise E2eBuildError(
                "git is required for RBS e2e builds (GIT_HASH must be embedded at compile time)"
            ) from exc
    if "BUILD_DATE" not in env:
        env["BUILD_DATE"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return env

"""RBC C ABI process-level E2E smoke test."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import create_resource

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_c_ffi_runs_complete_native_attestation_and_resource_flow(
    rbc_ffi_smoke: Path,
    rbc_library: Path,
    rbs_api: Any,
    agent_config_path: Path,
    rbc_config_path: Path,
) -> None:
    """Link the C ABI and verify challenge, evidence, token, resource, and decryption calls."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(rbc_library.parent)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(name, None)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    result = subprocess.run(
        [str(rbc_ffi_smoke), str(rbc_config_path), uri, json.dumps(secret, separators=(",", ":"))],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, f"C FFI smoke failed: stdout={result.stdout!r}; stderr={result.stderr!r}"
    assert json.loads(result.stdout) == {
        "nonce_present": True,
        "token_segments": 3,
        "plaintext_matches": True,
    }

"""RBC Rust SDK process-level E2E test."""

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


def test_rust_sdk_runs_complete_native_attestation_and_resource_flow(
    rbc_sdk_probe: Path,
    rbs_api: Any,
    agent_config_path: Path,
) -> None:
    """Call the public Rust SDK directly and verify evidence, token, JWE, and plaintext."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
    env = dict(os.environ)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(name, None)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    result = subprocess.run(
        [str(rbc_sdk_probe), rbs_api.base_url, str(agent_config_path), uri],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, f"SDK probe failed: stdout={result.stdout!r}; stderr={result.stderr!r}"
    payload = json.loads(result.stdout)
    assert payload["nonce"]
    assert payload["attester_type"] == "tpm"
    assert payload["token_segments"] == 3
    assert payload["uri"] == f"/rbs/v0/{uri}"
    assert payload["content_type"] == "json"
    assert payload["plaintext"] == secret

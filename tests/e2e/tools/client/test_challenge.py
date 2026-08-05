"""Unified tools client challenge tests."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

from e2e.tools.support import assert_cli_rejected, client_challenge, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_client_challenge_returns_complete_nonce_contract(
    rbs_cli_binary: Path, rbs_api: Any, agent_config_path: Path
) -> None:
    """Forward client challenge to real RBS and validate the encoded nonce."""
    nonce = client_challenge(rbs_cli_binary, rbs_api.base_url, agent_config_path)
    assert base64.b64decode(nonce, validate=True).decode("utf-8").startswith("e2e-nonce-")


def test_client_challenge_rejects_directory_agent_config(rbs_cli_binary: Path, tmp_path: Path) -> None:
    """Reject invalid agent configuration before contacting the service."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "client",
        "challenge",
        "--agent-config",
        str(tmp_path),
        check=False,
    )
    assert_cli_rejected(result, "existing directory")


def test_client_challenge_writes_explicit_json_to_file(
    rbs_cli_binary: Path, rbs_api: Any, agent_config_path: Path, tmp_path: Path
) -> None:
    """Write an explicit JSON challenge response without losing its schema."""
    output_file = tmp_path / "challenge.json"
    result = run_tools(
        rbs_cli_binary,
        rbs_api.base_url,
        "client",
        "challenge",
        "--agent-config",
        str(agent_config_path),
        output_file=output_file,
    )
    assert result.stdout.strip()
    payload = json_output(result)
    saved = json_output(type("Result", (), {"stdout": output_file.read_text(), "returncode": 0})())
    assert saved == payload

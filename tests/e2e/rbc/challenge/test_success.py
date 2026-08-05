"""RBC challenge command success and output-contract tests."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

from e2e.rbc.support import assert_json_output, run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_challenge_returns_a_base64_nonce_from_real_rbs(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path
) -> None:
    """Request a real RBS challenge and validate the complete JSON response contract."""
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "challenge",
        "--agent-config",
        str(agent_config_path),
        output_format="json",
    )
    payload = assert_json_output(result)
    assert set(payload) == {"nonce"}
    nonce = payload["nonce"]
    assert isinstance(nonce, str) and nonce
    decoded = base64.b64decode(nonce, validate=True).decode("utf-8")
    assert decoded.startswith("e2e-nonce-")


def test_challenge_supports_text_output(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path
) -> None:
    """Render the challenge response in the user-facing text format."""
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "challenge",
        "--agent-config",
        str(agent_config_path),
        output_format="text",
    )
    assert result.returncode == 0
    assert result.stdout.strip()
    decoded = base64.b64decode(result.stdout.strip(), validate=True).decode("utf-8")
    assert decoded.startswith("e2e-nonce-")

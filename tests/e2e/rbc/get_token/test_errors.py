"""RBC get-token upstream-error mapping tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from e2e.rbc.support import run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_get_token_maps_gta_attest_failure_to_server_error(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Convert a deterministic GTA attest failure to a CLI provider error."""
    rbs_api.fake_gta.fail_next_attest(status=503)
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "get-token",
        "--agent-config",
        str(agent_config_path),
        "--attester-pubkey",
        f"@{rbc_key_material.public_key_path}",
        output_format="json",
        check=False,
    )
    assert result.returncode != 0
    assert "providererror" in result.stderr.lower()
    assert "http 503" in result.stderr.lower()

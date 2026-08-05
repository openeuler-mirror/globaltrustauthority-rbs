"""RBC challenge command upstream-error mapping tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from e2e.rbc.support import run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_challenge_maps_gta_unavailability_to_server_error(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path
) -> None:
    """Convert an upstream GTA failure returned by real RBS into a stable CLI error."""
    rbs_api.fake_gta.fail_next_challenge(message="do not leak this GTA detail")
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "challenge",
        "--agent-config",
        str(agent_config_path),
        output_format="json",
        check=False,
    )
    assert result.returncode != 0
    assert "servererror" in result.stderr.lower()
    assert "do not leak this gta detail" not in result.stderr.lower()

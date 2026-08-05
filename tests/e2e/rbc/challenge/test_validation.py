"""RBC challenge command parameter validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from e2e.rbc.support import assert_cli_rejected, run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_challenge_rejects_an_existing_directory_as_agent_config(
    rbc_binary: Path, rbs_api: object, tmp_path: Path
) -> None:
    """Reject a directory before any RBS request is attempted."""
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "challenge",
        "--agent-config",
        str(tmp_path),
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "existing directory")

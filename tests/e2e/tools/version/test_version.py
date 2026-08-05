"""Unified tools version output tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from e2e.tools.support import json_output, run_tools, text_output

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_version_returns_complete_json_contract(rbs_cli_binary: Path, rbs_api: object) -> None:
    """Return binary name and package version without contacting an authenticated endpoint."""
    payload = json_output(run_tools(rbs_cli_binary, rbs_api.base_url, "version"))
    assert set(payload) == {"name", "version"}
    assert payload["name"] == "rbs-cli"
    assert isinstance(payload["version"], str) and payload["version"]


def test_version_supports_text_output(rbs_cli_binary: Path, rbs_api: object) -> None:
    """Render version information in the default human-readable format."""
    output = text_output(run_tools(rbs_cli_binary, rbs_api.base_url, "version", output_format="text"))
    assert "rbs-cli" in output

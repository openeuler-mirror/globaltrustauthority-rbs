"""Unified tools user update tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_user, create_user
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_user_update_changes_enabled_state(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Update a user and validate the changed state while preserving identity."""
    with httpx.Client(trust_env=False) as client:
        created = create_user(client, rbs_api)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "user",
            "update",
            "--username",
            created["username"],
            "--enabled",
            "false",
            token=rbs_api.admin_token,
        )
    )
    assert_user(payload, username=created["username"], role="user", enabled=False)


def test_user_update_requires_an_updatable_field(rbs_cli_binary: Path) -> None:
    """Reject a no-op update before contacting RBS."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "user",
        "update",
        "--username",
        "user",
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "at least one updatable field")

"""Unified tools user delete tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_error, create_user
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_user_delete_removes_user(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Delete a user and verify the admin API no longer returns it."""
    with httpx.Client(trust_env=False) as client:
        created = create_user(client, rbs_api)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "user",
            "delete",
            "--username",
            created["username"],
            token=rbs_api.admin_token,
        )
    )
    assert payload == {"username": created["username"]}
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users/{created['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 404)


def test_user_delete_rejects_invalid_username(rbs_cli_binary: Path) -> None:
    """Reject URL-control characters in a username before HTTP dispatch."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "user",
        "delete",
        "--username",
        "../admin",
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "username")

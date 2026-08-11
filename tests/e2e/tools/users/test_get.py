"""Unified tools user get tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_user, create_user
from e2e.tools.support import json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_user_get_returns_complete_user_contract(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Get a user and verify the response contains no key material."""
    with httpx.Client(trust_env=False) as client:
        created = create_user(client, rbs_api)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "user",
            "get",
            "--username",
            created["username"],
            token=rbs_api.admin_token,
        )
    )
    assert_user(payload, username=created["username"], role="user", enabled=True)
    assert "jwk" not in payload and "public_key" not in payload


def test_user_get_maps_unknown_username_to_not_found(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Map an admin API 404 into the sanitized tools diagnostic."""
    result = run_tools(
        rbs_cli_binary,
        rbs_api.base_url,
        "user",
        "get",
        "--username",
        "missing-user",
        token=rbs_api.admin_token,
        check=False,
    )
    assert result.returncode != 0
    assert "not found" in result.stderr.lower()

"""Unified tools user list tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_user_list_returns_complete_pagination_contract(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """List users and validate users plus all pagination metadata."""
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "user",
            "list",
            "--limit",
            "1",
            "--offset",
            "0",
            token=rbs_api.admin_token,
        )
    )
    assert set(payload) == {"users", "total_count", "limit", "offset"}
    assert isinstance(payload["users"], list)
    assert payload["limit"] == 1 and payload["offset"] == 0
    assert isinstance(payload["total_count"], int) and payload["total_count"] >= 1


def test_user_list_rejects_limit_below_minimum(rbs_cli_binary: Path) -> None:
    """Reject page limit zero before making an admin request."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "user",
        "list",
        "--limit",
        "0",
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "between 1 and 100")

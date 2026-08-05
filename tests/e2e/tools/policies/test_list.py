"""Unified tools resource-policy list tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from e2e.rbs.support import unique_name
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_policy_list_returns_complete_pagination_contract(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """List resource policies and validate items plus pagination metadata."""
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res-policy",
            "list",
            "--limit",
            "1",
            "--offset",
            "0",
            token=rbs_api.admin_token,
        )
    )
    assert set(payload) == {"items", "total_count", "limit", "offset"}
    assert isinstance(payload["items"], list)
    assert payload["limit"] == 1 and payload["offset"] == 0
    assert isinstance(payload["total_count"], int) and payload["total_count"] >= 0


@pytest.mark.parametrize("argument", ["0", "101"], ids=["below-min", "above-max"])
def test_policy_list_rejects_out_of_range_limit(rbs_cli_binary: Path, argument: str) -> None:
    """Reject limits outside the CLI's documented inclusive range 1..100."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res-policy",
        "list",
        "--limit",
        argument,
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "invalid value")

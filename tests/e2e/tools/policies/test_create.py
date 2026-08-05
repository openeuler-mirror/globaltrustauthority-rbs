"""Unified tools resource-policy create tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from e2e.rbs.support import ALLOW_POLICY, assert_policy, unique_name
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_policy_create_returns_complete_policy_contract(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Create one policy and validate all stable response fields."""
    name = unique_name("clipolicy")
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res-policy",
            "create",
            "--name",
            name,
            "--content",
            ALLOW_POLICY,
            token=rbs_api.admin_token,
        )
    )
    assert_policy(payload, name=name)


def test_policy_create_rejects_empty_name(rbs_cli_binary: Path) -> None:
    """Reject an empty policy name before HTTP dispatch."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res-policy",
        "create",
        "--name",
        " ",
        "--content",
        ALLOW_POLICY,
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "name must not be empty")

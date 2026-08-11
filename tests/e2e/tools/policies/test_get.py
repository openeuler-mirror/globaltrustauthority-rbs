"""Unified tools resource-policy get tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_policy, create_policy
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_policy_get_returns_detail_contract(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Get a policy and validate its applied-resource detail field."""
    with httpx.Client(trust_env=False) as client:
        created = create_policy(client, rbs_api)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res-policy",
            "get",
            "--id",
            created["policy_id"],
            token=rbs_api.admin_token,
        )
    )
    assert_policy(payload, name=created["policy_name"], detail=True)


def test_policy_get_rejects_path_control_characters(rbs_cli_binary: Path) -> None:
    """Reject policy IDs that could alter the request path."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res-policy",
        "get",
        "--id",
        "../policy",
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "url path control")

"""Unified tools resource-policy delete tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_error, create_policy
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_policy_delete_removes_policy_and_returns_message(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Delete a policy and verify the API no longer returns it."""
    with httpx.Client(trust_env=False) as client:
        created = create_policy(client, rbs_api)
    deleted = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res-policy",
            "delete",
            "--id",
            created["policy_id"],
            token=rbs_api.admin_token,
        )
    )
    assert set(deleted) == {"message"}
    with httpx.Client(trust_env=False) as client:
        response = client.get(
            f"{rbs_api.base_url}/rbs/v0/resource/policy/{created['policy_id']}", headers=rbs_api.admin_headers
        )
    assert_error(response, 404)


def test_policy_delete_requires_one_target(rbs_cli_binary: Path) -> None:
    """Reject delete without either a single ID or a list of IDs."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res-policy",
        "delete",
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "required")

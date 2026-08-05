"""Unified tools resource-policy update tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import ALLOW_POLICY, assert_policy, create_policy, unique_name
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_policy_update_increments_version_and_returns_new_name(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Update a policy and verify both mutation fields and version transition."""
    with httpx.Client(trust_env=False) as client:
        created = create_policy(client, rbs_api)
    new_name = unique_name("updatedpolicy")
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res-policy",
            "update",
            "--id",
            created["policy_id"],
            "--name",
            new_name,
            "--content",
            "package verification\ndefault allow = true",
            token=rbs_api.admin_token,
        )
    )
    assert_policy(payload, name=new_name)
    assert payload["policy_version"] == created["policy_version"] + 1


def test_policy_update_rejects_missing_required_content(rbs_cli_binary: Path) -> None:
    """Reject an update that omits the policy content argument."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res-policy",
        "update",
        "--id",
        "policy-id",
        "--name",
        "updated",
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "required")

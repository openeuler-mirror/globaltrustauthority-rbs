"""Unified tools resource update tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_resource, create_policy, create_resource
from e2e.tools.support import assert_cli_rejected, assert_resource_metadata, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_resource_update_returns_updated_metadata(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Update a resource binding and verify its policy and content metadata."""
    with httpx.Client(trust_env=False) as client:
        uri, _, _ = create_resource(client, rbs_api)
        updated_policy = create_policy(client, rbs_api)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res",
            "update",
            "--uri",
            uri,
            "--policy-id",
            updated_policy["policy_id"],
            "--content-type",
            "json",
            "--export-mode",
            "jwe",
            "--additional-info",
            "updated-by-tools",
            token=rbs_api.admin_token,
        )
    )
    assert_resource_metadata(payload, uri=uri, policy_id=updated_policy["policy_id"])


def test_resource_update_requires_policy_id(rbs_cli_binary: Path) -> None:
    """Reject an update without the required policy binding."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res",
        "update",
        "--uri",
        "vault/default/secret/demo",
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "required")

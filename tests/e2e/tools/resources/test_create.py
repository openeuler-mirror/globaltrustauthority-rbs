"""Unified tools resource create tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_resource, create_policy, unique_name
from e2e.tools.support import assert_cli_rejected, assert_resource_metadata, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_resource_create_returns_complete_metadata_contract(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Create a resource binding through tools and validate all stable metadata fields."""
    name = unique_name("toolres", max_length=30)
    uri = f"vault/default/secret/{name}"
    rbs_api.openbao.write_kv(f"default/secret/{name}", {"value": "create"})
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res",
            "create",
            "--uri",
            uri,
            "--policy-id",
            policy["policy_id"],
            "--content-type",
            "json",
            "--export-mode",
            "jwe",
            "--additional-info",
            "created-by-tools",
            token=rbs_api.admin_token,
        )
    )
    assert_resource_metadata(payload, uri=uri, policy_id=policy["policy_id"])


def test_resource_create_rejects_invalid_uri_and_export_mode(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Reject malformed four-segment URIs and unsupported plaintext export."""
    invalid_uri = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res",
        "create",
        "--uri",
        "vault/default/secret",
        "--policy-id",
        "policy-id",
        token="token",
        check=False,
    )
    assert_cli_rejected(invalid_uri, "provider/repository/type/name")
    invalid_export = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res",
        "create",
        "--uri",
        "vault/default/secret/demo",
        "--policy-id",
        "policy-id",
        "--export-mode",
        "plain",
        token="token",
        check=False,
    )
    assert_cli_rejected(invalid_export, "possible values")

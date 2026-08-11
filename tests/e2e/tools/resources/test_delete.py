"""Unified tools resource delete tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_error, create_resource
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_resource_delete_removes_metadata(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Delete a resource binding and verify subsequent metadata lookup returns not found."""
    with httpx.Client(trust_env=False) as client:
        uri, _, _ = create_resource(client, rbs_api)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res",
            "delete",
            "--uri",
            uri,
            token=rbs_api.admin_token,
        )
    )
    assert set(payload) == {"message"}
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{uri}/info", headers=rbs_api.admin_headers)
    assert_error(response, 404)


def test_resource_delete_rejects_invalid_uri(rbs_cli_binary: Path) -> None:
    """Reject path traversal and wrong-segment resource URIs before HTTP dispatch."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res",
        "delete",
        "--uri",
        "vault/default/secret/../admin",
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "provider/repository/type/name")

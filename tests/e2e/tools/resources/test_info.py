"""Unified tools resource metadata retrieval tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_resource, create_resource
from e2e.tools.support import assert_cli_rejected, assert_resource_metadata, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_resource_info_returns_metadata_without_content(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Retrieve resource metadata and ensure secret content is absent."""
    with httpx.Client(trust_env=False) as client:
        uri, metadata, _ = create_resource(client, rbs_api)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res",
            "get-res-info",
            "--uri",
            uri,
            token=rbs_api.admin_token,
        )
    )
    assert_resource_metadata(payload, uri=uri, policy_id=metadata["policy_id"])
    assert "content" not in payload


def test_resource_info_rejects_unknown_resource(rbs_cli_binary: Path, rbs_api: Any) -> None:
    """Map a valid but unknown resource URI to the admin-client not-found message."""
    result = run_tools(
        rbs_cli_binary,
        rbs_api.base_url,
        "res",
        "get-res-info",
        "--uri",
        "vault/default/secret/no-such-resource",
        token=rbs_api.admin_token,
        check=False,
    )
    assert result.returncode != 0
    assert "not found" in result.stderr.lower()

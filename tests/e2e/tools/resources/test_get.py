"""Unified tools resource content retrieval tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import create_resource
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_resource_get_decrypts_exact_openbao_json(rbs_cli_binary: Path, rbs_api: Any, rbc_key_material: Any) -> None:
    """Fetch resource JWE content through tools and validate URI, type, mode, and plaintext."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
    tools_token = rbs_api.fake_gta.issue_bearer_token(rbc_key_material.public_jwk)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "res",
            "get",
            "--uri",
            uri,
            "--private-key-file",
            str(rbc_key_material.private_key_path),
            token=tools_token,
        )
    )
    assert set(payload) == {"uri", "content", "content_type", "export_mode"}
    assert payload["uri"] == f"/rbs/v0/{uri}"
    assert payload["content_type"] == "json"
    assert payload["export_mode"] == "jwe"
    assert json.loads(base64.b64decode(payload["content"], validate=True)) == secret


def test_resource_get_rejects_directory_as_private_key(rbs_cli_binary: Path, rbs_api: Any, tmp_path: Path) -> None:
    """Reject an existing directory before contacting RBS."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "res",
        "get",
        "--uri",
        "vault/default/secret/demo",
        "--private-key-file",
        str(tmp_path),
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "existing directory")

"""Unified tools client token-mode resource retrieval tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import create_resource
from e2e.tools.support import json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_client_get_resource_by_token_decrypts_exact_value(
    rbs_cli_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Fetch and decrypt a real OpenBao value through the unified token mode."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
    token = rbs_api.fake_gta.issue_token(
        {"attester_data": {"runtime_data": {"tee-pubkey": rbc_key_material.public_jwk}}}
    )
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "client",
            "get-resource",
            "--agent-config",
            str(agent_config_path),
            "--uri",
            uri,
            "--attest-token",
            token,
            "--private-key-file",
            str(rbc_key_material.private_key_path),
        )
    )
    assert set(payload) == {"uri", "content", "content_type"}
    assert payload["uri"] == f"/rbs/v0/{uri}"
    assert payload["content_type"] == "json"
    import base64, json as json_module

    assert json_module.loads(base64.b64decode(payload["content"], validate=True)) == secret

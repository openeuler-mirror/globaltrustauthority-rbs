"""Unified tools client complete lifecycle E2E test."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import create_resource
from e2e.tools.support import client_challenge, client_collect_evidence, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_tools_client_lifecycle_challenge_evidence_token_resource(
    rbs_cli_binary: Path,
    rbs_api: Any,
    agent_config_path: Path,
    rbc_key_material: Any,
    tmp_path: Path,
) -> None:
    """Run challenge, evidence, token, resource, and decryption in one explicit sequence."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
    nonce = client_challenge(rbs_cli_binary, rbs_api.base_url, agent_config_path)
    evidence = client_collect_evidence(
        rbs_cli_binary, rbs_api.base_url, agent_config_path, rbc_key_material.public_key_path, nonce
    )
    evidence_path = tmp_path / "lifecycle-evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    token = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "client",
            "get-token",
            "--agent-config",
            str(agent_config_path),
            "--evidence",
            f"@{evidence_path}",
        )
    )["token"]
    resource = json_output(
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
    assert evidence["measurements"][0]["nonce"] == nonce
    assert token.count(".") == 2
    assert resource["uri"] == f"/rbs/v0/{uri}"
    assert resource["content_type"] == "json"
    assert json.loads(base64.b64decode(resource["content"], validate=True)) == secret

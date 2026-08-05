"""Unified tools client evidence-mode resource retrieval tests."""

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


def test_client_get_resource_by_evidence_uses_retrieve_and_decrypts(
    rbs_cli_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any, tmp_path: Path
) -> None:
    """POST evidence to retrieve and validate the complete encrypted resource output."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
    nonce = client_challenge(rbs_cli_binary, rbs_api.base_url, agent_config_path)
    evidence = client_collect_evidence(
        rbs_cli_binary, rbs_api.base_url, agent_config_path, rbc_key_material.public_key_path, nonce
    )
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
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
            "--evidence",
            f"@{evidence_path}",
            "--private-key-file",
            str(rbc_key_material.private_key_path),
        )
    )
    assert payload["uri"] == f"/rbs/v0/{uri}"
    assert payload["content_type"] == "json"
    assert json.loads(base64.b64decode(payload["content"], validate=True)) == secret

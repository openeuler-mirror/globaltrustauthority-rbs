"""RBC CLI complete lifecycle E2E test."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbc.support import run_rbc
from e2e.rbs.support import create_resource

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_cli_lifecycle_challenge_evidence_token_resource(
    rbc_binary: Path,
    rbs_api: Any,
    agent_config_path: Path,
    rbc_key_material: Any,
    tmp_path: Path,
) -> None:
    """Run every RBC CLI function in sequence and verify the final OpenBao plaintext."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)

    challenge = json.loads(
        run_rbc(
            rbc_binary,
            rbs_api.base_url,
            "--format",
            "json",
            "challenge",
            "--agent-config",
            str(agent_config_path),
        ).stdout
    )["nonce"]
    evidence = json.loads(
        run_rbc(
            rbc_binary,
            rbs_api.base_url,
            "--format",
            "json",
            "collect-evidence",
            "--agent-config",
            str(agent_config_path),
            "--nonce",
            challenge,
            "--attester-pubkey",
            f"@{rbc_key_material.public_key_path}",
        ).stdout
    )
    evidence_path = tmp_path / "lifecycle-evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    token = json.loads(
        run_rbc(
            rbc_binary,
            rbs_api.base_url,
            "--format",
            "json",
            "get-token",
            "--agent-config",
            str(agent_config_path),
            "--evidence",
            f"@{evidence_path}",
        ).stdout
    )["token"]
    resource = json.loads(
        run_rbc(
            rbc_binary,
            rbs_api.base_url,
            "--format",
            "json",
            "get-resource",
            "--agent-config",
            str(agent_config_path),
            "--uri",
            uri,
            "--attest-token",
            token,
            "--private-key-file",
            str(rbc_key_material.private_key_path),
        ).stdout
    )

    assert evidence["measurements"][0]["nonce"] == challenge
    assert token.count(".") == 2
    assert resource["uri"] == f"/rbs/v0/{uri}"
    assert json.loads(base64.b64decode(resource["content"], validate=True)) == secret

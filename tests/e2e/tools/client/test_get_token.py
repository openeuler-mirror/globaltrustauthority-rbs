"""Unified tools client token acquisition tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from e2e.tools.support import assert_cli_rejected, client_challenge, client_collect_evidence, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_client_get_token_with_evidence_returns_jwt(
    rbs_cli_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any, tmp_path: Path
) -> None:
    """Submit collected evidence through tools and validate the returned JWT contract."""
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
            "get-token",
            "--agent-config",
            str(agent_config_path),
            "--evidence",
            f"@{evidence_path}",
        )
    )
    assert set(payload) == {"token"}
    assert payload["token"].count(".") == 2


def test_client_get_token_native_flow_calls_gta_in_order(
    rbs_cli_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Run native collection and verify challenge precedes the GTA attest request."""
    before = len(rbs_api.fake_gta.requests)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "client",
            "get-token",
            "--agent-config",
            str(agent_config_path),
            "--attester-pubkey",
            f"@{rbc_key_material.public_key_path}",
        )
    )
    assert payload["token"].count(".") == 2
    requests = rbs_api.fake_gta.requests[before:]
    assert [item["method"] for item in requests] == ["GET", "POST"]


def test_client_get_token_requires_evidence_or_public_key(rbs_cli_binary: Path) -> None:
    """Reject token acquisition without either supported input mode."""
    result = run_tools(rbs_cli_binary, "http://127.0.0.1:1", "client", "get-token", check=False)
    assert_cli_rejected(result, "required")


def test_client_get_token_rejects_evidence_with_native_arguments(rbs_cli_binary: Path, tmp_path: Path) -> None:
    """Reject mutually exclusive evidence and native attester inputs."""
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "client",
        "get-token",
        "--evidence",
        f"@{evidence}",
        "--attester-pubkey",
        "key.pem",
        check=False,
    )
    assert_cli_rejected(result, "cannot be used with")

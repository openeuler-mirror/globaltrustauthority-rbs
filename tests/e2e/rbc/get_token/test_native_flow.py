"""RBC native get-token flow tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from e2e.rbc.support import assert_json_output, run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_get_token_native_flow_calls_challenge_then_gta(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Run native collection and token exchange while checking GTA request ordering."""
    before = len(rbs_api.fake_gta.requests)
    payload = assert_json_output(
        run_rbc(
            rbc_binary,
            rbs_api.base_url,
            "get-token",
            "--agent-config",
            str(agent_config_path),
            "--attester-pubkey",
            f"@{rbc_key_material.public_key_path}",
            output_format="json",
        )
    )
    assert payload["token"].count(".") == 2
    requests = rbs_api.fake_gta.requests[before:]
    assert [request["method"] for request in requests] == ["GET", "POST"]
    body = requests[1]["body"]
    evidence = body["measurements"][0]["evidences"][0]
    assert evidence["attester_type"] == "tpm"
    assert body["measurements"][0]["nonce"]

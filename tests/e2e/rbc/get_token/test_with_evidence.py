"""RBC get-token evidence-input success tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from e2e.rbc.support import assert_json_output, collect_tpm_evidence, run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def _claims(token: str) -> dict[str, Any]:
    """Decode the JWT payload without treating it as a trust decision."""
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def test_get_token_submits_collected_evidence_and_returns_complete_jwt(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any, tmp_path: Path
) -> None:
    """Exchange a native evidence document through real RBS and validate token claims."""
    evidence = collect_tpm_evidence(
        rbc_binary, rbs_api.base_url, agent_config_path, rbc_key_material.public_key_path
    )
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "get-token",
        "--agent-config",
        str(agent_config_path),
        "--evidence",
        f"@{evidence_path}",
        output_format="json",
    )
    payload = assert_json_output(result)
    assert set(payload) == {"token"}
    token = payload["token"]
    assert isinstance(token, str) and token.count(".") == 2
    claims = _claims(token)
    assert claims["attester_data"]["runtime_data"]["tee-pubkey"]["kty"] == "RSA"


def test_get_token_preserves_json_output_in_a_file(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any, tmp_path: Path
) -> None:
    """Write the token response to a file while keeping the explicit JSON contract."""
    evidence = collect_tpm_evidence(
        rbc_binary, rbs_api.base_url, agent_config_path, rbc_key_material.public_key_path
    )
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    output_file = tmp_path / "token.json"
    run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "get-token",
        "--agent-config",
        str(agent_config_path),
        "--evidence",
        f"@{evidence_path}",
        output_format="json",
        output_file=output_file,
    )
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert set(payload) == {"token"}
    assert payload["token"].count(".") == 2

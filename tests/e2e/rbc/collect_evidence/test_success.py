"""RBC native evidence collection success tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from e2e.rbc.support import assert_json_output, collect_tpm_evidence, run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_collect_evidence_wraps_tpm_fixture_with_nonce(
    rbc_binary: Path,
    rbs_api: Any,
    agent_config_path: Path,
    rbc_key_material: Any,
    repo_root: Path,
) -> None:
    """Load the test-only TPM SO and validate the complete evidence envelope."""
    payload = collect_tpm_evidence(
        rbc_binary, rbs_api.base_url, agent_config_path, rbc_key_material.public_key_path
    )
    assert set(payload) == {"agent_version", "measurements"}
    assert isinstance(payload["agent_version"], str) and payload["agent_version"]
    measurements = payload["measurements"]
    assert isinstance(measurements, list) and len(measurements) == 1
    measurement = measurements[0]
    assert set(measurement) == {"node_id", "nonce", "nonce_type", "attester_data", "evidences"}
    assert measurement["node_id"] == "e2e-node"
    assert measurement["nonce"]
    assert measurement["nonce_type"] == "verifier"
    assert measurement["attester_data"]["runtime_data"]["tee-pubkey"]["kty"] == "RSA"
    assert len(measurement["evidences"]) == 1
    evidence = measurement["evidences"][0]
    assert set(evidence) == {"attester_type", "mode", "evidence"}
    assert evidence["attester_type"] == "tpm"
    assert evidence["mode"] == "host"
    assert set(evidence["evidence"]) == {"ak_certs", "quote", "pcrs", "logs"}
    fixture = json.loads(
        (
            repo_root
            / "tests"
            / "fixtures"
            / "tpm_attester"
            / "data"
            / "tpm_evidence.json"
        ).read_text(encoding="utf-8")
    )
    expected_pcrs = {
        entry["pcr_index"]: entry["pcr_value"]
        for entry in fixture["pcrs"]["pcr_values"]
        if entry["pcr_index"] <= 7
    }
    actual_pcrs = {
        entry["pcr_index"]: entry["pcr_value"]
        for entry in evidence["evidence"]["pcrs"]["pcr_values"]
    }
    assert actual_pcrs == expected_pcrs
    assert [entry["log_type"] for entry in evidence["evidence"]["logs"]] == [
        "ima_log",
        "dim_log",
        "boot_log",
    ]


def test_collect_evidence_can_write_json_to_a_file(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any, tmp_path: Path
) -> None:
    """Keep the command's machine-readable evidence contract usable through file output."""
    challenge = assert_json_output(
        run_rbc(
            rbc_binary,
            rbs_api.base_url,
            "challenge",
            "--agent-config",
            str(agent_config_path),
            output_format="json",
        )
    )["nonce"]
    output_file = tmp_path / "evidence.json"
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "collect-evidence",
        "--agent-config",
        str(agent_config_path),
        "--nonce",
        str(challenge),
        "--attester-pubkey",
        f"@{rbc_key_material.public_key_path}",
        output_format="json",
        output_file=output_file,
    )
    assert result.returncode == 0
    assert "output written to" in result.stderr.lower()
    saved = json.loads(output_file.read_text(encoding="utf-8"))
    assert saved["measurements"][0]["nonce"] == challenge

"""Unified tools client evidence collection tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from e2e.tools.support import assert_cli_rejected, client_challenge, client_collect_evidence, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_client_collect_evidence_validates_complete_tpm_envelope(
    rbs_cli_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Collect TPM evidence through the unified CLI and validate every stable envelope field."""
    nonce = client_challenge(rbs_cli_binary, rbs_api.base_url, agent_config_path)
    payload = client_collect_evidence(
        rbs_cli_binary, rbs_api.base_url, agent_config_path, rbc_key_material.public_key_path, nonce
    )
    assert payload["agent_version"]
    measurement = payload["measurements"][0]
    assert set(measurement) == {"node_id", "nonce", "nonce_type", "attester_data", "evidences"}
    assert measurement["nonce"] == nonce
    evidence = measurement["evidences"][0]
    assert evidence["attester_type"] == "tpm"
    assert evidence["mode"] == "host"
    assert set(evidence["evidence"]) == {"ak_certs", "quote", "pcrs", "logs"}


def test_client_collect_evidence_requires_nonce_and_public_key(rbs_cli_binary: Path) -> None:
    """Reject missing required collection parameters at the CLI boundary."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "client",
        "collect-evidence",
        check=False,
    )
    assert_cli_rejected(result, "required")


def test_client_collect_evidence_rejects_invalid_runtime_data(rbs_cli_binary: Path) -> None:
    """Reject malformed runtime-data entries without a service request."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "client",
        "collect-evidence",
        "--nonce",
        "nonce",
        "--attester-pubkey",
        "key.pem",
        "--runtime-data",
        "missing-equals",
        check=False,
    )
    assert_cli_rejected(result, "runtime-data", "key=value")

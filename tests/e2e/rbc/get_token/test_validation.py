"""RBC get-token argument validation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from e2e.rbc.support import assert_cli_rejected, run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_get_token_requires_evidence_or_attester_public_key(rbc_binary: Path) -> None:
    """Reject a token request with neither supported token input mode."""
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "get-token",
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "required")


def test_get_token_rejects_evidence_with_native_inputs(rbc_binary: Path, tmp_path: Path) -> None:
    """Reject mutually exclusive evidence and native attester arguments."""
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({"measurements": []}), encoding="utf-8")
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "get-token",
        "--evidence",
        f"@{evidence}",
        "--attester-pubkey",
        "key.pem",
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "cannot be used with")


def test_get_token_rejects_invalid_evidence_json(rbc_binary: Path, tmp_path: Path) -> None:
    """Reject malformed evidence input before making an attest request."""
    evidence = tmp_path / "invalid.json"
    evidence.write_text("{invalid", encoding="utf-8")
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "get-token",
        "--evidence",
        f"@{evidence}",
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "json")

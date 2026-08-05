"""RBC native evidence collection parameter validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from e2e.rbc.support import assert_cli_rejected, run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_collect_evidence_requires_nonce_and_attester_public_key(rbc_binary: Path) -> None:
    """Reject missing required collection arguments before loading the provider."""
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "collect-evidence",
        "--nonce",
        "",
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "value is empty")


def test_collect_evidence_rejects_runtime_data_without_key_value(rbc_binary: Path) -> None:
    """Reject malformed repeated runtime-data entries without a network request."""
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "collect-evidence",
        "--nonce",
        "nonce",
        "--attester-pubkey",
        "missing.pem",
        "--runtime-data",
        "not-a-key-value",
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "runtime-data", "key=value")


def test_collect_evidence_rejects_invalid_attester_data_json(rbc_binary: Path, tmp_path: Path) -> None:
    """Reject malformed attester-data JSON before invoking tpm_boot collection."""
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{invalid", encoding="utf-8")
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "collect-evidence",
        "--nonce",
        "nonce",
        "--attester-pubkey",
        "missing.pem",
        "--attester-data",
        f"@{invalid}",
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "invalid attester-data json")

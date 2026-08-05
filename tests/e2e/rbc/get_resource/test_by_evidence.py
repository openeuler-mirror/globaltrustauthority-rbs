"""RBC evidence-authorized resource retrieval tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbc.support import assert_resource_output, collect_tpm_evidence, run_rbc
from e2e.rbs.support import create_resource

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_get_resource_by_evidence_posts_retrieve_and_decrypts(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any, tmp_path: Path
) -> None:
    """POST collected TPM evidence to RBS retrieve and validate the returned plaintext."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
    evidence = collect_tpm_evidence(
        rbc_binary, rbs_api.base_url, agent_config_path, rbc_key_material.public_key_path
    )
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "get-resource",
        "--agent-config",
        str(agent_config_path),
        "--uri",
        uri,
        "--evidence",
        f"@{evidence_path}",
        "--private-key-file",
        str(rbc_key_material.private_key_path),
        output_format="json",
    )
    assert_resource_output(result, uri, secret)


def test_get_resource_by_evidence_maps_gta_failure_to_server_error(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any, tmp_path: Path
) -> None:
    """Map a retrieve-time GTA failure to a sanitized server error."""
    with httpx.Client(trust_env=False) as client:
        uri, _, _ = create_resource(client, rbs_api)
    evidence = collect_tpm_evidence(
        rbc_binary, rbs_api.base_url, agent_config_path, rbc_key_material.public_key_path
    )
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    rbs_api.fake_gta.fail_next_attest(message="do not leak retrieve detail")
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "get-resource",
        "--agent-config",
        str(agent_config_path),
        "--uri",
        uri,
        "--evidence",
        f"@{evidence_path}",
        "--private-key-file",
        str(rbc_key_material.private_key_path),
        output_format="json",
        check=False,
    )
    assert result.returncode != 0
    assert "servererror" in result.stderr.lower()
    assert "do not leak retrieve detail" not in result.stderr.lower()

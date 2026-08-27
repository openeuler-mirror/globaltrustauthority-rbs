"""RBC protected-resource error mapping tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbc.support import run_rbc
from e2e.rbs.support import create_resource

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_get_resource_maps_invalid_attest_token_to_auth_error(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Map RBS's 401 response for a malformed Attest token to a stable CLI category."""
    with httpx.Client(trust_env=False) as client:
        uri, _, _ = create_resource(client, rbs_api)
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "get-resource",
        "--agent-config",
        str(agent_config_path),
        "--uri",
        uri,
        "--attest-token",
        "not-a-jwt",
        "--private-key-file",
        str(rbc_key_material.private_key_path),
        output_format="json",
        check=False,
    )
    assert result.returncode != 0
    assert "autherror" in result.stderr.lower()


def test_get_resource_maps_unknown_resource_to_not_found(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Map an RBS 404 to the resource-not-found category, mentioning both possible causes.

    RBS folds "missing" and "policy denied" into one 404 whose body names both
    causes ("resource not found or access denied"); the CLI output carries that
    body through verbatim.
    """
    token = rbs_api.fake_gta.issue_token(
        {"attester_data": {"runtime_data": {"tee-pubkey": rbc_key_material.public_jwk}}}
    )
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "get-resource",
        "--agent-config",
        str(agent_config_path),
        "--uri",
        "vault/default/secret/does-not-exist",
        "--attest-token",
        token,
        "--private-key-file",
        str(rbc_key_material.private_key_path),
        output_format="json",
        check=False,
    )
    assert result.returncode != 0
    assert "resource not found" in result.stderr.lower()
    assert "access denied" in result.stderr.lower()

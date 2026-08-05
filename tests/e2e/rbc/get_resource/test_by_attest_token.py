"""RBC token-authorized resource retrieval tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbc.support import assert_resource_output, run_rbc
from e2e.rbs.support import create_resource

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_get_resource_by_attest_token_decrypts_exact_openbao_value(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Fetch a resource with an Attest JWT and validate the complete decrypted output."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
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
        uri,
        "--attest-token",
        token,
        "--private-key-file",
        str(rbc_key_material.private_key_path),
        output_format="json",
    )
    assert_resource_output(result, uri, secret)


def test_get_resource_by_attest_token_supports_text_output(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Render a token-authorized resource response in text mode."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
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
        uri,
        "--attest-token",
        token,
        "--private-key-file",
        str(rbc_key_material.private_key_path),
        output_format="text",
    )
    assert result.returncode == 0
    assert secret["value"] in result.stdout

"""RBC protected-resource command validation tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from e2e.rbc.support import assert_cli_rejected, run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_get_resource_requires_exactly_one_authentication_mode(rbc_binary: Path) -> None:
    """Reject a resource request that does not select token, evidence, passport, or background."""
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "get-resource",
        "--uri",
        "vault/default/secret/demo",
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "required")


def test_get_resource_rejects_multiple_authentication_modes(rbc_binary: Path) -> None:
    """Reject simultaneous token and evidence authorization inputs."""
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "get-resource",
        "--uri",
        "vault/default/secret/demo",
        "--attest-token",
        "token",
        "--evidence",
        "{}",
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "cannot be used with")


def test_get_resource_rejects_passport_with_private_key(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, rbc_key_material: Any
) -> None:
    """Reject a caller key that conflicts with passport's ephemeral session key."""
    result = run_rbc(
        rbc_binary,
        "http://127.0.0.1:1",
        "get-resource",
        "--agent-config",
        str(agent_config_path),
        "--uri",
        "vault/default/secret/demo",
        "--passport",
        "--private-key-file",
        str(rbc_key_material.private_key_path),
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "cannot be used with")


def test_get_resource_rejects_ambiguous_uri_before_network(rbc_binary: Path, rbs_api: Any, agent_config_path: Path) -> None:
    """Reject traversal and percent-encoded URI syntax in the RBC REST client."""
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "get-resource",
        "--agent-config",
        str(agent_config_path),
        "--uri",
        "vault/default/secret/../admin%2Fkey",
        "--attest-token",
        "token",
        output_format="json",
        check=False,
    )
    assert_cli_rejected(result, "resource uri must not")

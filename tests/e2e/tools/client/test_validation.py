"""Unified tools client resource argument validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from e2e.tools.support import assert_cli_rejected, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_client_get_resource_requires_one_authentication_mode(rbs_cli_binary: Path) -> None:
    """Reject a resource request without token, evidence, passport, or background."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "client",
        "get-resource",
        "--uri",
        "vault/default/secret/demo",
        check=False,
    )
    assert_cli_rejected(result, "required")


def test_client_get_resource_rejects_conflicting_modes(rbs_cli_binary: Path) -> None:
    """Reject token, evidence, and passport inputs used together."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "client",
        "get-resource",
        "--uri",
        "vault/default/secret/demo",
        "--attest-token",
        "token",
        "--evidence",
        "{}",
        "--passport",
        check=False,
    )
    assert_cli_rejected(result, "cannot be used with")


def test_client_get_resource_rejects_passport_with_private_key(
    rbs_cli_binary: Path, rbs_api: object, agent_config_path: Path, rbc_key_material: object
) -> None:
    """Reject a caller-provided key with passport's ephemeral key mode."""
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "client",
        "get-resource",
        "--agent-config",
        str(agent_config_path),
        "--uri",
        "vault/default/secret/demo",
        "--passport",
        "--private-key-file",
        str(rbc_key_material.private_key_path),
        check=False,
    )
    assert_cli_rejected(result, "cannot be used with")

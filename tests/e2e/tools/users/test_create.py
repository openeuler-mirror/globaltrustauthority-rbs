"""Unified tools user create tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from e2e.rbs.support import assert_user, unique_name
from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_user_create_with_jwk_returns_complete_user_contract(
    rbs_cli_binary: Path, rbs_api: Any, rbc_key_material: Any, tmp_path: Path
) -> None:
    """Create a user from a JWK file and validate identity, role, status, and timestamps."""
    username = unique_name("tooluser")
    jwk_path = tmp_path / "user.jwk"
    jwk_path.write_text(json.dumps(rbc_key_material.public_jwk), encoding="utf-8")
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "user",
            "create",
            "--username",
            username,
            "--jwk",
            f"@{jwk_path}",
            token=rbs_api.admin_token,
        )
    )
    assert_user(payload, username=username, role="user", enabled=True)


def test_user_create_requires_exactly_one_key_input(rbs_cli_binary: Path, tmp_path: Path) -> None:
    """Reject user creation without a key or with both key forms."""
    missing = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "user",
        "create",
        "--username",
        "missing-key",
        token="token",
        check=False,
    )
    assert_cli_rejected(missing, "required")
    jwk = tmp_path / "key.jwk"
    jwk.write_text("{}", encoding="utf-8")
    both = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "user",
        "create",
        "--username",
        "both-keys",
        "--jwk",
        f"@{jwk}",
        "--public-key",
        "pem",
        token="token",
        check=False,
    )
    assert_cli_rejected(both, "cannot be used with")


def test_user_create_rejects_invalid_username(rbs_cli_binary: Path, rbc_key_material: Any, tmp_path: Path) -> None:
    """Reject usernames containing path/control characters."""
    jwk = tmp_path / "key.jwk"
    jwk.write_text(json.dumps(rbc_key_material.public_jwk), encoding="utf-8")
    result = run_tools(
        rbs_cli_binary,
        "http://127.0.0.1:1",
        "user",
        "create",
        "--username",
        "../admin",
        "--jwk",
        f"@{jwk}",
        token="token",
        check=False,
    )
    assert_cli_rejected(result, "username")

"""Unified tools token generation tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from e2e.tools.support import assert_cli_rejected, json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def _decode_segment(segment: str) -> dict[str, Any]:
    """Decode one JWT JSON segment for structural assertions."""
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def test_token_generate_returns_signed_ps256_token_with_merged_claims(
    rbs_cli_binary: Path, rbs_api: Any, tmp_path: Path
) -> None:
    """Generate a PS256 JWT and validate standard and custom claims."""
    claims_path = tmp_path / "claims.json"
    claims_path.write_text('{"scope":"e2e-tools"}', encoding="utf-8")
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "token",
            "gen",
            "--private-key-file",
            str(rbs_api.encryption_private_key_path),
            "--alg",
            "PS256",
            "--iss",
            "e2e-tools",
            "--sub",
            "tools-user",
            "--claims",
            f"@{claims_path}",
        )
    )
    assert set(payload) == {"token"}
    token = payload["token"]
    assert isinstance(token, str) and token.count(".") == 2
    assert _decode_segment(token.split(".")[0])["alg"] == "PS256"
    claims = _decode_segment(token.split(".")[1])
    assert claims["iss"] == "e2e-tools"
    assert claims["sub"] == "tools-user"
    assert claims["scope"] == "e2e-tools"
    assert isinstance(claims["exp"], int)


def test_token_generate_rejects_invalid_claims_json(rbs_cli_binary: Path, rbs_api: Any, tmp_path: Path) -> None:
    """Reject malformed custom claims before signing or network access."""
    claims = tmp_path / "invalid.json"
    claims.write_text("{invalid", encoding="utf-8")
    result = run_tools(
        rbs_cli_binary,
        rbs_api.base_url,
        "token",
        "gen",
        "--private-key-file",
        str(rbs_api.encryption_private_key_path),
        "--claims",
        f"@{claims}",
        check=False,
    )
    assert_cli_rejected(result, "json")

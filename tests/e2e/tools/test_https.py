"""Unified tools HTTPS transport and protected-resource tests."""

from __future__ import annotations

import base64
import json
import ssl
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import create_resource
from e2e.tools.support import json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


@pytest.fixture
def wrong_ca_cert(tmp_path: Path) -> Path:
    """Generate a CA that does not trust the E2E HTTPS server certificate."""
    wrong_cert = tmp_path / "wrong-ca.crt"
    wrong_key = tmp_path / "wrong-ca.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(wrong_key),
            "-out",
            str(wrong_cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=wrong-ca",
        ],
        check=True,
        capture_output=True,
    )
    return wrong_cert


def _assert_certificate_rejected(result: subprocess.CompletedProcess[str]) -> None:
    """Require a certificate-verification failure, not a generic connection failure."""
    assert result.returncode != 0
    diagnostic = f"{result.stdout}\n{result.stderr}".lower()
    assert "connection refused" not in diagnostic, diagnostic
    assert "connection reset" not in diagnostic, diagnostic
    assert (
        "certificate" in diagnostic
        or "unknownissuer" in diagnostic
        or "unknown issuer" in diagnostic
    ), diagnostic


def test_tools_client_challenge_accepts_configured_ca(
    rbs_cli_binary: Path, https_rbc_tools_environment: Any, https_agent_config_path: Path
) -> None:
    """Use --cert with the real CA for the client challenge command."""
    result = run_tools(
        rbs_cli_binary,
        https_rbc_tools_environment.base_url,
        "client",
        "challenge",
        "--agent-config",
        str(https_agent_config_path),
        cert=https_rbc_tools_environment.ca_cert_path,
    )
    payload = json_output(result)
    assert set(payload) == {"nonce"}
    assert base64.b64decode(payload["nonce"], validate=True)


def test_tools_rejects_wrong_ca(
    rbs_cli_binary: Path,
    https_rbc_tools_environment: Any,
    https_agent_config_path: Path,
    wrong_ca_cert: Path,
) -> None:
    """Reject the HTTPS server when --cert points to an unrelated CA."""
    result = run_tools(
        rbs_cli_binary,
        https_rbc_tools_environment.base_url,
        "client",
        "challenge",
        "--agent-config",
        str(https_agent_config_path),
        cert=wrong_ca_cert,
        check=False,
    )
    _assert_certificate_rejected(result)


def test_tools_rejects_missing_ca(
    rbs_cli_binary: Path, https_rbc_tools_environment: Any, https_agent_config_path: Path
) -> None:
    """Reject the self-signed HTTPS server when --cert is omitted."""
    result = run_tools(
        rbs_cli_binary,
        https_rbc_tools_environment.base_url,
        "client",
        "challenge",
        "--agent-config",
        str(https_agent_config_path),
        check=False,
    )
    _assert_certificate_rejected(result)


def test_tools_https_resource_flow(
    rbs_cli_binary: Path,
    https_rbc_tools_environment: Any,
    rbc_key_material: Any,
) -> None:
    """Create and decrypt a resource through tools while every RBS request uses HTTPS."""
    verify = https_rbc_tools_environment.ca_cert_path
    tls_context = ssl.create_default_context(cafile=str(verify))
    with httpx.Client(verify=tls_context, trust_env=False) as client:
        uri, _, secret = create_resource(client, https_rbc_tools_environment)
    token = https_rbc_tools_environment.fake_gta.issue_bearer_token(rbc_key_material.public_jwk)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            https_rbc_tools_environment.base_url,
            "res",
            "get",
            "--uri",
            uri,
            "--private-key-file",
            str(rbc_key_material.private_key_path),
            token=token,
            cert=verify,
        )
    )
    assert payload["uri"] == f"/rbs/v0/{uri}"
    assert payload["content_type"] == "json"
    assert payload["export_mode"] == "jwe"
    assert json.loads(base64.b64decode(payload["content"], validate=True)) == secret

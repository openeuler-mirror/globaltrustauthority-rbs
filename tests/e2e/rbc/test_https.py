"""RBC HTTPS transport, certificate validation, and resource-flow tests."""

from __future__ import annotations

import base64
import json
import ssl
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbc.support import run_rbc
from e2e.rbs.support import create_resource

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


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


def test_rbc_challenge_accepts_configured_ca(
    rbc_binary: Path, https_rbc_tools_environment: Any, https_agent_config_path: Path
) -> None:
    """Use --cert with the real CA and verify the HTTPS challenge response."""
    result = run_rbc(
        rbc_binary,
        https_rbc_tools_environment.base_url,
        "--cert",
        str(https_rbc_tools_environment.ca_cert_path),
        "--format",
        "json",
        "challenge",
        "--agent-config",
        str(https_agent_config_path),
    )
    payload = json.loads(result.stdout)
    assert set(payload) == {"nonce"}
    assert base64.b64decode(payload["nonce"], validate=True)


def test_rbc_rejects_wrong_ca(
    rbc_binary: Path,
    https_rbc_tools_environment: Any,
    https_agent_config_path: Path,
    wrong_ca_cert: Path,
) -> None:
    """Reject the HTTPS server when --cert points to an unrelated CA."""
    result = run_rbc(
        rbc_binary,
        https_rbc_tools_environment.base_url,
        "--cert",
        str(wrong_ca_cert),
        "challenge",
        "--agent-config",
        str(https_agent_config_path),
        check=False,
    )
    _assert_certificate_rejected(result)


def test_rbc_rejects_missing_ca(
    rbc_binary: Path, https_rbc_tools_environment: Any, https_agent_config_path: Path
) -> None:
    """Reject the self-signed HTTPS server when --cert is omitted."""
    result = run_rbc(
        rbc_binary,
        https_rbc_tools_environment.base_url,
        "challenge",
        "--agent-config",
        str(https_agent_config_path),
        check=False,
    )
    _assert_certificate_rejected(result)


def test_rbc_https_resource_flow(
    rbc_binary: Path,
    https_rbc_tools_environment: Any,
    https_agent_config_path: Path,
    rbc_key_material: Any,
    tmp_path: Path,
) -> None:
    """Run challenge, evidence, token, and decrypted resource retrieval entirely over HTTPS."""
    verify = https_rbc_tools_environment.ca_cert_path
    tls_context = ssl.create_default_context(cafile=str(verify))
    with httpx.Client(verify=tls_context, trust_env=False) as client:
        uri, _, secret = create_resource(client, https_rbc_tools_environment)

    challenge = json.loads(
        run_rbc(
            rbc_binary,
            https_rbc_tools_environment.base_url,
            "--cert",
            str(verify),
            "--format",
            "json",
            "challenge",
            "--agent-config",
            str(https_agent_config_path),
        ).stdout
    )["nonce"]
    evidence = json.loads(
        run_rbc(
            rbc_binary,
            https_rbc_tools_environment.base_url,
            "--cert",
            str(verify),
            "--format",
            "json",
            "collect-evidence",
            "--agent-config",
            str(https_agent_config_path),
            "--nonce",
            challenge,
            "--attester-pubkey",
            f"@{rbc_key_material.public_key_path}",
        ).stdout
    )
    evidence_path = tmp_path / "https-evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    token = json.loads(
        run_rbc(
            rbc_binary,
            https_rbc_tools_environment.base_url,
            "--cert",
            str(verify),
            "--format",
            "json",
            "get-token",
            "--agent-config",
            str(https_agent_config_path),
            "--evidence",
            f"@{evidence_path}",
        ).stdout
    )["token"]
    resource = json.loads(
        run_rbc(
            rbc_binary,
            https_rbc_tools_environment.base_url,
            "--cert",
            str(verify),
            "--format",
            "json",
            "get-resource",
            "--agent-config",
            str(https_agent_config_path),
            "--uri",
            uri,
            "--attest-token",
            token,
            "--private-key-file",
            str(rbc_key_material.private_key_path),
        ).stdout
    )
    assert resource["uri"] == f"/rbs/v0/{uri}"
    assert json.loads(base64.b64decode(resource["content"], validate=True)) == secret

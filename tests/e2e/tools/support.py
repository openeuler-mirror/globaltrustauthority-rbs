"""Helpers for invoking the real unified rbs-cli binary."""

from __future__ import annotations

import json
import os
import subprocess
import base64
from pathlib import Path
from typing import Any


def run_tools(
    binary: Path,
    base_url: str,
    *args: str,
    token: str | None = None,
    check: bool = True,
    output_format: str = "json",
    output_file: Path | None = None,
    cert: Path | None = None,
    noout: bool = False,
    quiet: bool = False,
    verbose: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run rbs-cli with selected output controls and no inherited HTTP proxy."""
    command = [str(binary), "--base-url", base_url, "--format", output_format]
    if token is not None:
        command.extend(["--token", token])
    if output_file is not None:
        command.extend(["--output-file", str(output_file)])
    if cert is not None:
        command.extend(["--cert", str(cert)])
    if noout:
        command.append("--noout")
    if quiet:
        command.append("--quiet")
    if verbose:
        command.append("--verbose")
    command.extend(args)
    env = dict(os.environ)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(name, None)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60, env=env)
    if check and result.returncode != 0:
        raise RuntimeError(f"rbs-cli exited with {result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}")
    return result


def assert_cli_rejected(
    result: subprocess.CompletedProcess[str],
    *expected_fragments: str,
) -> None:
    """Assert parser/configuration rejection without a network failure."""
    assert result.returncode != 0
    diagnostic = f"{result.stdout}\n{result.stderr}".lower()
    assert "unable to connect to the service" not in diagnostic
    assert "connection refused" not in diagnostic
    for fragment in expected_fragments:
        assert fragment.lower() in diagnostic, diagnostic


def text_output(result: subprocess.CompletedProcess[str]) -> str:
    """Return one non-empty text CLI response."""
    assert result.returncode == 0
    assert result.stdout.strip()
    return result.stdout.strip()


def client_challenge(binary: Path, base_url: str, agent_config: Path) -> str:
    """Run tools client challenge and return its base64 nonce."""
    payload = json_output(
        run_tools(binary, base_url, "client", "challenge", "--agent-config", str(agent_config))
    )
    assert set(payload) == {"nonce"}
    nonce = payload["nonce"]
    assert isinstance(nonce, str) and nonce
    assert base64.b64decode(nonce, validate=True).decode("utf-8").startswith("e2e-nonce-")
    return nonce


def client_collect_evidence(
    binary: Path,
    base_url: str,
    agent_config: Path,
    public_key: Path,
    nonce: str,
) -> dict[str, Any]:
    """Run tools client evidence collection and return its structured envelope."""
    payload = json_output(
        run_tools(
            binary,
            base_url,
            "client",
            "collect-evidence",
            "--agent-config",
            str(agent_config),
            "--nonce",
            nonce,
            "--attester-pubkey",
            f"@{public_key}",
        )
    )
    assert set(payload) == {"agent_version", "measurements"}
    return payload


def assert_resource_metadata(payload: dict[str, Any], *, uri: str, policy_id: str) -> None:
    """Assert tools' exact prefixed resource URI plus the complete RBS metadata contract."""
    from e2e.rbs.support import assert_resource

    expected_uri = f"/rbs/v0/{uri}"
    assert payload.get("uri") == expected_uri
    assert_resource(payload, uri=expected_uri, policy_id=policy_id)


def json_output(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Parse one successful JSON CLI response."""
    return json.loads(result.stdout)

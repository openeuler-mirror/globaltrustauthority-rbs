"""Process helpers shared by RBC E2E tests."""

from __future__ import annotations

import os
import json
import subprocess
import base64
from pathlib import Path
from typing import Any


def run_rbc(
    binary: Path,
    base_url: str,
    *args: str,
    check: bool = True,
    env: dict[str, str] | None = None,
    output_format: str | None = None,
    output_file: Path | None = None,
    cert: Path | None = None,
    noout: bool = False,
    quiet: bool = False,
    verbose: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the real rbc-cli binary without inheriting proxy configuration."""
    command = [str(binary), "--base-url", base_url]
    if output_format is not None:
        command.extend(["--format", output_format])
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
    process_env: dict[str, str] = dict(os.environ)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        process_env.pop(name, None)
    process_env["NO_PROXY"] = "127.0.0.1,localhost"
    if env is not None:
        process_env.update(env)
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=process_env,
        timeout=60,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"rbc-cli exited with {result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    return result


def assert_cli_rejected(
    result: subprocess.CompletedProcess[str],
    *expected_fragments: str,
) -> None:
    """Assert parser/configuration rejection and a stable diagnostic fragment."""
    assert result.returncode != 0
    diagnostic = f"{result.stdout}\n{result.stderr}".lower()
    assert "connection refused" not in diagnostic
    assert "connection reset" not in diagnostic
    for fragment in expected_fragments:
        assert fragment.lower() in diagnostic, diagnostic


def assert_json_output(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    """Parse one successful JSON response and require a non-empty stdout payload."""
    assert result.returncode == 0
    assert result.stdout.strip()
    return json.loads(result.stdout)


def assert_resource_output(
    result: subprocess.CompletedProcess[str],
    uri: str,
    secret: dict[str, str],
) -> dict[str, object]:
    """Validate the complete RBC resource output and its decrypted JSON payload."""
    payload = assert_json_output(result)
    assert set(payload) == {"uri", "content", "content_type"}
    assert payload["uri"] == f"/rbs/v0/{uri}"
    assert payload["content_type"] == "json"
    decoded = base64.b64decode(payload["content"], validate=True)
    assert json.loads(decoded) == secret
    return payload


def collect_tpm_evidence(
    binary: Path,
    base_url: str,
    agent_config: Path,
    public_key: Path,
) -> dict[str, object]:
    """Collect one native TPM evidence document through rbc-cli."""
    challenge = json.loads(
        run_rbc(
            binary,
            base_url,
            "--format",
            "json",
            "challenge",
            "--agent-config",
            str(agent_config),
        ).stdout
    )["nonce"]
    result = run_rbc(
        binary,
        base_url,
        "--format",
        "json",
        "collect-evidence",
        "--agent-config",
        str(agent_config),
        "--nonce",
        challenge,
        "--attester-pubkey",
        f"@{public_key}",
    )
    return json.loads(result.stdout)

"""Black-box tests for RBC CLI global output and input options."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from e2e.rbc.support import assert_cli_rejected, run_rbc

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_rbc_quiet_suppresses_success_output(rbc_binary: Path, rbs_api: Any, agent_config_path: Path) -> None:
    """The quiet flag suppresses stdout for a successful challenge."""
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "challenge",
        "--agent-config",
        str(agent_config_path),
        quiet=True,
    )
    assert result.returncode == 0
    assert result.stdout == ""


def test_rbc_noout_suppresses_stdout_but_writes_file(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path, tmp_path: Path
) -> None:
    """The noout flag leaves stdout empty while writing the challenge response."""
    output_path = tmp_path / "challenge.txt"
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "challenge",
        "--agent-config",
        str(agent_config_path),
        output_file=output_path,
        noout=True,
    )
    assert result.stdout == ""
    assert output_path.read_text(encoding="utf-8").strip()


def test_rbc_verbose_emits_diagnostic_logging(rbc_binary: Path, rbs_api: Any, agent_config_path: Path) -> None:
    """The verbose flag enables startup diagnostics without changing the challenge result."""
    normal = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "challenge",
        "--agent-config",
        str(agent_config_path),
    )
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "challenge",
        "--agent-config",
        str(agent_config_path),
        verbose=True,
    )
    assert result.returncode == 0
    assert result.stdout.strip()
    assert normal.stderr == ""
    assert result.stderr.strip()


def test_rbc_rejects_invalid_global_inputs(rbc_binary: Path, rbs_api: Any, agent_config_path: Path, tmp_path: Path) -> None:
    """Reject malformed URL, certificate, and output path during argument parsing."""
    result = run_rbc(
        rbc_binary,
        "not a url",
        "challenge",
        "--agent-config",
        str(agent_config_path),
        check=False,
    )
    assert_cli_rejected(result, "invalid base url")
    for args, fragments in [
        (("--cert", str(tmp_path / "missing-ca.pem"), "challenge"), ("read ca cert",)),
        (("--output-file", str(tmp_path), "challenge"), ("existing directory",)),
    ]:
        result = run_rbc(
            rbc_binary,
            rbs_api.base_url,
            *args,
            "--agent-config",
            str(agent_config_path),
            check=False,
        )
        assert_cli_rejected(result, *fragments)

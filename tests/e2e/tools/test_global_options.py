"""Black-box tests for unified CLI global output and input options."""

from __future__ import annotations

from pathlib import Path

import pytest

from e2e.tools.support import assert_cli_rejected, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_tools_quiet_suppresses_success_output(rbs_cli_binary: Path, rbs_api: object) -> None:
    """The quiet flag suppresses stdout for a successful command."""
    result = run_tools(rbs_cli_binary, rbs_api.base_url, "version", quiet=True)
    assert result.returncode == 0
    assert result.stdout == ""


def test_tools_noout_suppresses_stdout_but_writes_file(
    rbs_cli_binary: Path, rbs_api: object, tmp_path: Path
) -> None:
    """The noout flag leaves stdout empty while preserving output-file content."""
    output_path = tmp_path / "version.json"
    result = run_tools(
        rbs_cli_binary,
        rbs_api.base_url,
        "version",
        output_file=output_path,
        noout=True,
    )
    assert result.stdout == ""
    assert '"name": "rbs-cli"' in output_path.read_text(encoding="utf-8")


def test_tools_verbose_emits_diagnostic_logging(rbs_cli_binary: Path, rbs_api: object) -> None:
    """The verbose flag enables startup diagnostics without changing the result."""
    normal = run_tools(rbs_cli_binary, rbs_api.base_url, "version")
    result = run_tools(rbs_cli_binary, rbs_api.base_url, "version", verbose=True)
    assert result.returncode == 0
    assert result.stdout
    assert normal.stderr == ""
    assert result.stderr.strip()


def test_tools_rejects_invalid_global_inputs(rbs_cli_binary: Path, rbs_api: object, tmp_path: Path) -> None:
    """Reject malformed URL, token, certificate, and output path before network dispatch."""
    result = run_tools(rbs_cli_binary, "not a url", "version", check=False)
    assert_cli_rejected(result, "invalid url")
    for args, fragments in [
        (("--token", "", "version"), ("value is empty",)),
        (("--cert", str(tmp_path / "missing-ca.pem"), "version"), ("unable to access",)),
        (("--output-file", str(tmp_path), "version"), ("existing directory",)),
    ]:
        result = run_tools(rbs_cli_binary, rbs_api.base_url, *args, check=False)
        assert_cli_rejected(result, *fragments)

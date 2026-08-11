"""RBC background-check resource retrieval tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbc.support import assert_resource_output, run_rbc
from e2e.rbs.support import create_resource

pytestmark = [pytest.mark.e2e, pytest.mark.rbc]


def test_get_resource_background_posts_inline_evidence_with_ephemeral_key(
    rbc_binary: Path, rbs_api: Any, agent_config_path: Path
) -> None:
    """Run background challenge, evidence collection, retrieve, and decryption as one command."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
    result = run_rbc(
        rbc_binary,
        rbs_api.base_url,
        "get-resource",
        "--agent-config",
        str(agent_config_path),
        "--uri",
        uri,
        "--background",
        output_format="json",
    )
    assert_resource_output(result, uri, secret)

"""Unified tools client passport resource retrieval tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from e2e.rbs.support import create_resource
from e2e.tools.support import json_output, run_tools

pytestmark = [pytest.mark.e2e, pytest.mark.tools]


def test_client_get_resource_passport_uses_ephemeral_key(
    rbs_cli_binary: Path, rbs_api: Any, agent_config_path: Path
) -> None:
    """Run the passport auto flow and validate its decrypted JSON result."""
    with httpx.Client(trust_env=False) as client:
        uri, _, secret = create_resource(client, rbs_api)
    payload = json_output(
        run_tools(
            rbs_cli_binary,
            rbs_api.base_url,
            "client",
            "get-resource",
            "--agent-config",
            str(agent_config_path),
            "--uri",
            uri,
            "--passport",
        )
    )
    assert json.loads(base64.b64decode(payload["content"], validate=True)) == secret

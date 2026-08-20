"""E2E contract tests for GET /rbs/v0/challenge."""

import base64
from typing import Any
import httpx
import pytest
from e2e.rbs.support import assert_error

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


@pytest.mark.parametrize("params", [None, {"as_provider": "gta"}], ids=["default-provider", "explicit-provider"])
def test_get_challenge_forwards_to_provider_and_returns_exact_nonce(rbs_api: Any, params: dict[str, str] | None) -> None:
    """Use the default or explicit GTA provider and return only its opaque nonce."""
    before = len(rbs_api.fake_gta.requests)
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/challenge", params=params)
    assert response.status_code == 200
    assert set(response.json()) == {"nonce"}
    assert base64.b64decode(response.json()["nonce"], validate=True).decode().startswith("e2e-nonce-")
    assert len(rbs_api.fake_gta.requests) == before + 1


def test_get_challenge_returns_not_found_for_unknown_provider(rbs_api: Any) -> None:
    """Return the documented not-found response for an unknown backend."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/challenge", params={"as_provider": "missing"})
    assert_error(response, 404, "management provider not found: missing")


def test_get_challenge_returns_upstream_failure_details(rbs_api: Any) -> None:
    """Map a deterministic GTA failure to 503 with its upstream response message."""
    rbs_api.fake_gta.fail_next_challenge(message="sensitive upstream detail")
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/challenge")
    error = assert_error(response, 503, "sensitive upstream detail")
    assert "attestation provider error" in error

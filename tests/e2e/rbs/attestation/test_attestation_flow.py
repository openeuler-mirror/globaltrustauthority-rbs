"""Integrated challenge-to-attestation E2E test."""

from typing import Any
import httpx
import pytest
from e2e.rbs.attestation.test_post_attest import _body

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_attestation_flow(rbs_api: Any) -> None:
    """Obtain a challenge, bind it into evidence, and receive a signed token."""
    with httpx.Client(trust_env=False) as client:
        challenge = client.get(f"{rbs_api.base_url}/rbs/v0/challenge")
        assert challenge.status_code == 200
        attest = client.post(f"{rbs_api.base_url}/rbs/v0/attest", json=_body(challenge.json()["nonce"]))
    assert attest.status_code == 200
    assert attest.json()["token"].count(".") == 2

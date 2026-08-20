"""E2E contract tests for POST /rbs/v0/attest."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import assert_error

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def _body(nonce: str, *, provider: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"rbc_evidences": {"agent_version": "e2e", "measurements": [{"node_id": "node", "nonce": nonce, "nonce_type": "string", "token_fmt": "jwt", "evidences": [{"attester_type": "fake", "evidence": {"result": "pass"}, "policy_ids": ["policy"]}]}]}}
    if provider is not None:
        body["as_provider"] = provider
    return body


def test_post_attest_forwards_complete_evidence_and_returns_jwt(rbs_api: Any) -> None:
    """Forward all evidence fields to GTA and return one signed three-part token."""
    with httpx.Client(trust_env=False) as client:
        challenge = client.get(f"{rbs_api.base_url}/rbs/v0/challenge").json()["nonce"]
        response = client.post(f"{rbs_api.base_url}/rbs/v0/attest", json=_body(challenge))
    assert response.status_code == 200
    assert set(response.json()) == {"token"}
    assert response.json()["token"].count(".") == 2
    forwarded = rbs_api.fake_gta.requests[-1]["body"]["measurements"][0]
    assert forwarded["nonce"] == challenge
    assert forwarded["node_id"] == "node"
    assert forwarded["evidences"][0]["policy_ids"] == ["policy"]


@pytest.mark.parametrize("content,content_type", [("{", "application/json"), ("not-json", "text/plain")], ids=["malformed-json", "wrong-content-type"])
def test_post_attest_rejects_malformed_request_body(rbs_api: Any, content: str, content_type: str) -> None:
    """Reject malformed JSON and unsupported request content type."""
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/attest", content=content, headers={"Content-Type": content_type})
    assert_error(response, 400)


def test_post_attest_returns_not_found_for_unknown_provider(rbs_api: Any) -> None:
    """Return the documented not-found response for an unknown requested provider."""
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/attest", json=_body("nonce", provider="missing"))
    assert_error(response, 404, "management provider not found: missing")


def test_post_attest_returns_upstream_failure_details(rbs_api: Any) -> None:
    """Map a deterministic GTA failure to 503 with its upstream response message."""
    rbs_api.fake_gta.fail_next_attest(status=503, message="sensitive upstream detail")
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/attest", json=_body("nonce"))
    error = assert_error(response, 503, "sensitive upstream detail")
    assert "attestation provider error" in error

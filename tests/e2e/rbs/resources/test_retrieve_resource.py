"""E2E contract tests for POST /rbs/v0/{resource_uri}/retrieve."""

import json
from typing import Any
import httpx
import pytest
from e2e.rbs.support import DENY_POLICY, RESOURCE_CONTENT_KEYS, assert_error, create_resource, decode_jwe, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def _evidence(api: Any, *, tee_pubkey: Any = None, include_tee_pubkey: bool = True) -> dict[str, Any]:
    runtime_data: dict[str, Any] = {}
    if include_tee_pubkey:
        runtime_data["tee-pubkey"] = api.encryption_jwk if tee_pubkey is None else tee_pubkey
    return {
        "rbc_evidences": {
            "measurements": [
                {
                    "node_id": "e2e-node",
                    "nonce": "e2e-nonce",
                    "attester_data": {"runtime_data": runtime_data},
                    "evidences": [{"attester_type": "fake", "evidence": {"result": "pass"}}],
                }
            ]
        }
    }


def test_retrieve_resource_is_public_but_attests_and_returns_decryptable_jwe(rbs_api: Any) -> None:
    """Retrieve without Bearer auth, verify GTA forwarding, and decrypt exact plaintext."""
    with httpx.Client(trust_env=False) as client:
        path, _, secret = create_resource(client, rbs_api)
        before = len(rbs_api.fake_gta.requests)
        response = client.post(f"{rbs_api.base_url}/rbs/v0/{path}/retrieve", json=_evidence(rbs_api))
    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) == RESOURCE_CONTENT_KEYS
    _, plaintext = decode_jwe(payload["content"], rbs_api.encryption_private_key_path)
    assert json.loads(plaintext) == secret
    assert len(rbs_api.fake_gta.requests) == before + 1


def test_retrieve_resource_rejects_malformed_json(rbs_api: Any) -> None:
    """Reject a request body that cannot deserialize as attestation evidence."""
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/vault/default/secret/name/retrieve", content="{", headers={"Content-Type": "application/json"})
    assert_error(response, 400)


def test_retrieve_resource_maps_attestation_failure_to_bad_gateway(rbs_api: Any) -> None:
    """Return the documented 502 when the inline attestation backend fails."""
    rbs_api.fake_gta.fail_next_attest(message="sensitive upstream detail")
    with httpx.Client(trust_env=False) as client:
        response = client.post(
            f"{rbs_api.base_url}/rbs/v0/vault/default/secret/name/retrieve",
            json=_evidence(rbs_api),
        )
    error = assert_error(response, 502)
    assert "sensitive upstream detail" not in error


def test_retrieve_resource_returns_not_found_after_valid_attestation(rbs_api: Any) -> None:
    """Return 404 for a validly attested request targeting a missing resource."""
    path = f"vault/default/secret/{unique_name('missing', max_length=32)}"
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/{path}/retrieve", json=_evidence(rbs_api))
    assert_error(response, 404)


def test_retrieve_resource_applies_attest_policy_deny(rbs_api: Any) -> None:
    """Return 404 when valid evidence produces a token denied by the resource policy."""
    with httpx.Client(trust_env=False) as client:
        path, _, secret = create_resource(client, rbs_api, policy_content=DENY_POLICY)
        response = client.post(f"{rbs_api.base_url}/rbs/v0/{path}/retrieve", json=_evidence(rbs_api))
    assert_error(response, 404)
    assert secret["value"] not in response.text


@pytest.mark.parametrize(
    "kwargs",
    [{"include_tee_pubkey": False}, {"tee_pubkey": "not-a-jwk"}],
    ids=["missing-tee-key", "invalid-tee-key"],
)
def test_retrieve_resource_rejects_missing_or_invalid_tee_key(rbs_api: Any, kwargs: dict[str, Any]) -> None:
    """Reject a validly attested request that cannot encrypt the resource response."""
    with httpx.Client(trust_env=False) as client:
        path, _, secret = create_resource(client, rbs_api)
        response = client.post(
            f"{rbs_api.base_url}/rbs/v0/{path}/retrieve",
            json=_evidence(rbs_api, **kwargs),
        )
    assert_error(response, 400, "JWE")
    assert secret["value"] not in response.text


def test_retrieve_resource_rejects_invalid_attest_token(rbs_api: Any) -> None:
    """Return an internal error when GTA returns a token that RBS cannot authenticate."""
    invalid_token = rbs_api.fake_gta.issue_token({"iss": "not-global-trust-authority"})
    rbs_api.fake_gta.respond_next_attest(
        {
            "service_version": "e2e",
            "tokens": [{"node_id": "e2e-node", "token": invalid_token}],
        }
    )
    path = f"vault/default/secret/{unique_name('invalid-token', max_length=32)}"
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/{path}/retrieve", json=_evidence(rbs_api))
    assert_error(response, 500)

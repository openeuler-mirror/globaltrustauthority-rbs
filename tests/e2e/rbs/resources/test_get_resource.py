"""E2E contract tests for GET /rbs/v0/{resource_uri}."""

import json
from typing import Any
import httpx
import pytest
from e2e.rbs.support import (
    DENY_POLICY,
    RESOURCE_CONTENT_KEYS,
    assert_error,
    attest_headers,
    create_resource,
    create_user,
    decode_jwe,
    unique_name,
)

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_get_resource_returns_decryptable_jwe_with_exact_plaintext(rbs_api: Any) -> None:
    """Decrypt the Bearer response and compare it exactly with the OpenBao value."""
    with httpx.Client(trust_env=False) as client:
        path, _, secret = create_resource(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) == RESOURCE_CONTENT_KEYS
    assert payload["uri"] == f"/rbs/v0/{path}"
    assert payload["content_type"] == "json" and payload["export_mode"] == "jwe"
    _, plaintext = decode_jwe(payload["content"], rbs_api.encryption_private_key_path)
    assert json.loads(plaintext) == secret


def test_get_resource_accepts_attest_token_and_returns_decryptable_jwe(rbs_api: Any) -> None:
    """Allow a valid AttestToken to retrieve a resource-bound JWE."""
    with httpx.Client(trust_env=False) as client:
        path, _, secret = create_resource(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}", headers=attest_headers(rbs_api))
    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) == RESOURCE_CONTENT_KEYS
    _, plaintext = decode_jwe(payload["content"], rbs_api.encryption_private_key_path)
    assert json.loads(plaintext) == secret


def test_get_resource_applies_attest_policy_deny(rbs_api: Any) -> None:
    """Hide resource content when the resource policy denies the AttestToken."""
    with httpx.Client(trust_env=False) as client:
        path, _, secret = create_resource(client, rbs_api, policy_content=DENY_POLICY)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}", headers=attest_headers(rbs_api))
    assert_error(response, 404)
    assert secret["value"] not in response.text


def test_get_resource_allows_owner_bearer_without_role_claim(rbs_api: Any) -> None:
    """Allow an owner BearerToken without a role claim to retrieve a resource."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        owner_headers = rbs_api.bearer_headers(user["username"])
        path, _, secret = create_resource(client, rbs_api, headers=owner_headers)
        no_role_headers = rbs_api.bearer_headers(user["username"], role=None)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}", headers=no_role_headers)
    assert response.status_code == 200, response.text
    _, plaintext = decode_jwe(response.json()["content"], rbs_api.encryption_private_key_path)
    assert json.loads(plaintext) == secret


@pytest.mark.parametrize(
    "kwargs",
    [{"include_enc_pubkey": False}, {"enc_pubkey": "not-a-jwk"}],
    ids=["missing-enc-pubkey", "invalid-enc-pubkey"],
)
def test_get_resource_rejects_missing_or_invalid_bearer_encryption_key(
    rbs_api: Any, kwargs: dict[str, Any]
) -> None:
    """Reject a Bearer request that cannot provide a valid JWE encryption key."""
    with httpx.Client(trust_env=False) as client:
        path, _, secret = create_resource(client, rbs_api)
        response = client.get(
            f"{rbs_api.base_url}/rbs/v0/{path}",
            headers=rbs_api.bearer_headers("Administrator", **kwargs),
        )
    assert_error(response, 400, "JWE")
    assert secret["value"] not in response.text


@pytest.mark.parametrize("case", ["wrong-issuer", "expired"], ids=["wrong-issuer", "expired"])
def test_get_resource_rejects_invalid_attest_token(rbs_api: Any, case: str) -> None:
    """Reject an AttestToken with invalid registered claims before resource access."""
    claims = {"attester_data": {"runtime_data": {"tee-pubkey": rbs_api.encryption_jwk}}}
    expires_in = 300
    if case == "wrong-issuer":
        claims["iss"] = "not-global-trust-authority"
    else:
        expires_in = -120
    token = rbs_api.fake_gta.issue_token(claims, expires_in=expires_in)
    path = f"vault/default/secret/{unique_name('invalid-attest', max_length=32)}"
    with httpx.Client(trust_env=False) as client:
        response = client.get(
            f"{rbs_api.base_url}/rbs/v0/{path}",
            headers={"Authorization": f"Attest {token}"},
        )
    assert_error(response, 401)


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"attester_data": {"runtime_data": {"tee-pubkey": "not-a-jwk"}}},
    ],
    ids=["missing-tee-key", "invalid-tee-key"],
)
def test_get_resource_rejects_missing_or_invalid_tee_key(rbs_api: Any, claims: dict[str, Any]) -> None:
    """Reject resource retrieval when the AttestToken cannot supply a valid JWE key."""
    with httpx.Client(trust_env=False) as client:
        path, _, secret = create_resource(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}", headers=attest_headers(rbs_api, claims=claims))
    assert_error(response, 400, "JWE")
    assert secret["value"] not in response.text


def test_get_resource_requires_authentication_and_hides_missing_resource(rbs_api: Any) -> None:
    """Return 401 without auth and 404 for an authenticated unknown resource."""
    path = f"vault/default/secret/{unique_name('missing', max_length=32)}"
    with httpx.Client(trust_env=False) as client:
        unauthenticated = client.get(f"{rbs_api.base_url}/rbs/v0/{path}")
        missing = client.get(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers)
    assert_error(unauthenticated, 401)
    assert_error(missing, 404)


def test_get_resource_hides_another_owners_resource(rbs_api: Any) -> None:
    """Return not found instead of exposing another owner's resource content."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        headers = rbs_api.bearer_headers(user["username"])
        path, resource, _ = create_resource(client, rbs_api, headers=headers)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/{path}", headers=headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{resource['policy_id']}", headers=headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 404)

"""E2E contract tests for POST /rbs/v0/resource/policy."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import ALLOW_POLICY, assert_error, assert_policy, create_user, policy_payload, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


@pytest.mark.parametrize("length", [1, 255], ids=["minimum-name", "maximum-name"])
def test_create_policy_accepts_name_boundaries(rbs_api: Any, length: int) -> None:
    """Accept policy names exactly at both documented length boundaries."""
    name = "p" * length
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, json=policy_payload(name))
        assert response.status_code == 201, response.text
        assert_policy(response.json(), name=name)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{response.json()['policy_id']}", headers=rbs_api.admin_headers)


@pytest.mark.parametrize("name", ["", "p" * 256, "bad<name", "bad/name", "bad`name"], ids=["empty", "above-max", "angle", "slash", "backtick"])
def test_create_policy_rejects_invalid_names(rbs_api: Any, name: str) -> None:
    """Reject empty, oversized, and representative blacklisted policy names."""
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, json=policy_payload(name))
    assert_error(response, 400)


@pytest.mark.parametrize("body", [
    {"name": "p", "content_type": "text", "content": "x"},
    {"name": "p", "content_type": "base64", "content": ""},
    {"name": "p", "content_type": "base64", "content": "%%%"},
], ids=["content-type", "empty-content", "invalid-base64"])
def test_create_policy_rejects_invalid_content(rbs_api: Any, body: dict[str, str]) -> None:
    """Reject unsupported content type, empty content, and invalid Base64."""
    body = {**body, "name": unique_name("policy")}
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, json=body)
    assert_error(response, 400)


def test_create_policy_rejects_duplicate_name(rbs_api: Any) -> None:
    """Return conflict for a duplicate policy name owned by the same user."""
    name = unique_name("duplicate")
    with httpx.Client(trust_env=False) as client:
        first = client.post(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, json=policy_payload(name))
        second = client.post(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, json=policy_payload(name))
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{first.json()['policy_id']}", headers=rbs_api.admin_headers)
    assert first.status_code == 201
    assert_error(second, 409)


def test_create_policy_requires_authentication(rbs_api: Any) -> None:
    """Reject policy creation without a Bearer token."""
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/resource/policy", json=policy_payload(unique_name("unauth")))
    assert_error(response, 401)


def test_create_policy_scopes_duplicate_names_to_owner(rbs_api: Any) -> None:
    """Allow different authenticated users to own policies with the same name."""
    name = unique_name("shared")
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        user_headers = rbs_api.bearer_headers(user["username"])
        admin_policy = client.post(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, json=policy_payload(name))
        user_policy = client.post(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=user_headers, json=policy_payload(name))
        if admin_policy.status_code == 201:
            client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{admin_policy.json()['policy_id']}", headers=rbs_api.admin_headers)
        if user_policy.status_code == 201:
            client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{user_policy.json()['policy_id']}", headers=user_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert admin_policy.status_code == 201, admin_policy.text
    assert user_policy.status_code == 201, user_policy.text


def test_create_policy_enforces_per_user_maximum(rbs_api: Any) -> None:
    """Reject the first policy above the configured per-user limit of ten."""
    created: list[str] = []
    with httpx.Client(trust_env=False) as client:
        for _ in range(10):
            response = client.post(
                f"{rbs_api.base_url}/rbs/v0/resource/policy",
                headers=rbs_api.admin_headers,
                json=policy_payload(unique_name("quota")),
            )
            assert response.status_code == 201, response.text
            created.append(response.json()["policy_id"])
        overflow = client.post(
            f"{rbs_api.base_url}/rbs/v0/resource/policy",
            headers=rbs_api.admin_headers,
            json=policy_payload(unique_name("overflow")),
        )
        client.delete(
            f"{rbs_api.base_url}/rbs/v0/resource/policy",
            headers=rbs_api.admin_headers,
            params={"ids": ",".join(created)},
        )
    assert_error(overflow, 409)

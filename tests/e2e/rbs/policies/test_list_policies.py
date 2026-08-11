"""E2E contract tests for GET /rbs/v0/resource/policy."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import assert_error, assert_policy, create_policy, create_user, policy_payload, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_list_policies_returns_defaults_filters_and_exact_shape(rbs_api: Any) -> None:
    """List owned policies with default pagination and an ID filter."""
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, params={"ids": policy["policy_id"]})
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers)
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"items", "total_count", "limit", "offset"}
    assert payload["total_count"] == 1 and payload["limit"] == 10 and payload["offset"] == 0
    assert_policy(payload["items"][0], name=policy["policy_name"])


@pytest.mark.parametrize("field,value", [("limit", 0), ("limit", 101), ("offset", -1), ("offset", 100001)], ids=["limit-below", "limit-above", "offset-below", "offset-above"])
def test_list_policies_rejects_pagination_outside_range(rbs_api: Any, field: str, value: int) -> None:
    """Reject pagination values immediately outside the documented boundaries."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, params={field: value})
    assert_error(response, 400)


@pytest.mark.parametrize("ids", ["not-a-uuid", "x" * 37, "00000000-0000-0000-0000-000000000000,bad"], ids=["invalid-format", "too-long-id", "invalid-member"])
def test_list_policies_rejects_invalid_id_filters(rbs_api: Any, ids: str) -> None:
    """Validate every non-empty member of a comma-separated policy ID filter."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, params={"ids": ids})
    assert_error(response, 400)


def test_list_policies_requires_authentication(rbs_api: Any) -> None:
    """Reject policy listing without a Bearer token."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/resource/policy")
    assert_error(response, 401)


def test_list_policies_returns_only_authenticated_owners_policies(rbs_api: Any) -> None:
    """Keep another user's policy IDs and names out of list results."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        user_headers = rbs_api.bearer_headers(user["username"])
        own = client.post(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=user_headers, json=policy_payload(unique_name("own")))
        admin_policy = create_policy(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=user_headers)
        if own.status_code == 201:
            client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{own.json()['policy_id']}", headers=user_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{admin_policy['policy_id']}", headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert own.status_code == 201, own.text
    assert response.status_code == 200
    returned_ids = {policy["policy_id"] for policy in response.json()["items"]}
    assert own.json()["policy_id"] in returned_ids
    assert admin_policy["policy_id"] not in returned_ids

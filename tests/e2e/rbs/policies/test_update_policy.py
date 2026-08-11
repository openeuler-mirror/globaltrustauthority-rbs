"""E2E contract tests for PUT /rbs/v0/resource/policy/{policy_id}."""

from typing import Any
from uuid import uuid4
import httpx
import pytest
from e2e.rbs.support import assert_error, assert_policy, create_policy, create_user, policy_payload, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_update_policy_changes_name_and_increments_version(rbs_api: Any) -> None:
    """Update a policy while preserving ID and creation timestamp and incrementing version."""
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
        new_name = unique_name("updated")
        response = client.put(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers, json=policy_payload(new_name))
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers)
    assert response.status_code == 200
    assert_policy(response.json(), name=new_name)
    assert response.json()["policy_id"] == policy["policy_id"]
    assert response.json()["policy_version"] == policy["policy_version"] + 1
    assert response.json()["created_at"] == policy["created_at"]


@pytest.mark.parametrize("body", [policy_payload(""), {"name": "ok", "content_type": "text", "content": "x"}, {"name": "ok", "content_type": "base64", "content": ""}], ids=["empty-name", "content-type", "empty-content"])
def test_update_policy_rejects_invalid_body(rbs_api: Any, body: dict[str, str]) -> None:
    """Apply the same name and content validation rules used during creation."""
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
        response = client.put(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers, json=body)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers)
    assert_error(response, 400)


def test_update_policy_returns_not_found(rbs_api: Any) -> None:
    """Return 404 when updating an unknown well-formed identifier."""
    with httpx.Client(trust_env=False) as client:
        response = client.put(f"{rbs_api.base_url}/rbs/v0/resource/policy/{uuid4()}", headers=rbs_api.admin_headers, json=policy_payload(unique_name("missing")))
    assert_error(response, 404)


def test_update_policy_forbids_cross_owner_mutation(rbs_api: Any) -> None:
    """Reject a valid regular user changing another owner's policy."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        policy = create_policy(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}"
        response = client.put(url, headers=rbs_api.bearer_headers(user["username"]), json=policy_payload(unique_name("forbidden")))
        client.delete(url, headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 403)

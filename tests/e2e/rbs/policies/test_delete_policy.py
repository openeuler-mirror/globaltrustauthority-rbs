"""E2E contract tests for DELETE /rbs/v0/resource/policy/{policy_id}."""

from typing import Any
from uuid import uuid4
import httpx
import pytest
from e2e.rbs.support import assert_error, create_policy, create_resource, create_user

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_delete_policy_returns_empty_204_and_removes_policy(rbs_api: Any) -> None:
    """Delete an unreferenced policy and confirm subsequent lookup fails."""
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}"
        deleted = client.delete(url, headers=rbs_api.admin_headers)
        missing = client.get(url, headers=rbs_api.admin_headers)
    assert deleted.status_code == 204 and deleted.content == b""
    assert_error(missing, 404)


@pytest.mark.parametrize("policy_id,status", [("bad", 400), (str(uuid4()), 404)], ids=["invalid-id", "unknown-id"])
def test_delete_policy_validates_existence(rbs_api: Any, policy_id: str, status: int) -> None:
    """Distinguish malformed identifiers from well-formed missing policies."""
    with httpx.Client(trust_env=False) as client:
        response = client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy_id}", headers=rbs_api.admin_headers)
    assert_error(response, status)


def test_delete_policy_hides_cross_owner_policy(rbs_api: Any) -> None:
    """Treat another owner's policy as not found and leave it unchanged."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        policy = create_policy(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}"
        response = client.delete(url, headers=rbs_api.bearer_headers(user["username"]))
        still_exists = client.get(url, headers=rbs_api.admin_headers)
        client.delete(url, headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 404)
    assert still_exists.status_code == 200


def test_delete_policy_rejects_policy_referenced_by_resource(rbs_api: Any) -> None:
    """Return conflict while a resource still refers to the policy."""
    with httpx.Client(trust_env=False) as client:
        resource_path, resource, _ = create_resource(client, rbs_api)
        policy_url = f"{rbs_api.base_url}/rbs/v0/resource/policy/{resource['policy_id']}"
        response = client.delete(policy_url, headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/{resource_path}", headers=rbs_api.admin_headers)
        cleanup = client.delete(policy_url, headers=rbs_api.admin_headers)
    assert_error(response, 409, "referenced")
    assert cleanup.status_code == 204

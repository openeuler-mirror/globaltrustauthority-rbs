"""E2E contract tests for GET /rbs/v0/resource/policy/{policy_id}."""

from typing import Any
from uuid import uuid4
import httpx
import pytest
from e2e.rbs.support import assert_error, assert_policy, create_policy, create_user

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_get_policy_returns_detail_shape(rbs_api: Any) -> None:
    """Return complete detail including the applied-resources collection."""
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers)
    assert response.status_code == 200
    assert_policy(response.json(), name=policy["policy_name"], detail=True)


@pytest.mark.parametrize("policy_id", ["bad", "x" * 37], ids=["invalid-uuid", "above-max"])
def test_get_policy_validates_path_id(rbs_api: Any, policy_id: str) -> None:
    """Reject malformed and oversized policy identifiers."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy_id}", headers=rbs_api.admin_headers)
    assert_error(response, 400)


def test_get_policy_returns_not_found_for_unknown_uuid(rbs_api: Any) -> None:
    """Return 404 for a well-formed policy identifier that does not exist."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/resource/policy/{uuid4()}", headers=rbs_api.admin_headers)
    assert_error(response, 404)


def test_get_policy_forbids_cross_owner_access(rbs_api: Any) -> None:
    """Reject a valid regular user reading another owner's policy."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        policy = create_policy(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}"
        response = client.get(url, headers=rbs_api.bearer_headers(user["username"]))
        client.delete(url, headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 403)

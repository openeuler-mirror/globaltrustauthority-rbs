"""E2E contract tests for DELETE /rbs/v0/{resource_uri}."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import assert_error, create_resource, create_user, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_delete_resource_returns_empty_204_and_removes_metadata_only(rbs_api: Any) -> None:
    """Delete RBS metadata, preserve OpenBao data, and confirm metadata is gone."""
    with httpx.Client(trust_env=False) as client:
        path, _, _ = create_resource(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/{path}"
        response = client.delete(url, headers=rbs_api.admin_headers)
        missing = client.get(f"{url}/info", headers=rbs_api.admin_headers)
    assert response.status_code == 204 and response.content == b""
    assert_error(missing, 404)


def test_delete_resource_requires_authentication_and_existing_metadata(rbs_api: Any) -> None:
    """Return 401 without auth and 404 for unknown metadata."""
    path = f"vault/default/secret/{unique_name('missing', max_length=32)}"
    with httpx.Client(trust_env=False) as client:
        unauthenticated = client.delete(f"{rbs_api.base_url}/rbs/v0/{path}")
        missing = client.delete(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers)
    assert_error(unauthenticated, 401)
    assert_error(missing, 404)


def test_delete_resource_forbids_cross_owner_mutation(rbs_api: Any) -> None:
    """Reject deletion by another user and leave the resource metadata intact."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        user_headers = rbs_api.bearer_headers(user["username"])
        path, resource, _ = create_resource(client, rbs_api, headers=user_headers)
        url = f"{rbs_api.base_url}/rbs/v0/{path}"
        response = client.delete(url, headers=rbs_api.admin_headers)
        still_exists = client.get(f"{url}/info", headers=user_headers)
        client.delete(url, headers=user_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{resource['policy_id']}", headers=user_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 403)
    assert still_exists.status_code == 200

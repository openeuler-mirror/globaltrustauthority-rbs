"""E2E contract tests for GET /rbs/v0/{resource_uri}/info."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import DENY_POLICY, assert_error, assert_resource, attest_headers, create_resource, create_user

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_get_resource_info_returns_metadata_without_secret(rbs_api: Any) -> None:
    """Return complete metadata while never exposing resource content."""
    with httpx.Client(trust_env=False) as client:
        path, created, secret = create_resource(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}/info", headers=rbs_api.admin_headers)
    assert response.status_code == 200
    assert_resource(response.json(), uri=f"/rbs/v0/{path}", policy_id=created["policy_id"])
    assert secret["value"] not in response.text


def test_get_resource_info_accepts_attest_token(rbs_api: Any) -> None:
    """Allow a valid AttestToken to retrieve resource metadata."""
    with httpx.Client(trust_env=False) as client:
        path, created, _ = create_resource(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}/info", headers=attest_headers(rbs_api))
    assert response.status_code == 200, response.text
    assert_resource(response.json(), uri=f"/rbs/v0/{path}", policy_id=created["policy_id"])


def test_get_resource_info_applies_attest_policy_deny(rbs_api: Any) -> None:
    """Hide metadata when the resource policy denies the AttestToken."""
    with httpx.Client(trust_env=False) as client:
        path, _, secret = create_resource(client, rbs_api, policy_content=DENY_POLICY)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}/info", headers=attest_headers(rbs_api))
    assert_error(response, 404)
    assert secret["value"] not in response.text


def test_get_resource_info_requires_authentication(rbs_api: Any) -> None:
    """Reject metadata lookup without a Bearer or Attest token."""
    with httpx.Client(trust_env=False) as client:
        path, _, _ = create_resource(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}/info")
    assert_error(response, 401)


def test_get_resource_info_hides_another_owners_metadata(rbs_api: Any) -> None:
    """Return not found instead of exposing another owner's resource metadata."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        headers = rbs_api.bearer_headers(user["username"])
        path, resource, _ = create_resource(client, rbs_api, headers=headers)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}/info", headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/{path}", headers=headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{resource['policy_id']}", headers=headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 404)

"""E2E contract tests for POST /rbs/v0/{resource_uri}."""

from typing import Any
from uuid import uuid4
import httpx
import pytest
from e2e.rbs.support import assert_error, assert_resource, create_policy, create_user, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_create_resource_registers_existing_backend_secret(rbs_api: Any) -> None:
    """Register complete metadata for an existing OpenBao secret."""
    name = unique_name("secret", max_length=32)
    path = f"vault/default/secret/{name}"
    rbs_api.openbao.write_kv(f"default/secret/{name}", {"value": "secret"})
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
        response = client.post(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers, json={"policy_id": policy["policy_id"]})
        client.delete(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers)
    assert response.status_code == 201, response.text
    assert_resource(response.json(), uri=f"/rbs/v0/{path}", policy_id=policy["policy_id"])
    assert "content_type" not in response.json()
    assert "additional_info" not in response.json()


@pytest.mark.parametrize("path", ["vault/default/secret", "vault/default/secret/name/extra", "vault/bad.name/secret/name", "vault/default/unknown/name", "unknown/default/secret/name"], ids=["too-few-segments", "too-many-segments", "repository-characters", "resource-type", "provider"])
def test_create_resource_validates_every_uri_component(rbs_api: Any, path: str) -> None:
    """Reject invalid URI cardinality, repository, type, and provider components."""
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
        response = client.post(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers, json={"policy_id": policy["policy_id"]})
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers)
    assert_error(response, 400)


@pytest.mark.parametrize("field,value", [("content_type", "xml"), ("export_mode", "plain"), ("additional_info", ""), ("additional_info", "x" * 513)], ids=["content-type", "plain-export", "empty-info", "long-info"])
def test_create_resource_rejects_invalid_optional_metadata(rbs_api: Any, field: str, value: str) -> None:
    """Validate content type, JWE-only export mode, and additional-info boundaries."""
    name = unique_name("meta", max_length=32)
    rbs_api.openbao.write_kv(f"default/secret/{name}", {"value": "secret"})
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
        body = {"policy_id": policy["policy_id"], field: value}
        response = client.post(f"{rbs_api.base_url}/rbs/v0/vault/default/secret/{name}", headers=rbs_api.admin_headers, json=body)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers)
    assert_error(response, 400)


def test_create_resource_rejects_unknown_policy_missing_backend_and_duplicate(rbs_api: Any) -> None:
    """Distinguish invalid policy, absent backend secret, and duplicate metadata."""
    name = unique_name("create", max_length=32)
    path = f"vault/default/secret/{name}"
    with httpx.Client(trust_env=False) as client:
        bad_policy = client.post(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers, json={"policy_id": str(uuid4())})
        policy = create_policy(client, rbs_api)
        missing = client.post(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers, json={"policy_id": policy["policy_id"]})
        rbs_api.openbao.write_kv(f"default/secret/{name}", {"value": "secret"})
        first = client.post(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers, json={"policy_id": policy["policy_id"]})
        duplicate = client.post(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers, json={"policy_id": policy["policy_id"]})
    assert_error(bad_policy, 400)
    assert_error(missing, 400)
    assert first.status_code == 201
    assert_error(duplicate, 409)


def test_create_resource_allows_regular_owner_with_own_policy(rbs_api: Any) -> None:
    """Allow a regular user to register backend metadata using its own policy."""
    name = unique_name("owned", max_length=32)
    path = f"vault/default/secret/{name}"
    rbs_api.openbao.write_kv(f"default/secret/{name}", {"value": "secret"})
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        headers = rbs_api.bearer_headers(user["username"])
        policy = create_policy(client, rbs_api, headers=headers)
        response = client.post(
            f"{rbs_api.base_url}/rbs/v0/{path}",
            headers=headers,
            json={"policy_id": policy["policy_id"]},
        )
        client.delete(f"{rbs_api.base_url}/rbs/v0/{path}", headers=headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert response.status_code == 201, response.text
    assert_resource(response.json(), uri=f"/rbs/v0/{path}", policy_id=policy["policy_id"])


def test_create_resource_rejects_another_owners_policy(rbs_api: Any) -> None:
    """Reject a valid policy ID owned by a different authenticated user."""
    name = unique_name("foreign", max_length=32)
    path = f"vault/default/secret/{name}"
    rbs_api.openbao.write_kv(f"default/secret/{name}", {"value": "secret"})
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        policy = create_policy(client, rbs_api)
        response = client.post(
            f"{rbs_api.base_url}/rbs/v0/{path}",
            headers=rbs_api.bearer_headers(user["username"]),
            json={"policy_id": policy["policy_id"]},
        )
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}", headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 400)

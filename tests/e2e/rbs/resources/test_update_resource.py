"""E2E contract tests for PUT /rbs/v0/{resource_uri}."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import assert_error, assert_resource, create_policy, create_resource, create_user, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_update_resource_updates_existing_and_put_creates_missing_metadata(rbs_api: Any) -> None:
    """Return 200 for update and 201 when PUT creates metadata for an existing backend secret."""
    with httpx.Client(trust_env=False) as client:
        path, created, _ = create_resource(client, rbs_api)
        updated = client.put(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers, json={"policy_id": created["policy_id"], "additional_info": "updated"})
        new_name = unique_name("put", max_length=32)
        new_path = f"vault/default/secret/{new_name}"
        rbs_api.openbao.write_kv(f"default/secret/{new_name}", {"value": "new"})
        policy = create_policy(client, rbs_api)
        upserted = client.put(f"{rbs_api.base_url}/rbs/v0/{new_path}", headers=rbs_api.admin_headers, json={"policy_id": policy["policy_id"]})
    assert updated.status_code == 200
    assert_resource(updated.json(), uri=f"/rbs/v0/{path}", policy_id=created["policy_id"])
    assert updated.json()["additional_info"] == "updated"
    assert updated.json()["created_at"] == created["created_at"]
    assert upserted.status_code == 201
    assert_resource(upserted.json(), uri=f"/rbs/v0/{new_path}", policy_id=policy["policy_id"])


@pytest.mark.parametrize("body", [{}, {"policy_id": ""}, {"policy_id": "x" * 37}, {"policy_id": "00000000-0000-0000-0000-000000000000", "export_mode": "plain"}], ids=["missing-policy", "empty-policy", "long-policy", "plain-export"])
def test_update_resource_validates_required_body_and_export_mode(rbs_api: Any, body: dict[str, str]) -> None:
    """Reject missing or invalid policy IDs and plaintext export mode."""
    path = f"vault/default/secret/{unique_name('invalid', max_length=32)}"
    with httpx.Client(trust_env=False) as client:
        response = client.put(f"{rbs_api.base_url}/rbs/v0/{path}", headers=rbs_api.admin_headers, json=body)
    assert_error(response, 400)


def test_update_resource_forbids_cross_owner_mutation(rbs_api: Any) -> None:
    """Reject replacing another owner's resource metadata with the actor's policy."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        user_headers = rbs_api.bearer_headers(user["username"])
        path, resource, _ = create_resource(client, rbs_api, headers=user_headers)
        admin_policy = create_policy(client, rbs_api)
        response = client.put(
            f"{rbs_api.base_url}/rbs/v0/{path}",
            headers=rbs_api.admin_headers,
            json={"policy_id": admin_policy["policy_id"]},
        )
        client.delete(f"{rbs_api.base_url}/rbs/v0/{path}", headers=user_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{resource['policy_id']}", headers=user_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy/{admin_policy['policy_id']}", headers=rbs_api.admin_headers)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 403)

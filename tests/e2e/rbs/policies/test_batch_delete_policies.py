"""E2E contract tests for DELETE /rbs/v0/resource/policy?ids=...."""

from typing import Any
from uuid import uuid4
import httpx
import pytest
from e2e.rbs.support import assert_error, create_policy, create_resource

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_batch_delete_policies_deletes_all_ids_atomically(rbs_api: Any) -> None:
    """Delete multiple owned policies and return an empty 204 response."""
    with httpx.Client(trust_env=False) as client:
        policies = [create_policy(client, rbs_api) for _ in range(2)]
        response = client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, params={"ids": ",".join(item["policy_id"] for item in policies)})
        deleted = [
            client.get(
                f"{rbs_api.base_url}/rbs/v0/resource/policy/{item['policy_id']}",
                headers=rbs_api.admin_headers,
            )
            for item in policies
        ]
    assert response.status_code == 204 and response.content == b""
    for item in deleted:
        assert_error(item, 404)


@pytest.mark.parametrize("ids", ["", "bad", str(uuid4())], ids=["empty", "invalid-id", "unknown-id"])
def test_batch_delete_policies_rejects_invalid_or_missing_ids(rbs_api: Any, ids: str) -> None:
    """Reject an empty list, malformed member, or missing well-formed policy."""
    with httpx.Client(trust_env=False) as client:
        response = client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, params={"ids": ids})
    assert_error(response, 400 if ids in ("", "bad") else 404)


def test_batch_delete_policies_requires_ids_query(rbs_api: Any) -> None:
    """Reject a batch delete request when the required ids query is absent."""
    with httpx.Client(trust_env=False) as client:
        response = client.delete(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers)
    assert_error(response, 400)


def test_batch_delete_policies_is_atomic_when_one_policy_is_referenced(rbs_api: Any) -> None:
    """Keep every policy when one member of the batch is referenced by a resource."""
    with httpx.Client(trust_env=False) as client:
        resource_path, resource, _ = create_resource(client, rbs_api)
        free_policy = create_policy(client, rbs_api)
        ids = f"{resource['policy_id']},{free_policy['policy_id']}"
        response = client.delete(
            f"{rbs_api.base_url}/rbs/v0/resource/policy",
            headers=rbs_api.admin_headers,
            params={"ids": ids},
        )
        free_still_exists = client.get(
            f"{rbs_api.base_url}/rbs/v0/resource/policy/{free_policy['policy_id']}",
            headers=rbs_api.admin_headers,
        )
        client.delete(f"{rbs_api.base_url}/rbs/v0/{resource_path}", headers=rbs_api.admin_headers)
        cleanup = client.delete(
            f"{rbs_api.base_url}/rbs/v0/resource/policy",
            headers=rbs_api.admin_headers,
            params={"ids": ids},
        )
    assert_error(response, 409, "referenced")
    assert free_still_exists.status_code == 200
    assert cleanup.status_code == 204

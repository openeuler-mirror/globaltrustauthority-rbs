"""Integrated resource-policy lifecycle E2E test."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import assert_error, assert_policy, create_policy, policy_payload, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_policy_lifecycle(rbs_api: Any) -> None:
    """Create, discover, update, list, delete, and confirm removal of one policy."""
    with httpx.Client(trust_env=False) as client:
        policy = create_policy(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/resource/policy/{policy['policy_id']}"
        assert_policy(client.get(url, headers=rbs_api.admin_headers).json(), name=policy["policy_name"], detail=True)
        new_name = unique_name("lifecycle")
        updated = client.put(url, headers=rbs_api.admin_headers, json=policy_payload(new_name))
        assert updated.status_code == 200 and updated.json()["policy_version"] == 2
        listed = client.get(f"{rbs_api.base_url}/rbs/v0/resource/policy", headers=rbs_api.admin_headers, params={"ids": policy["policy_id"]})
        assert listed.json()["items"][0]["policy_name"] == new_name
        deleted = client.delete(url, headers=rbs_api.admin_headers)
        assert deleted.status_code == 204 and deleted.content == b""
        assert_error(client.get(url, headers=rbs_api.admin_headers), 404)

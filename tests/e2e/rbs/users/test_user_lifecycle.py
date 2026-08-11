"""Integrated user-management lifecycle E2E test."""

from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_error, assert_user, create_user

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_user_lifecycle(rbs_api: Any) -> None:
    """Create, discover, update, authenticate, delete, and confirm removal of one user."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        username = user["username"]
        url = f"{rbs_api.base_url}/rbs/v0/users/{username}"
        fetched = client.get(url, headers=rbs_api.admin_headers)
        assert_user(fetched.json(), username=username, role="user", enabled=True)
        listed = client.get(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers, params={"role": "user", "enabled": True})
        assert any(item["username"] == username for item in listed.json()["users"])
        disabled = client.put(url, headers=rbs_api.admin_headers, json={"enabled": False})
        assert_user(disabled.json(), username=username, role="user", enabled=False)
        denied = client.get(url, headers=rbs_api.bearer_headers(username))
        assert_error(denied, 403, "permissions")
        restored = client.put(url, headers=rbs_api.admin_headers, json={"enabled": True})
        assert restored.status_code == 200
        assert client.get(url, headers=rbs_api.bearer_headers(username)).status_code == 200
        deleted = client.delete(url, headers=rbs_api.admin_headers)
        assert deleted.status_code == 204 and deleted.content == b""
        assert_error(client.get(url, headers=rbs_api.admin_headers), 404)

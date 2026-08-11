"""E2E contract tests for GET /rbs/v0/users."""

from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_error, assert_user, create_user

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_list_users_returns_defaults_and_complete_user_shape(rbs_api: Any) -> None:
    """List users with default pagination and validate every response field."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers)
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"users", "total_count", "limit", "offset"}
    assert payload["limit"] == 10 and payload["offset"] == 0
    assert payload["total_count"] >= 1
    admin = next(user for user in payload["users"] if user["username"] == "Administrator")
    assert_user(admin, username="Administrator", role="admin", enabled=True)


@pytest.mark.parametrize("field,value", [("limit", 0), ("limit", 101), ("offset", -1), ("offset", 100001)], ids=["limit-below-min", "limit-above-max", "offset-below-min", "offset-above-max"])
def test_list_users_rejects_out_of_range_pagination(rbs_api: Any, field: str, value: int) -> None:
    """Reject each pagination value immediately outside its documented range."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers, params={field: value})
    assert_error(response, 400)


@pytest.mark.parametrize("params", [{"role": "owner"}, {"enabled": "maybe"}, {"limit": "ten"}], ids=["invalid-role", "invalid-bool", "invalid-integer"])
def test_list_users_rejects_invalid_query_types(rbs_api: Any, params: dict[str, str]) -> None:
    """Reject query values that cannot be deserialized into the public query schema."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers, params=params)
    assert_error(response, 400)


def test_list_users_filters_and_paginates(rbs_api: Any) -> None:
    """Apply role, enabled, limit, and offset filters and echo effective pagination."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api, enabled=False)
        response = client.get(
            f"{rbs_api.base_url}/rbs/v0/users",
            headers=rbs_api.admin_headers,
            params={"role": "user", "enabled": "false", "limit": 1, "offset": 0},
        )
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["limit"] == 1 and payload["offset"] == 0
    assert all(item["role"] == "user" and item["enabled"] is False for item in payload["users"])


def test_list_users_requires_authentication(rbs_api: Any) -> None:
    """Reject a list request without a Bearer token."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users")
    assert_error(response, 401)


def test_list_users_forbids_regular_user(rbs_api: Any) -> None:
    """Reject user enumeration by an authenticated non-admin account."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        response = client.get(
            f"{rbs_api.base_url}/rbs/v0/users",
            headers=rbs_api.bearer_headers(user["username"]),
        )
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 403)

"""E2E contract tests for GET /rbs/v0/users/{username}."""

from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_error, assert_user, create_user, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_get_user_returns_complete_response_for_admin_and_self(rbs_api: Any) -> None:
    """Allow an administrator and the user itself to read the same account."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/users/{user['username']}"
        for headers in (rbs_api.admin_headers, rbs_api.bearer_headers(user["username"])):
            response = client.get(url, headers=headers)
            assert response.status_code == 200
            assert_user(response.json(), username=user["username"], role="user", enabled=True)
        client.delete(url, headers=rbs_api.admin_headers)


def test_get_user_hides_other_users_from_regular_user(rbs_api: Any) -> None:
    """Reject a regular user attempting to read another account."""
    with httpx.Client(trust_env=False) as client:
        first = create_user(client, rbs_api)
        second = create_user(client, rbs_api)
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users/{second['username']}", headers=rbs_api.bearer_headers(first["username"]))
        for user in (first, second):
            client.delete(f"{rbs_api.base_url}/rbs/v0/users/{user['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 403)


@pytest.mark.parametrize("username", ["bad name", "x" * 37], ids=["invalid-characters", "above-max"])
def test_get_user_validates_path_username(rbs_api: Any, username: str) -> None:
    """Reject invalid path usernames before querying storage."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users/{username}", headers=rbs_api.admin_headers)
    assert_error(response, 400)


def test_get_user_returns_not_found(rbs_api: Any) -> None:
    """Return 404 for a valid but unknown username."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users/{unique_name('missing')}", headers=rbs_api.admin_headers)
    assert_error(response, 404)

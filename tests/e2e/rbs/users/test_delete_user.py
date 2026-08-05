"""E2E contract tests for DELETE /rbs/v0/users/{username}."""

from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_error, create_user, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_delete_user_removes_account_and_returns_empty_204(rbs_api: Any) -> None:
    """Delete a regular account and verify the no-content and not-found contracts."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/users/{user['username']}"
        deleted = client.delete(url, headers=rbs_api.admin_headers)
        missing = client.get(url, headers=rbs_api.admin_headers)
    assert deleted.status_code == 204 and deleted.content == b""
    assert_error(missing, 404)


def test_delete_user_rejects_admin_self_deletion(rbs_api: Any) -> None:
    """Protect the authenticated built-in administrator from deleting itself."""
    with httpx.Client(trust_env=False) as client:
        response = client.delete(f"{rbs_api.base_url}/rbs/v0/users/Administrator", headers=rbs_api.admin_headers)
    assert_error(response, 403)


def test_delete_user_returns_not_found(rbs_api: Any) -> None:
    """Return 404 when deleting a syntactically valid unknown account."""
    with httpx.Client(trust_env=False) as client:
        response = client.delete(f"{rbs_api.base_url}/rbs/v0/users/{unique_name('missing')}", headers=rbs_api.admin_headers)
    assert_error(response, 404)


def test_delete_user_requires_admin(rbs_api: Any) -> None:
    """Reject deletion by an unauthenticated caller and by a regular user."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/users/{user['username']}"
        unauthenticated = client.delete(url)
        regular = client.delete(url, headers=rbs_api.bearer_headers(user["username"]))
        client.delete(url, headers=rbs_api.admin_headers)
    assert_error(unauthenticated, 401)
    assert_error(regular, 403)

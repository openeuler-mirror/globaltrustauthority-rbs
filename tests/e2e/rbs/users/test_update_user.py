"""E2E contract tests for PUT /rbs/v0/users/{username}."""

from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_error, assert_user, create_user

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_update_user_changes_enabled_and_returns_complete_response(rbs_api: Any) -> None:
    """Allow an administrator to disable a regular account."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/users/{user['username']}"
        response = client.put(url, headers=rbs_api.admin_headers, json={"enabled": False})
        assert response.status_code == 200
        assert_user(response.json(), username=user["username"], role="user", enabled=False)
        client.delete(url, headers=rbs_api.admin_headers)


@pytest.mark.parametrize("body", [{}, {"public_key": "", "jwk": None}, {"public_key": "x", "jwk": {"kty": "RSA"}}, {"role": "admin"}], ids=["empty", "empty-key-material", "mutually-exclusive", "admin-role"])
def test_update_user_rejects_invalid_field_combinations(rbs_api: Any, body: dict[str, Any]) -> None:
    """Reject empty updates, invalid key combinations, and unsupported role changes."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/users/{user['username']}"
        response = client.put(url, headers=rbs_api.admin_headers, json=body)
        client.delete(url, headers=rbs_api.admin_headers)
    expected_status = 403 if body == {"role": "admin"} else 400
    assert_error(response, expected_status)


def test_update_user_enforces_self_service_field_whitelist(rbs_api: Any) -> None:
    """Permit self key rotation but forbid a regular user changing account status."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/users/{user['username']}"
        headers = rbs_api.bearer_headers(user["username"])
        forbidden = client.put(url, headers=headers, json={"enabled": False})
        allowed = client.put(url, headers=headers, json={"jwk": rbs_api.encryption_jwk})
        client.delete(url, headers=rbs_api.admin_headers)
    assert_error(forbidden, 403)
    assert allowed.status_code == 200


@pytest.mark.parametrize("body", [{"enabled": False}, {"role": "user"}], ids=["disable", "change-role"])
def test_update_user_protects_builtin_administrator(rbs_api: Any, body: dict[str, Any]) -> None:
    """Prevent disabling or changing the role of the built-in administrator."""
    with httpx.Client(trust_env=False) as client:
        response = client.put(f"{rbs_api.base_url}/rbs/v0/users/Administrator", headers=rbs_api.admin_headers, json=body)
    assert_error(response, 403, "built-in administrator")

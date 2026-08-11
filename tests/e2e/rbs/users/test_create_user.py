"""E2E contract tests for POST /rbs/v0/users."""

from typing import Any

import httpx
import pytest

from e2e.rbs.support import assert_error, assert_user, create_user, unique_name

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def _payload(api: Any, username: str) -> dict[str, Any]:
    return {"username": username, "role": "user", "enabled": True, "auth_type": "jwt", "jwk": api.encryption_jwk}


@pytest.mark.parametrize("username", ["a", "u" * 36], ids=["minimum-length", "maximum-length"])
def test_create_user_accepts_username_boundaries(rbs_api: Any, username: str) -> None:
    """Accept usernames exactly at the minimum and maximum lengths."""
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers, json=_payload(rbs_api, username))
        assert response.status_code == 201, response.text
        assert_user(response.json(), username=username, role="user", enabled=True)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{username}", headers=rbs_api.admin_headers)


@pytest.mark.parametrize("username", ["", "u" * 37, "bad name", "bad/name", "名字"], ids=["empty", "above-max", "space", "slash", "non-ascii"])
def test_create_user_rejects_invalid_usernames(rbs_api: Any, username: str) -> None:
    """Reject usernames outside the length and ASCII character constraints."""
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers, json=_payload(rbs_api, username))
    assert_error(response, 400)


@pytest.mark.parametrize(
    "mutation",
    [
        {"auth_type": "password"}, {"role": "admin"}, {"jwk": None},
        {"jwk": {"kty": "invalid"}}, {"public_key": "also-present"},
    ],
    ids=["invalid-auth-type", "admin-role", "missing-key", "invalid-jwk", "mutually-exclusive-keys"],
)
def test_create_user_rejects_invalid_auth_material(rbs_api: Any, mutation: dict[str, Any]) -> None:
    """Reject unsupported roles, auth types, missing keys, malformed keys, and dual keys."""
    payload = _payload(rbs_api, unique_name("invalid"))
    payload.update(mutation)
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers, json=payload)
    assert_error(response, 400)


def test_create_user_applies_optional_defaults(rbs_api: Any) -> None:
    """Default omitted role to user and omitted enabled to true."""
    username = unique_name("defaults")
    payload = {"username": username, "auth_type": "jwt", "jwk": rbs_api.encryption_jwk}
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers, json=payload)
        assert response.status_code == 201, response.text
        assert_user(response.json(), username=username, role="user", enabled=True)
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{username}", headers=rbs_api.admin_headers)


def test_create_user_rejects_duplicate_username(rbs_api: Any) -> None:
    """Return conflict when a username already exists."""
    username = unique_name("duplicate")
    with httpx.Client(trust_env=False) as client:
        first = client.post(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers, json=_payload(rbs_api, username))
        second = client.post(f"{rbs_api.base_url}/rbs/v0/users", headers=rbs_api.admin_headers, json=_payload(rbs_api, username))
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{username}", headers=rbs_api.admin_headers)
    assert first.status_code == 201
    assert_error(second, 409)


def test_create_user_requires_admin_authentication(rbs_api: Any) -> None:
    """Reject creation without authentication."""
    with httpx.Client(trust_env=False) as client:
        response = client.post(f"{rbs_api.base_url}/rbs/v0/users", json=_payload(rbs_api, unique_name("unauth")))
    assert_error(response, 401)


def test_create_user_forbids_regular_user(rbs_api: Any) -> None:
    """Reject user creation by an authenticated non-admin account."""
    with httpx.Client(trust_env=False) as client:
        actor = create_user(client, rbs_api)
        response = client.post(
            f"{rbs_api.base_url}/rbs/v0/users",
            headers=rbs_api.bearer_headers(actor["username"]),
            json=_payload(rbs_api, unique_name("forbidden")),
        )
        client.delete(f"{rbs_api.base_url}/rbs/v0/users/{actor['username']}", headers=rbs_api.admin_headers)
    assert_error(response, 403)


def test_create_user_enforces_configured_maximum(rbs_api: Any) -> None:
    """Reject the first regular user above the configured max_users value of ten."""
    created: list[str] = []
    with httpx.Client(trust_env=False) as client:
        for _ in range(10):
            username = unique_name("quota")
            response = client.post(
                f"{rbs_api.base_url}/rbs/v0/users",
                headers=rbs_api.admin_headers,
                json=_payload(rbs_api, username),
            )
            assert response.status_code == 201, response.text
            created.append(username)
        overflow = client.post(
            f"{rbs_api.base_url}/rbs/v0/users",
            headers=rbs_api.admin_headers,
            json=_payload(rbs_api, unique_name("overflow")),
        )
        for username in created:
            client.delete(f"{rbs_api.base_url}/rbs/v0/users/{username}", headers=rbs_api.admin_headers)
    assert_error(overflow, 409, "quota")

"""E2E contract tests for GET /rbs/v0/resource (user-scoped resource list)."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import (
    assert_error,
    assert_resource,
    attest_headers,
    create_resource,
    create_user,
)

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def _list(client: httpx.Client, api: Any, *, headers: dict[str, str], query: str = "") -> httpx.Response:
    return client.get(f"{api.base_url}/rbs/v0/resource{query}", headers=headers)


def test_list_resources_returns_caller_resource_details(rbs_api: Any) -> None:
    """List the caller's resources as full metadata details, without secrets."""
    with httpx.Client(trust_env=False) as client:
        path_one, created_one, secret_one = create_resource(client, rbs_api)
        path_two, created_two, _ = create_resource(client, rbs_api)
        response = _list(client, rbs_api, headers=rbs_api.admin_headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) == {"items", "total_count", "limit", "offset"}
    assert payload["total_count"] == 2
    assert payload["limit"] == 10
    assert payload["offset"] == 0
    assert len(payload["items"]) == 2
    by_uri = {item["uri"]: item for item in payload["items"]}
    assert set(by_uri) == {f"/rbs/v0/{path_one}", f"/rbs/v0/{path_two}"}
    assert_resource(by_uri[f"/rbs/v0/{path_one}"], uri=f"/rbs/v0/{path_one}", policy_id=created_one["policy_id"])
    assert_resource(by_uri[f"/rbs/v0/{path_two}"], uri=f"/rbs/v0/{path_two}", policy_id=created_two["policy_id"])
    assert secret_one["value"] not in response.text


def test_list_resources_is_strictly_user_scoped(rbs_api: Any) -> None:
    """Never return another user's resources in the caller's list."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        user_headers = rbs_api.bearer_headers(user["username"])
        path, created, _ = create_resource(client, rbs_api, headers=user_headers)
        user_list = _list(client, rbs_api, headers=user_headers)
        admin_list = _list(client, rbs_api, headers=rbs_api.admin_headers)
    assert user_list.status_code == 200, user_list.text
    user_payload = user_list.json()
    assert user_payload["total_count"] == 1
    assert len(user_payload["items"]) == 1
    assert_resource(user_payload["items"][0], uri=f"/rbs/v0/{path}", policy_id=created["policy_id"])
    # The Administrator owns nothing here — the user's resource must not leak.
    admin_payload = admin_list.json()
    assert admin_payload["total_count"] == 0
    assert admin_payload["items"] == []


def test_list_resources_paginates_with_limit_and_offset(rbs_api: Any) -> None:
    """Page through the caller's resources with deterministic coverage."""
    with httpx.Client(trust_env=False) as client:
        user = create_user(client, rbs_api)
        user_headers = rbs_api.bearer_headers(user["username"])
        paths = [create_resource(client, rbs_api, headers=user_headers)[0] for _ in range(3)]

        page_one = _list(client, rbs_api, headers=user_headers, query="?limit=2&offset=0")
        page_two = _list(client, rbs_api, headers=user_headers, query="?limit=2&offset=2")
    assert page_one.status_code == 200, page_one.text
    one = page_one.json()
    assert one["total_count"] == 3
    assert one["limit"] == 2
    assert one["offset"] == 0
    assert len(one["items"]) == 2
    assert page_two.status_code == 200, page_two.text
    two = page_two.json()
    assert two["total_count"] == 3
    assert len(two["items"]) == 1
    # Pages cover every resource exactly once — no overlap, no gap.
    paged_uris = {item["uri"] for item in one["items"] + two["items"]}
    assert paged_uris == {f"/rbs/v0/{path}" for path in paths}


def test_list_resources_requires_authentication(rbs_api: Any) -> None:
    """Reject the user-dimension query without a Bearer token."""
    with httpx.Client(trust_env=False) as client:
        response = _list(client, rbs_api, headers={})
    assert_error(response, 401)


def test_list_resources_rejects_attest_token(rbs_api: Any) -> None:
    """Reject Attest tokens: they carry no user subject for the user-scoped list."""
    with httpx.Client(trust_env=False) as client:
        response = _list(client, rbs_api, headers=attest_headers(rbs_api))
    error = assert_error(response, 401)
    # The message is the unified auth failure text: it must not disclose this
    # endpoint's token-type policy (reason stays in the server log only).
    assert error == "Authentication failed"


@pytest.mark.parametrize("field,value", [("limit", 0), ("limit", 101), ("offset", -1), ("offset", 100001)], ids=["limit-below", "limit-above", "offset-below", "offset-above"])
def test_list_resources_rejects_pagination_outside_range(rbs_api: Any, field: str, value: int) -> None:
    """Reject pagination values immediately outside the documented boundaries."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(
            f"{rbs_api.base_url}/rbs/v0/resource",
            headers=rbs_api.admin_headers,
            params={field: value},
        )
    assert_error(response, 400)

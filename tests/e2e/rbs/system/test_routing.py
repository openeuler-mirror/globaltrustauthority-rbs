"""E2E tests for routing, wildcard precedence, and URI length guards."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import assert_error

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_unknown_rbs_path_returns_uniform_not_found(rbs_api: Any) -> None:
    """Return the JSON 404 contract for a path outside all versioned routes."""
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/unknown", headers=rbs_api.admin_headers)
    assert_error(response, 404)


def test_info_and_retrieve_suffixes_use_specialized_routes(rbs_api: Any) -> None:
    """Ensure wildcard resource routing does not swallow info or retrieve suffixes."""
    with httpx.Client(trust_env=False) as client:
        info = client.get(f"{rbs_api.base_url}/rbs/v0/vault/default/secret/missing/info", headers=rbs_api.admin_headers)
        retrieve = client.post(f"{rbs_api.base_url}/rbs/v0/vault/default/secret/missing/retrieve", content="{", headers={"Content-Type": "application/json"})
    assert_error(info, 404)
    assert_error(retrieve, 400)


def test_uri_length_guard_rejects_path_and_query_over_2048_bytes(rbs_api: Any) -> None:
    """Return 414 with the uniform error shape when path plus query exceeds 2048 bytes."""
    path = f"{rbs_api.base_url}/rbs/v0/challenge"
    fixed = len("/rbs/v0/challenge") + len("q=")
    with httpx.Client(trust_env=False) as client:
        response = client.get(path, params={"q": "x" * (2049 - fixed)})
    assert_error(response, 414, "URI Too Long")

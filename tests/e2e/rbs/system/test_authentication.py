"""E2E tests for shared authentication middleware behavior."""

from typing import Any
import httpx
import pytest
from e2e.rbs.support import assert_error

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


@pytest.mark.parametrize(
    "authorization",
    [None, "Basic abc", "Bearer not-a-jwt", "bearer token"],
    ids=["missing", "wrong-scheme", "malformed", "wrong-case"],
)
def test_protected_endpoint_rejects_missing_or_malformed_authorization(rbs_api: Any, authorization: str | None) -> None:
    """Return the uniform 401 contract for every malformed Authorization form."""
    headers = {} if authorization is None else {"Authorization": authorization}
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users", headers=headers)
    assert_error(response, 401)


@pytest.mark.parametrize("token", ["expired", "issuer", "audience"], ids=["expired", "wrong-issuer", "wrong-audience"])
def test_protected_endpoint_rejects_invalid_signed_token_claims(rbs_api: Any, token: str) -> None:
    """Reject otherwise valid signatures with expired or mismatched registered claims."""
    kwargs: dict[str, Any] = {}
    if token == "expired": kwargs["expires_in"] = -120
    if token == "issuer": kwargs["issuer"] = "wrong"
    if token == "audience": kwargs["audience"] = "wrong"
    value = rbs_api.fake_gta.issue_bearer_token(rbs_api.encryption_jwk, **kwargs)
    with httpx.Client(trust_env=False) as client:
        response = client.get(f"{rbs_api.base_url}/rbs/v0/users", headers={"Authorization": f"Bearer {value}"})
    assert_error(response, 401, "Authentication failed")


def test_attest_token_is_rejected_on_bearer_only_endpoint(rbs_api: Any) -> None:
    """Reject a valid AttestToken on user and policy administration APIs."""
    token = rbs_api.fake_gta.issue_token()
    with httpx.Client(trust_env=False) as client:
        for path in ("users", "resource/policy"):
            response = client.get(f"{rbs_api.base_url}/rbs/v0/{path}", headers={"Authorization": f"Attest {token}"})
            assert_error(response, 401, "not allowed")


def test_public_endpoints_ignore_invalid_authorization_header(rbs_api: Any) -> None:
    """Keep version and challenge public even when a caller sends an unusable token."""
    headers = {"Authorization": "Bearer invalid"}
    with httpx.Client(trust_env=False) as client:
        assert client.get(f"{rbs_api.base_url}/rbs/version", headers=headers).status_code == 200
        assert client.get(f"{rbs_api.base_url}/rbs/v0/challenge", headers=headers).status_code == 200

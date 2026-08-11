"""Shared data builders and strict contract assertions for RBS E2E tests."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
from jwcrypto import jwe, jwk

ALLOW_POLICY = """package verification

default allow = true
result = {\"policy_matched\": allow}
"""
DENY_POLICY = """package verification

default allow = false
result = {\"policy_matched\": allow}
"""

USER_KEYS = {"id", "username", "role", "enabled", "created_at", "updated_at"}
POLICY_KEYS = {"policy_id", "policy_name", "policy_version", "content_type", "created_at", "updated_at"}
RESOURCE_REQUIRED_KEYS = {
    "uri", "provider_name", "repository_name", "resource_type", "resource_name",
    "created_at", "updated_at", "export_mode", "policy_id",
}
RESOURCE_OPTIONAL_KEYS = {"content_type", "additional_info"}
RESOURCE_CONTENT_KEYS = {"uri", "content", "content_type", "export_mode"}


def unique_name(prefix: str, *, max_length: int = 36) -> str:
    """Return a collision-resistant API identifier within the requested length."""
    return f"{prefix}_{uuid4().hex}"[:max_length]


def assert_error(response: httpx.Response, status: int, contains: str | None = None) -> str:
    """Assert the uniform JSON error contract and optionally its stable semantic text."""
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert set(payload) == {"error"}
    assert isinstance(payload["error"], str) and payload["error"]
    if contains is not None:
        assert contains.lower() in payload["error"].lower()
    return payload["error"]


def assert_rfc3339(value: Any) -> None:
    """Assert a non-empty RFC 3339 timestamp."""
    assert isinstance(value, str) and value
    datetime.fromisoformat(value.replace("Z", "+00:00"))


def assert_uuid(value: Any) -> None:
    """Assert a canonical UUID string."""
    assert isinstance(value, str)
    assert str(UUID(value)) == value.lower()


def assert_user(payload: dict[str, Any], *, username: str, role: str, enabled: bool) -> None:
    """Assert the complete user response and absence of authentication key material."""
    assert set(payload) == USER_KEYS
    assert_uuid(payload["id"])
    assert payload["username"] == username
    assert payload["role"] == role
    assert payload["enabled"] is enabled
    assert_rfc3339(payload["created_at"])
    assert_rfc3339(payload["updated_at"])


def policy_payload(name: str, content: str = ALLOW_POLICY) -> dict[str, str]:
    """Build a valid base64 policy request."""
    return {
        "name": name,
        "content_type": "base64",
        "content": base64.b64encode(content.encode()).decode(),
    }


def assert_policy(payload: dict[str, Any], *, name: str, detail: bool = False) -> None:
    """Assert the complete policy response returned by list/create/update or detail."""
    expected = POLICY_KEYS | ({"applied_resources"} if detail else set())
    assert set(payload) == expected
    assert_uuid(payload["policy_id"])
    assert payload["policy_name"] == name
    assert isinstance(payload["policy_version"], int) and payload["policy_version"] >= 1
    assert payload["content_type"] == "base64"
    assert_rfc3339(payload["created_at"])
    assert_rfc3339(payload["updated_at"])
    if detail:
        assert isinstance(payload["applied_resources"], list)


def create_policy(
    client: httpx.Client,
    api: Any,
    *,
    name: str | None = None,
    headers: dict[str, str] | None = None,
    content: str = ALLOW_POLICY,
) -> dict[str, Any]:
    """Create and return one valid policy through the public API."""
    chosen = name or unique_name("policy")
    owner_headers = api.admin_headers if headers is None else headers
    response = client.post(
        f"{api.base_url}/rbs/v0/resource/policy",
        headers=owner_headers,
        json=policy_payload(chosen, content),
    )
    assert response.status_code == 201, response.text
    assert_policy(response.json(), name=chosen)
    return response.json()


def create_user(client: httpx.Client, api: Any, *, username: str | None = None, enabled: bool = True) -> dict[str, Any]:
    """Create and return one regular user registered with the E2E public key."""
    chosen = username or unique_name("user")
    response = client.post(
        f"{api.base_url}/rbs/v0/users",
        headers=api.admin_headers,
        json={"username": chosen, "role": "user", "enabled": enabled, "auth_type": "jwt", "jwk": api.encryption_jwk},
    )
    assert response.status_code == 201, response.text
    assert_user(response.json(), username=chosen, role="user", enabled=enabled)
    return response.json()


def create_resource(
    client: httpx.Client,
    api: Any,
    *,
    name: str | None = None,
    secret: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    policy_content: str = ALLOW_POLICY,
) -> tuple[str, dict[str, Any], dict[str, str]]:
    """Seed OpenBao and register matching resource metadata through RBS."""
    owner_headers = api.admin_headers if headers is None else headers
    resource_name = name or unique_name("secret", max_length=32)
    resource_path = f"vault/default/secret/{resource_name}"
    secret_value = secret or {"value": unique_name("value")}
    api.openbao.write_kv(f"default/secret/{resource_name}", secret_value)
    policy = create_policy(client, api, headers=owner_headers, content=policy_content)
    response = client.post(
        f"{api.base_url}/rbs/v0/{resource_path}",
        headers=owner_headers,
        json={
            "policy_id": policy["policy_id"],
            "content_type": "json",
            "export_mode": "jwe",
            "additional_info": "created by e2e",
        },
    )
    assert response.status_code == 201, response.text
    return resource_path, response.json(), secret_value


def attest_headers(api: Any, *, claims: dict[str, Any] | None = None) -> dict[str, str]:
    """Build an Attest header carrying the E2E JWE public key by default."""
    token_claims = (
        claims
        if claims is not None
        else {"attester_data": {"runtime_data": {"tee-pubkey": api.encryption_jwk}}}
    )
    token = api.fake_gta.issue_token(token_claims)
    return {"Authorization": f"Attest {token}"}


def decode_jwe(content: str, private_key_path: Path) -> tuple[dict[str, Any], bytes]:
    """Decode Base64, validate compact JWE headers, decrypt, and return plaintext."""
    compact = base64.b64decode(content, validate=True).decode("utf-8")
    assert compact.count(".") == 4
    header_segment = compact.split(".", 1)[0]
    header_segment += "=" * (-len(header_segment) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_segment))
    assert header["alg"] == "RSA-OAEP-256"
    assert header["enc"] == "A256GCM"
    token = jwe.JWE()
    token.deserialize(compact, key=jwk.JWK.from_pem(private_key_path.read_bytes()))
    return header, token.payload


def assert_resource(payload: dict[str, Any], *, uri: str, policy_id: str) -> None:
    """Assert complete resource metadata without secret material."""
    assert RESOURCE_REQUIRED_KEYS <= set(payload) <= RESOURCE_REQUIRED_KEYS | RESOURCE_OPTIONAL_KEYS
    assert payload["uri"] == uri
    assert payload["provider_name"] == "vault"
    assert payload["repository_name"] == "default"
    assert payload["resource_type"] == "secret"
    assert payload["resource_name"] == uri.rsplit("/", 1)[-1]
    assert payload["policy_id"] == policy_id
    assert payload["export_mode"] == "jwe"
    assert_rfc3339(payload["created_at"])
    assert_rfc3339(payload["updated_at"])
    assert "content" not in payload

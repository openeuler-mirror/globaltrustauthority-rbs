"""Integrated resource lifecycle E2E test."""

import json
from typing import Any
import httpx
import pytest
from e2e.rbs.resources.test_retrieve_resource import _evidence
from e2e.rbs.support import assert_error, create_resource, decode_jwe

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def test_resource_lifecycle(rbs_api: Any) -> None:
    """Create, inspect, decrypt, update, attest-retrieve, delete, and confirm removal."""
    with httpx.Client(trust_env=False) as client:
        path, created, secret = create_resource(client, rbs_api)
        url = f"{rbs_api.base_url}/rbs/v0/{path}"
        assert client.get(f"{url}/info", headers=rbs_api.admin_headers).status_code == 200
        bearer = client.get(url, headers=rbs_api.admin_headers).json()
        assert json.loads(decode_jwe(bearer["content"], rbs_api.encryption_private_key_path)[1]) == secret
        assert client.put(url, headers=rbs_api.admin_headers, json={"policy_id": created["policy_id"], "additional_info": "lifecycle"}).status_code == 200
        attest = client.post(f"{url}/retrieve", json=_evidence(rbs_api)).json()
        assert json.loads(decode_jwe(attest["content"], rbs_api.encryption_private_key_path)[1]) == secret
        deleted = client.delete(url, headers=rbs_api.admin_headers)
        assert deleted.status_code == 204 and deleted.content == b""
        assert_error(client.get(f"{url}/info", headers=rbs_api.admin_headers), 404)

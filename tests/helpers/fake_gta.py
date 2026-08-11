# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""Small GTA REST double used by black-box RBS E2E tests.

It intentionally implements only the two calls made by ``GtaRestProvider``:
challenge issuance and evidence attestation.  Tokens are signed by the
temporary key whose public half is configured in the RBS process, so later
resource-flow tests can exercise RBS's real AttestToken verification.
"""

from __future__ import annotations

import base64
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


_CHALLENGE_PATH = "/global-trust-authority/service/v1/challenge"
_ATTEST_PATH = "/global-trust-authority/service/v1/attest"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class FakeGta:
    """Lifecycle owner for a deterministic, local GTA REST double."""

    def __init__(self, signing_key_path: Path, *, port: int = 0) -> None:
        self._signing_key_path = signing_key_path
        self._port = port

    @property
    def base_url(self) -> str:
        server = getattr(self, "_server", None)
        if server is None:
            raise RuntimeError("Fake GTA has not been started")
        host, port = server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> None:
        if getattr(self, "_server", None) is not None:
            return
        self._nonce_number = 0
        self._next_responses: dict[str, tuple[int, dict[str, Any]]] = {}
        self.requests: list[dict[str, Any]] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path != _CHALLENGE_PATH:
                    self.send_error(404)
                    return
                status, payload = owner.challenge()
                self._send_json(status, payload)

            def do_POST(self) -> None:  # noqa: N802
                if self.path != _ATTEST_PATH:
                    self.send_error(404)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    body = json.loads(self.rfile.read(length))
                except (ValueError, json.JSONDecodeError):
                    self._send_json(400, {"message": "invalid JSON"})
                    return
                status, payload = owner.attest(body)
                self._send_json(status, payload)

            def _send_json(self, status: int, payload: dict[str, Any]) -> None:
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self._server = HTTPServer(("127.0.0.1", self._port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def challenge(self) -> tuple[int, dict[str, Any]]:
        """Return the GTA challenge response."""
        forced = self._take_next_response("challenge")
        if forced is not None:
            status, payload = forced
            self.requests.append({"method": "GET", "path": _CHALLENGE_PATH, "forced_status": status})
            return status, payload

        self._nonce_number += 1
        nonce = base64.b64encode(f"e2e-nonce-{self._nonce_number}".encode()).decode()
        self.requests.append({"method": "GET", "path": _CHALLENGE_PATH, "nonce": nonce})
        return 200, {"service_version": "e2e", "nonce": nonce}

    def attest(self, body: Any) -> tuple[int, dict[str, Any]]:
        """Return the GTA attestation response for one evidence payload."""
        if not isinstance(body, dict) or not isinstance(body.get("measurements"), list):
            return 400, {"message": "measurements is required"}

        self.requests.append({"method": "POST", "path": _ATTEST_PATH, "body": body})
        forced = self._take_next_response("attest")
        if forced is not None:
            return forced

        token_claims: dict[str, Any] = {}
        if body["measurements"]:
            attester_data = body["measurements"][0].get("attester_data")
            if attester_data is not None:
                token_claims["attester_data"] = attester_data
        node_id = body["measurements"][0].get("node_id", "e2e-node") if body["measurements"] else "e2e-node"
        return 200, {
            "service_version": "e2e",
            "tokens": [{"node_id": node_id, "token": self.issue_token(token_claims)}],
        }

    def stop(self) -> None:
        server = getattr(self, "_server", None)
        if server is None:
            return
        server.shutdown()
        server.server_close()
        thread = getattr(self, "_thread", None)
        if thread is not None:
            thread.join(timeout=5)
        self._server = None
        self._thread = None

    def fail_next_challenge(self, *, status: int = 503, message: str = "GTA unavailable") -> None:
        """Make the next challenge call return one deterministic upstream failure."""
        self._set_next_response("challenge", status, {"message": message})

    def fail_next_attest(self, *, status: int = 503, message: str = "GTA unavailable") -> None:
        """Make the next attest call return one deterministic upstream failure."""
        self._set_next_response("attest", status, {"message": message})

    def _set_next_response(self, operation: str, status: int, payload: dict[str, Any]) -> None:
        self._next_responses[operation] = (status, payload)

    def _take_next_response(self, operation: str) -> tuple[int, dict[str, Any]] | None:
        return self._next_responses.pop(operation, None)


    def issue_token(
        self,
        extra_claims: dict[str, Any] | None = None,
        *,
        expires_in: int = 300,
    ) -> str:
        """Create a PS256 JWT signed by the temporary E2E attestation key."""
        header = _base64url(b'{"alg":"PS256","typ":"JWT"}')
        claims = {
            "iss": "Global Trust Authority",
            "sub": "e2e-attester",
            "exp": int(time.time()) + expires_in,
        }
        if extra_claims:
            claims.update(extra_claims)
        payload = _base64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header}.{payload}".encode("ascii")
        return f"{header}.{payload}.{_base64url(self._sign_ps256(signing_input))}"

    def respond_next_attest(self, payload: dict[str, Any], *, status: int = 200) -> None:
        """Return one caller-supplied response from the next attest request."""
        self._set_next_response("attest", status, payload)

    def issue_bearer_token(
        self,
        encryption_jwk: dict[str, str],
        *,
        subject: str = "Administrator",
        role: str | None = "admin",
        issuer: str = "rbs-cli",
        audience: str = "globaltrustauthority-rbs",
        expires_in: int = 300,
        enc_pubkey: Any | None = None,
        include_enc_pubkey: bool = True,
    ) -> str:
        """Create a configurable Bearer token signed by the E2E user key."""
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": subject,
            "exp": int(time.time()) + expires_in,
        }
        if include_enc_pubkey:
            claims["enc-pubkey"] = encryption_jwk if enc_pubkey is None else enc_pubkey
        if role is not None:
            claims["role"] = role
        header = _base64url(b'{"alg":"PS256","typ":"JWT"}')
        payload = _base64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header}.{payload}".encode("ascii")
        return f"{header}.{payload}.{_base64url(self._sign_ps256(signing_input))}"

    def issue_admin_bearer_token(self, encryption_jwk: dict[str, str]) -> str:
        """Create the Bearer token accepted by the bootstrapped Administrator user."""
        return self.issue_bearer_token(encryption_jwk)

    def _sign_ps256(self, signing_input: bytes) -> bytes:
        """Sign a JWT input using the RSA-PSS parameters required by PS256."""
        return subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(self._signing_key_path),
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:-1",
            ],
            input=signing_input,
            capture_output=True,
            check=True,
        ).stdout

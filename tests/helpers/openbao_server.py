# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""Lifecycle helper for an isolated OpenBao dev server used by E2E tests."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from contextlib import suppress
from pathlib import Path

import httpx

from helpers.env import E2E_WAIT_SECS


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class OpenBaoServer:
    """Start and stop one in-memory OpenBao dev server for a test."""

    root_token = "e2e-openbao-root-token"

    def __init__(self, binary: str, scratch_dir: Path) -> None:
        self._binary = binary
        self._scratch_dir = scratch_dir
        self._port = _unused_loopback_port()
        self._proc: subprocess.Popen[bytes] | None = None
        self._log_path = scratch_dir / "openbao.log"
        self._log_file: object | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    def start(self) -> None:
        if self._proc is not None:
            return
        self._log_file = self._log_path.open("wb")
        self._proc = subprocess.Popen(
            [
                self._binary,
                "server",
                "-dev",
                f"-dev-root-token-id={self.root_token}",
                f"-dev-listen-address=127.0.0.1:{self._port}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.wait_until_ready()

    def wait_until_ready(self, *, max_wait: int = E2E_WAIT_SECS) -> None:
        deadline = time.monotonic() + max_wait
        last_error: Exception | None = None
        with httpx.Client(timeout=2.0, trust_env=False) as client:
            while time.monotonic() < deadline:
                if self._proc is not None and self._proc.poll() is not None:
                    raise RuntimeError(self._failure_message("OpenBao exited during startup"))
                try:
                    response = client.get(f"{self.base_url}/v1/sys/health")
                    if response.status_code in (200, 429):
                        return
                    last_error = RuntimeError(f"OpenBao health returned HTTP {response.status_code}")
                except httpx.HTTPError as exc:
                    last_error = exc
                time.sleep(0.2)
        detail = f": {last_error}" if last_error else ""
        raise TimeoutError(self._failure_message(f"OpenBao did not become ready within {max_wait}s{detail}"))

    def stop(self) -> None:
        proc = self._proc
        if proc is not None and proc.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
        self._proc = None
        if self._log_file is not None:
            self._log_file.close()  # type: ignore[union-attr]
            self._log_file = None

    def write_kv(self, path: str, values: dict[str, str]) -> None:
        """Write one KV v2 secret below the E2E ``secret`` mount."""
        with httpx.Client(timeout=5.0, trust_env=False) as client:
            response = client.post(
                f"{self.base_url}/v1/secret/data/{path.strip('/')}",
                headers={"X-Vault-Token": self.root_token},
                json={"data": values},
            )
        response.raise_for_status()

    def _failure_message(self, message: str) -> str:
        return f"{message}; OpenBao log: {self._log_path}"

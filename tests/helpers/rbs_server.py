# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""Start/stop the RBS binary for e2e tests."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import httpx
import yaml

from helpers.env import E2E_WAIT_SECS


class RbsServer:
    """Manage a single RBS process for one listen configuration."""

    def __init__(self, binary: Path, scratch_dir: Path, repo_root: Path) -> None:
        self._binary = binary
        self._scratch_dir = scratch_dir
        self._repo_root = repo_root
        self._proc: subprocess.Popen[bytes] | None = None
        self._started_with_setsid = False
        self._pub_key_path = self._scratch_dir / "e2e_pub.pem"
        self._db_path = self._scratch_dir / "rbs.db"
        self._log_path: Path | None = None

    def _failure_diagnostics(self) -> str:
        parts: list[str] = []
        if self._proc is not None:
            rc = self._proc.poll()
            if rc is not None:
                parts.append(f"process exit code {rc}")
        if self._log_path is not None and self._log_path.is_file():
            parts.append(f"server log: {self._log_path}")
        return "; ".join(parts) if parts else "no server log captured"

    def ensure_e2e_materials(self) -> None:
        """Generate RSA public key and sqlite DB file required by RBS startup."""
        if not self._pub_key_path.is_file():
            key_path = self._scratch_dir / "e2e_key.pem"
            subprocess.run(
                ["openssl", "genrsa", "-out", str(key_path), "2048"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["openssl", "rsa", "-in", str(key_path), "-pubout", "-out", str(self._pub_key_path)],
                check=True,
                capture_output=True,
            )
            key_path.unlink(missing_ok=True)
        self._db_path.touch(exist_ok=True)

    def write_config(
        self,
        *,
        listen_addr: str,
        https_enabled: bool,
        cert_file: str = "",
        key_file: str = "",
        log_name: str = "rbs.log",
    ) -> Path:
        self.ensure_e2e_materials()
        pub_key = str(self._pub_key_path)
        db_url = f"sqlite:///{self._db_path}"
        self._log_path = self._scratch_dir / log_name
        config: dict[str, Any] = {
            "rest": {
                "listen_addr": listen_addr,
                "https": {
                    "enabled": https_enabled,
                    "cert_file": cert_file,
                    "key_file": key_file,
                },
            },
            "logging": {
                "level": "info",
                "format": "text",
                "file_path": str(self._log_path),
            },
            "auth": {
                "attest_token": {
                    "public_key_path": pub_key,
                    "issuer": "Global Trust Authority",
                },
            },
            "storage": {
                "db_type": "sqlite",
                "max_connections": 10,
                "timeout": 30,
                "url": db_url,
                "sql_file_path": "rbs/rdb_sql/sqlite_rbs.sql",
            },
            "admin": {
                "max_users": 10,
                "admin_key": {
                    "public_key_path": pub_key,
                },
            },
            "attestation": {
                "default_as_provider": "gta",
                # Version-only e2e: /rbs/version does not call GTA. Port 9 (discard) satisfies
                # required attestation.backends config without a mock server. Attestation-flow
                # tests must replace this with a reachable GTA stub or mock base_url.
                "backends": {
                    "gta": {
                        "mode": "rest",
                        "rest": {
                            "base_url": "http://127.0.0.1:9",
                            "timeout_secs": 5,
                            "retries": 0,
                            "tls_verify": False,
                            "ca_file": "",
                            "credentials": {
                                "user_id": "e2e",
                            },
                        },
                    },
                },
            },
        }
        config_path = self._scratch_dir / "rbs.yaml"
        config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        return config_path

    def start(self, config_path: Path) -> None:
        self.stop()
        cmd = [str(self._binary), "--config", str(config_path)]
        setsid = shutil.which("setsid")
        if setsid:
            self._proc = subprocess.Popen(
                [setsid, *cmd],
                cwd=self._repo_root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._started_with_setsid = True
        else:
            self._proc = subprocess.Popen(
                cmd,
                cwd=self._repo_root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._started_with_setsid = False

    def stop(self) -> None:
        proc = self._proc
        if proc is None:
            return
        if proc.poll() is not None:
            self._proc = None
            self._started_with_setsid = False
            return
        pid = proc.pid
        with suppress(ProcessLookupError):
            if self._started_with_setsid:
                os.killpg(pid, signal.SIGTERM)
            else:
                if shutil.which("pkill"):
                    subprocess.run(
                        ["pkill", "-TERM", "-P", str(pid)],
                        check=False,
                        capture_output=True,
                    )
                proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                if self._started_with_setsid:
                    os.killpg(pid, signal.SIGKILL)
                else:
                    proc.kill()
            proc.wait(timeout=5)
        self._proc = None
        self._started_with_setsid = False

    def wait_for_version(
        self,
        base_url: str,
        *,
        verify: bool = True,
        max_wait: int = E2E_WAIT_SECS,
    ) -> None:
        deadline = time.monotonic() + max_wait
        last_error: Exception | None = None
        with httpx.Client(verify=verify, timeout=2.0) as client:
            while time.monotonic() < deadline:
                if self._proc is not None and self._proc.poll() is not None:
                    raise RuntimeError(
                        f"RBS server process exited unexpectedly ({self._failure_diagnostics()})"
                    )
                try:
                    resp = client.get(f"{base_url}/rbs/version")
                    if resp.status_code == 200:
                        return
                    last_error = RuntimeError(
                        f"GET /rbs/version returned HTTP {resp.status_code}"
                    )
                except httpx.HTTPError as exc:
                    last_error = exc
                time.sleep(1)
        detail = f": {last_error}" if last_error else ""
        diag = self._failure_diagnostics()
        raise TimeoutError(
            f"server did not return 200 from /rbs/version within {max_wait}s{detail}\n{diag}"
        )

    @staticmethod
    def generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            capture_output=True,
        )

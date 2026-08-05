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
import ssl
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
        self._private_key_path = self._scratch_dir / "e2e_key.pem"
        self._pub_key_path = self._scratch_dir / "e2e_pub.pem"
        self._db_path = self._scratch_dir / "rbs.db"
        self._log_path: Path | None = None
        self._process_log_path: Path | None = None
        self._process_log_file: Any | None = None

    def _failure_diagnostics(self) -> str:
        parts: list[str] = []
        if self._proc is not None:
            rc = self._proc.poll()
            if rc is not None:
                parts.append(f"process exit code {rc}")
        if self._log_path is not None and self._log_path.is_file():
            parts.append(f"server log: {self._log_path}")
        if self._process_log_path is not None and self._process_log_path.is_file():
            parts.append(f"server stderr: {self._process_log_path}")
        return "; ".join(parts) if parts else "no server log captured"

    def ensure_e2e_materials(self) -> None:
        """Generate RSA public key and sqlite DB file required by RBS startup."""
        if not self._pub_key_path.is_file():
            subprocess.run(
                ["openssl", "genrsa", "-out", str(self._private_key_path), "2048"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["openssl", "rsa", "-in", str(self._private_key_path), "-pubout", "-out", str(self._pub_key_path)],
                check=True,
                capture_output=True,
            )
        self._db_path.touch(exist_ok=True)

    @property
    def attestation_signing_key_path(self) -> Path:
        """Private key paired with RBS's temporary AttestToken verification key."""
        self.ensure_e2e_materials()
        return self._private_key_path

    @property
    def attestation_public_key_path(self) -> Path:
        """Public half of the temporary key used by the bootstrapped admin user."""
        self.ensure_e2e_materials()
        return self._pub_key_path

    @property
    def attestation_private_key_path(self) -> Path:
        """Private key used by E2E clients to decrypt returned JWE content."""
        self.ensure_e2e_materials()
        return self._private_key_path

    @property
    def database_path(self) -> Path:
        """SQLite database used by the E2E deployment."""
        self.ensure_e2e_materials()
        return self._db_path

    def write_config(
        self,
        *,
        listen_addr: str,
        https_enabled: bool,
        cert_file: str = "",
        key_file: str = "",
        log_name: str = "rbs.log",
        gta_base_url: str = "http://127.0.0.1:9",
        openbao_base_url: str | None = None,
        openbao_token: str = "",
        rate_limit_enabled: bool = False,
        requests_per_sec: int = 60,
        burst: int | None = None,
        trusted_proxy_addrs: list[str] | None = None,
        max_users: int = 10,
        max_policies: int = 10,
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
                "rate_limit": {
                    "enabled": rate_limit_enabled,
                    "requests_per_sec": requests_per_sec,
                    "burst": burst,
                },
                "trusted_proxy": {"addrs": trusted_proxy_addrs or []},
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
                "bearer_token": {
                    "issuer": "rbs-cli",
                    "audience": "globaltrustauthority-rbs",
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
                "max_users": max_users,
                "admin_key": {
                    "public_key_path": pub_key,
                },
            },
            "policy": {
                "max_per_user": max_policies,
            },
            "attestation": {
                "default_as_provider": "gta",
                "backends": {
                    "gta": {
                        "mode": "rest",
                        "rest": {
                            "base_url": gta_base_url,
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
        if openbao_base_url is not None:
            config["resource"] = {
                "backends": {
                    "vault": {
                        "type": "vault",
                        "url": openbao_base_url,
                        "token": openbao_token,
                        "mount_path": "secret",
                        "kv_version": "v2",
                        "verify_ssl": False,
                        "timeout": 5,
                        "max_connections": 10,
                        "max_retries": 0,
                    }
                }
            }
        config_path = self._scratch_dir / "rbs.yaml"
        config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        return config_path

    def start(self, config_path: Path) -> None:
        self.stop()
        cmd = [str(self._binary), "--config", str(config_path)]
        self._process_log_path = self._scratch_dir / "rbs-process.log"
        self._process_log_file = self._process_log_path.open("wb")
        setsid = shutil.which("setsid")
        if setsid:
            self._proc = subprocess.Popen(
                [setsid, *cmd],
                cwd=self._repo_root,
                stdin=subprocess.DEVNULL,
                stdout=self._process_log_file,
                stderr=subprocess.STDOUT,
            )
            self._started_with_setsid = True
        else:
            self._proc = subprocess.Popen(
                cmd,
                cwd=self._repo_root,
                stdin=subprocess.DEVNULL,
                stdout=self._process_log_file,
                stderr=subprocess.STDOUT,
            )
            self._started_with_setsid = False

    def stop(self) -> None:
        proc = self._proc
        if proc is None:
            self._close_process_log()
            return
        if proc.poll() is not None:
            self._proc = None
            self._started_with_setsid = False
            self._close_process_log()
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

        self._close_process_log()

    def _close_process_log(self) -> None:
        if self._process_log_file is not None:
            self._process_log_file.close()
            self._process_log_file = None

    def wait_for_version(
        self,
        base_url: str,
        *,
        verify: bool | ssl.SSLContext = True,
        max_wait: int = E2E_WAIT_SECS,
    ) -> None:
        deadline = time.monotonic() + max_wait
        last_error: Exception | None = None
        # E2E services always run on loopback. Do not inherit a developer or CI
        # proxy configuration, which can redirect local readiness checks.
        with httpx.Client(verify=verify, timeout=2.0, trust_env=False) as client:
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
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )

# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

"""Lifecycle helper for a provisioned software TPM used by E2E tests."""

from __future__ import annotations

import base64
import json
import shutil
import socket
import subprocess
import time
from contextlib import suppress
from pathlib import Path

import yaml

from helpers.env import E2E_WAIT_SECS


class SwtpmServer:
    """Run a TPM 2.0 socket and provision the AK expected by GTA's real plugin."""

    host = "127.0.0.1"
    command_port = 2321
    control_port = 2322
    ak_handle = 0x81010020
    ak_nv_index = 0x150001B

    def __init__(self, scratch_dir: Path, evidence_fixture: Path) -> None:
        self._scratch_dir = scratch_dir
        self._evidence_fixture = evidence_fixture
        self._proc: subprocess.Popen[bytes] | None = None
        self._log_path = scratch_dir / "swtpm.log"
        self._boot_log_path = scratch_dir / "binary_bios_measurements"
        self._ima_log_path = scratch_dir / "ascii_runtime_measurements"
        self._dim_log_path = scratch_dir / "dim_runtime_measurements"

    @property
    def boot_log_path(self) -> Path:
        return self._boot_log_path

    @property
    def ima_log_path(self) -> Path:
        return self._ima_log_path

    @property
    def dim_log_path(self) -> Path:
        return self._dim_log_path

    @property
    def tcti_config(self) -> str:
        # GTA currently validates this as an enum-like value, so host/port cannot be appended.
        return "swtpm"

    @classmethod
    def required_tools(cls) -> tuple[str, ...]:
        return (
            "swtpm",
            "tpm2_getrandom",
            "tpm2_createek",
            "tpm2_createak",
            "tpm2_flushcontext",
            "tpm2_evictcontrol",
            "tpm2_readpublic",
            "tpm2_nvdefine",
            "tpm2_nvwrite",
            "tpm2_eventlog",
            "tpm2_pcrextend",
            "openssl",
        )

    @classmethod
    def missing_tools(cls) -> list[str]:
        return [tool for tool in cls.required_tools() if shutil.which(tool) is None]

    def start(self) -> None:
        if self._proc is not None:
            return
        self._assert_fixed_ports_available()
        self._proc = subprocess.Popen(
            [
                "swtpm",
                "socket",
                "--tpm2",
                "--tpmstate",
                f"dir={self._scratch_dir}",
                "--server",
                f"type=tcp,port={self.command_port},bindaddr={self.host}",
                "--ctrl",
                f"type=tcp,port={self.control_port},bindaddr={self.host}",
                "--flags",
                "not-need-init,startup-clear",
                "--log",
                f"file={self._log_path},level=5",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            self._wait_until_ready()
            self._provision_attestation_key()
            self._write_measurement_log_fixtures()
            self._replay_boot_log()
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        self._proc = None

    def _tcti(self) -> str:
        return f"swtpm:host={self.host},port={self.command_port}"

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(command, check=True, capture_output=True)

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + E2E_WAIT_SECS
        last_error = "no TPM response"
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                raise RuntimeError(self._failure_message("swtpm exited during startup"))
            result = subprocess.run(
                ["tpm2_getrandom", "-T", self._tcti(), "--hex", "1"],
                capture_output=True,
            )
            if result.returncode == 0:
                return
            last_error = result.stderr.decode("utf-8", errors="replace").strip()
            time.sleep(0.2)
        raise TimeoutError(self._failure_message(f"swtpm did not become ready: {last_error}"))

    def _provision_attestation_key(self) -> None:
        ek_context = self._scratch_dir / "ek.ctx"
        ak_context = self._scratch_dir / "ak.ctx"
        ak_public = self._scratch_dir / "ak.pub"
        ak_name = self._scratch_dir / "ak.name"
        ak_pem = self._scratch_dir / "ak.pem"
        ca_key = self._scratch_dir / "ca.key"
        ca_cert = self._scratch_dir / "ca.crt"
        ak_cert = self._scratch_dir / "ak.crt"
        ak_der = self._scratch_dir / "ak.der"
        tcti = self._tcti()

        self._run(["tpm2_createek", "-T", tcti, "-G", "rsa", "-c", str(ek_context)])
        self._run(
            [
                "tpm2_createak",
                "-T",
                tcti,
                "-C",
                str(ek_context),
                "-G",
                "rsa",
                "-g",
                "sha256",
                "-s",
                "rsassa",
                "-c",
                str(ak_context),
                "-u",
                str(ak_public),
                "-n",
                str(ak_name),
            ]
        )
        # swtpm exposes only a small transient-object pool. Flush the EK before reloading the AK.
        self._run(["tpm2_flushcontext", "-T", tcti, "-t"])
        self._run(
            ["tpm2_evictcontrol", "-T", tcti, "-C", "o", "-c", str(ak_context), hex(self.ak_handle)]
        )
        self._run(
            ["tpm2_readpublic", "-T", tcti, "-c", hex(self.ak_handle), "-f", "pem", "-o", str(ak_pem)]
        )

        self._run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(ca_key)]
        )
        self._run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                str(ca_key),
                "-subj",
                "/CN=E2E-TPM-CA",
                "-days",
                "1",
                "-out",
                str(ca_cert),
            ]
        )
        self._run(
            [
                "openssl",
                "x509",
                "-new",
                "-force_pubkey",
                str(ak_pem),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-set_serial",
                "1",
                "-subj",
                "/CN=E2E-TPM-AK",
                "-days",
                "1",
                "-out",
                str(ak_cert),
            ]
        )
        self._run(["openssl", "x509", "-in", str(ak_cert), "-outform", "DER", "-out", str(ak_der)])

        self._run(
            [
                "tpm2_nvdefine",
                "-T",
                tcti,
                "-C",
                "o",
                "-s",
                str(ak_der.stat().st_size),
                "-a",
                "ownerread|ownerwrite|authread|authwrite",
                hex(self.ak_nv_index),
            ]
        )
        self._run(
            [
                "tpm2_nvwrite",
                "-T",
                tcti,
                "-C",
                hex(self.ak_nv_index),
                "-i",
                str(ak_der),
                hex(self.ak_nv_index),
            ]
        )

    def _write_measurement_log_fixtures(self) -> None:
        evidence = json.loads(self._evidence_fixture.read_text(encoding="utf-8"))
        logs = evidence.get("logs")
        if not isinstance(logs, list):
            raise RuntimeError(f"measurement logs missing from fixture: {self._evidence_fixture}")
        by_type = {
            entry.get("log_type"): entry.get("log_data")
            for entry in logs
            if isinstance(entry, dict)
        }
        for log_type, destination in (
            ("boot_log", self._boot_log_path),
            ("ima_log", self._ima_log_path),
        ):
            encoded = by_type.get(log_type)
            if not isinstance(encoded, str):
                raise RuntimeError(f"{log_type} missing from fixture: {self._evidence_fixture}")
            destination.write_bytes(base64.b64decode(encoded, validate=True))
        # Keep the unified TPM DIM path valid while returning a deterministic empty DIM log.
        self._dim_log_path.write_bytes(b"")

    def _replay_boot_log(self) -> None:
        """Extend the event-log digests so swtpm PCRs match the supplied boot log."""
        parsed = yaml.safe_load(
            self._run(["tpm2_eventlog", str(self._boot_log_path)]).stdout.decode("utf-8")
        )
        events = parsed.get("events") if isinstance(parsed, dict) else None
        if not isinstance(events, list):
            raise RuntimeError(f"cannot parse boot events from {self._boot_log_path}")

        for event in events:
            if not isinstance(event, dict) or event.get("EventType") == "EV_NO_ACTION":
                continue
            pcr_index = event.get("PCRIndex")
            digests = event.get("Digests")
            if not isinstance(pcr_index, int) or not isinstance(digests, list):
                raise RuntimeError(f"invalid extending event in {self._boot_log_path}: {event!r}")
            for digest in digests:
                if not isinstance(digest, dict):
                    raise RuntimeError(f"invalid event digest in {self._boot_log_path}: {digest!r}")
                algorithm = digest.get("AlgorithmId")
                value = digest.get("Digest")
                if not isinstance(algorithm, str) or not isinstance(value, str):
                    raise RuntimeError(f"invalid event digest in {self._boot_log_path}: {digest!r}")
                self._run(
                    [
                        "tpm2_pcrextend",
                        "-T",
                        self._tcti(),
                        f"{pcr_index}:{algorithm}={value}",
                    ]
                )

    def _assert_fixed_ports_available(self) -> None:
        sockets: list[socket.socket] = []
        try:
            for port in (self.command_port, self.control_port):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind((self.host, port))
                sockets.append(listener)
        except OSError as exc:
            raise RuntimeError(
                f"swtpm requires unused fixed ports {self.command_port}/{self.control_port}: {exc}"
            ) from exc
        finally:
            for listener in sockets:
                with suppress(OSError):
                    listener.close()

    def _failure_message(self, message: str) -> str:
        return f"{message}; swtpm log: {self._log_path}"

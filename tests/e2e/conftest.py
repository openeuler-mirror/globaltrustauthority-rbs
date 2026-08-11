# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

from __future__ import annotations

import base64
import re
import sqlite3
import shutil
import socket
import ssl
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import pytest
import yaml

from helpers.env import E2E_PORT_HTTP
from helpers.fake_gta import FakeGta
from helpers.openbao_server import OpenBaoServer
from helpers.rbs_build import E2eBuildError, rbs_e2e_cargo_env
from helpers.rbs_server import RbsServer
from helpers.swtpm_server import SwtpmServer


@dataclass(frozen=True)
class RbsApi:
    """Connection details for one isolated RBS E2E deployment."""

    base_url: str
    admin_token: str
    encryption_jwk: dict[str, str]
    encryption_private_key_path: Path
    encryption_public_key_path: Path
    database_path: Path
    openbao: OpenBaoServer
    fake_gta: FakeGta
    ca_cert_path: Path | None = None

    @property
    def admin_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.admin_token}"}

    def bearer_headers(
        self,
        subject: str,
        *,
        role: str | None = "user",
        expires_in: int = 300,
        enc_pubkey: Any | None = None,
        include_enc_pubkey: bool = True,
    ) -> dict[str, str]:
        """Return a signed Bearer header for a user registered with the E2E key."""
        token = self.fake_gta.issue_bearer_token(
            self.encryption_jwk,
            subject=subject,
            role=role,
            expires_in=expires_in,
            enc_pubkey=enc_pubkey,
            include_enc_pubkey=include_enc_pubkey,
        )
        return {"Authorization": f"Bearer {token}"}

    def reset_database(self) -> None:
        """Remove mutable API data while preserving the bootstrap administrator."""
        with sqlite3.connect(self.database_path, timeout=30) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("DELETE FROM t_res_info")
            connection.execute("DELETE FROM t_res_policy")
            connection.execute("DELETE FROM t_user_info WHERE username <> ?", ("Administrator",))
            connection.commit()


@dataclass(frozen=True)
class RbcKeyMaterial:
    """Dedicated 4096-bit RSA key pair for RBC JWE workflows."""

    private_key_path: Path
    public_key_path: Path
    public_jwk: dict[str, str]


@pytest.fixture(scope="session")
def rbs_binary(repo_root: Path) -> Path:
    """Build the RBS REST binary once for every selected E2E suite."""
    for tool in ("openssl", "cargo"):
        if shutil.which(tool) is None:
            pytest.fail(f"{tool} is required for RBS e2e tests", pytrace=False)
    binary = repo_root / "target" / "debug" / "rbs"
    try:
        build_env = rbs_e2e_cargo_env(repo_root)
    except E2eBuildError as exc:
        pytest.fail(str(exc), pytrace=False)
    try:
        subprocess.run(
            ["cargo", "build", "-p", "rbs", "--bin", "rbs", "--features", "rest", "--quiet"],
            cwd=repo_root,
            check=True,
            env=build_env,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.fail(f"failed to build RBS binary with cargo: {exc}", pytrace=False)
    if not binary.is_file():
        pytest.fail(f"RBS binary not found at {binary}", pytrace=False)
    return binary


def _rsa_public_jwk(public_key_path: Path) -> dict[str, str]:
    """Convert the temporary RSA PEM key to the JWK required for JWE encryption."""
    output = subprocess.run(
        ["openssl", "rsa", "-pubin", "-in", str(public_key_path), "-text", "-noout"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    modulus_match = re.search(r"Modulus:\s*([0-9a-fA-F:\s]+?)\s*Exponent:", output)
    exponent_match = re.search(r"Exponent:\s*(\d+)", output)
    if modulus_match is None or exponent_match is None:
        raise RuntimeError("unable to convert E2E RSA public key to JWK")

    modulus = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", modulus_match.group(1))).lstrip(b"\0")
    exponent = int(exponent_match.group(1)).to_bytes(3, "big").lstrip(b"\0")
    return {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(modulus).rstrip(b"=").decode("ascii"),
        "e": base64.urlsafe_b64encode(exponent).rstrip(b"=").decode("ascii"),
    }


def _unused_loopback_port() -> int:
    """Reserve and release one loopback port for a serial E2E deployment."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@contextmanager
def _running_rbs_environment(
    rbs_binary: Path,
    repo_root: Path,
    tmp_path_factory: pytest.TempPathFactory,
    *,
    scratch_name: str,
    port: int,
    https_enabled: bool,
    max_users: int,
    max_policies: int,
) -> Iterator[RbsApi]:
    """Run one real RBS, Fake GTA, and OpenBao deployment with guaranteed teardown."""
    openbao_binary = shutil.which("bao") or shutil.which("openbao")
    if openbao_binary is None:
        pytest.fail(
            "bao or openbao is required for RBS, RBC, and tools E2E tests",
            pytrace=False,
        )

    scratch_dir = tmp_path_factory.mktemp(scratch_name)
    rbs = RbsServer(rbs_binary, scratch_dir, repo_root)
    gta = FakeGta(rbs.attestation_signing_key_path)
    openbao = OpenBaoServer(openbao_binary, scratch_dir)
    cert_path: Path | None = None
    key_path: Path | None = None
    if https_enabled:
        cert_path = scratch_dir / "rbs-server.crt"
        key_path = scratch_dir / "rbs-server.key"
        RbsServer.generate_self_signed_cert(cert_path, key_path)
    try:
        gta.start()
        openbao.start()
        listen = f"127.0.0.1:{port}"
        encryption_jwk = _rsa_public_jwk(rbs.attestation_public_key_path)
        config = rbs.write_config(
            listen_addr=listen,
            https_enabled=https_enabled,
            cert_file=str(cert_path) if cert_path is not None else "",
            key_file=str(key_path) if key_path is not None else "",
            gta_base_url=gta.base_url,
            openbao_base_url=openbao.base_url,
            openbao_token=openbao.root_token,
            max_users=max_users,
            max_policies=max_policies,
        )
        rbs.start(config)
        scheme = "https" if https_enabled else "http"
        host = "localhost" if https_enabled else "127.0.0.1"
        base_url = f"{scheme}://{host}:{port}"
        verify = ssl.create_default_context(cafile=str(cert_path)) if cert_path is not None else True
        rbs.wait_for_version(base_url, verify=verify)
        yield RbsApi(
            base_url=base_url,
            admin_token=gta.issue_admin_bearer_token(encryption_jwk),
            encryption_jwk=encryption_jwk,
            encryption_private_key_path=rbs.attestation_private_key_path,
            encryption_public_key_path=rbs.attestation_public_key_path,
            database_path=rbs.database_path,
            openbao=openbao,
            fake_gta=gta,
            ca_cert_path=cert_path,
        )
    finally:
        rbs.stop()
        openbao.stop()
        gta.stop()


@pytest.fixture(scope="session")
def rbs_environment(
    rbs_binary: Path,
    repo_root: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> RbsApi:
    """Start the shared RBS deployment with production-like quotas."""
    with _running_rbs_environment(
        rbs_binary,
        repo_root,
        tmp_path_factory,
        scratch_name="rbs_environment",
        port=E2E_PORT_HTTP,
        https_enabled=False,
        max_users=10,
        max_policies=10,
    ) as api:
        yield api


@pytest.fixture(scope="session")
def rbc_tools_environment(
    rbs_binary: Path,
    repo_root: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> RbsApi:
    """Start the shared high-quota deployment for client and CLI workflows."""
    with _running_rbs_environment(
        rbs_binary,
        repo_root,
        tmp_path_factory,
        scratch_name="rbc_tools_environment",
        port=_unused_loopback_port(),
        https_enabled=False,
        max_users=100,
        max_policies=100,
    ) as api:
        yield api


@pytest.fixture(scope="session")
def https_rbc_tools_environment(
    rbs_binary: Path,
    repo_root: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> RbsApi:
    """Start the shared HTTPS deployment for RBC/tools TLS workflows."""
    with _running_rbs_environment(
        rbs_binary,
        repo_root,
        tmp_path_factory,
        scratch_name="https_rbc_tools_environment",
        port=_unused_loopback_port(),
        https_enabled=True,
        max_users=100,
        max_policies=100,
    ) as api:
        yield api


@pytest.fixture(autouse=True)
def reset_e2e_database(request: pytest.FixtureRequest) -> Iterator[None]:
    """Reset API data after tests that use a shared RBS deployment."""
    environment_name = next(
        (
            name
            for name in ("rbs_api", "https_rbc_tools_environment")
            if name in request.fixturenames
        ),
        None,
    )
    if environment_name is None:
        yield
        return

    api = request.getfixturevalue(environment_name)
    try:
        yield
    finally:
        api.reset_database()


@pytest.fixture
def rbs_api(request: pytest.FixtureRequest) -> RbsApi:
    """Lazily select the suite deployment without starting an unused RBS process."""
    if request.node.get_closest_marker("rbc") or request.node.get_closest_marker("tools"):
        return request.getfixturevalue("rbc_tools_environment")
    return request.getfixturevalue("rbs_environment")


@pytest.fixture(scope="session")
def rbc_key_material(tmp_path_factory: pytest.TempPathFactory) -> RbcKeyMaterial:
    """Generate RBC-owned key material separately from RBS token-signing keys."""
    scratch_dir = tmp_path_factory.mktemp("e2e_rbc_keys")
    private_key = scratch_dir / "rbc-private.pem"
    public_key = scratch_dir / "rbc-public.pem"
    subprocess.run(
        ["openssl", "genrsa", "-out", str(private_key), "4096"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "rsa", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        check=True,
        capture_output=True,
    )
    return RbcKeyMaterial(
        private_key_path=private_key,
        public_key_path=public_key,
        public_jwk=_rsa_public_jwk(public_key),
    )


def _build_workspace_binary(repo_root: Path, package: str, binary_name: str) -> Path:
    """Build and return one workspace CLI binary used by black-box E2E tests."""
    subprocess.run(
        ["cargo", "build", "-p", package, "--bin", binary_name, "--quiet"],
        cwd=repo_root,
        check=True,
    )
    binary = repo_root / "target" / "debug" / binary_name
    if not binary.is_file():
        raise RuntimeError(f"built binary not found: {binary}")
    return binary


@pytest.fixture(scope="session")
def rbc_binary(repo_root: Path) -> Path:
    """Build the standalone RBC CLI once."""
    return _build_workspace_binary(repo_root, "rbc", "rbc-cli")


@pytest.fixture(scope="session")
def rbs_cli_binary(repo_root: Path) -> Path:
    """Build the unified RBS CLI once."""
    return _build_workspace_binary(repo_root, "rbs-cli", "rbs-cli")


@pytest.fixture(scope="session")
def rbc_library(repo_root: Path) -> Path:
    """Build the RBC shared library used by the C ABI E2E smoke test."""
    subprocess.run(["cargo", "build", "-p", "rbc", "--lib", "--quiet"], cwd=repo_root, check=True)
    library = repo_root / "target" / "debug" / "librbc.so"
    if not library.is_file():
        raise RuntimeError(f"built RBC shared library not found: {library}")
    return library


@pytest.fixture(scope="session")
def rbc_sdk_probe(repo_root: Path) -> Path:
    """Build the standalone executable that calls the public Rust RBC SDK."""
    probe_dir = repo_root / "tests" / "fixtures" / "rbc_sdk_probe"
    subprocess.run(
        ["cargo", "build", "--quiet"],
        cwd=probe_dir,
        check=True,
    )
    binary = probe_dir / "target" / "debug" / "rbc-sdk-e2e-probe"
    if not binary.is_file():
        raise RuntimeError(f"built RBC SDK probe not found: {binary}")
    return binary


@pytest.fixture(scope="session")
def rbc_ffi_smoke(repo_root: Path, rbc_library: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile the C ABI lifecycle smoke program against the generated RBC header."""
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.fail("a C compiler is required for the RBC FFI E2E smoke test", pytrace=False)
    output = tmp_path_factory.mktemp("e2e_rbc_ffi") / "rbc-ffi-smoke"
    source = repo_root / "tests" / "fixtures" / "rbc_ffi_smoke" / "main.c"
    subprocess.run(
        [
            compiler,
            "-I",
            str(repo_root / "rbc" / "include"),
            str(source),
            "-L",
            str(rbc_library.parent),
            "-lrbc",
            "-lpthread",
            "-ldl",
            "-lm",
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
    )
    return output


@pytest.fixture(scope="session")
def tpm_plugin(repo_root: Path) -> Path:
    """Build the E2E wrapper around GTA's real unified TPM dynamic plugin."""
    plugin_dir = repo_root / "tests" / "fixtures" / "tpm_attester"
    subprocess.run(
        ["cargo", "build", "--quiet"],
        cwd=plugin_dir,
        check=True,
    )
    plugin = plugin_dir / "target" / "debug" / "libe2e_tpm_attester.so"
    if not plugin.is_file():
        raise RuntimeError(f"built TPM plugin not found: {plugin}")
    return plugin


def _write_agent_config(
    api: RbsApi, tpm_plugin: Path, swtpm: SwtpmServer, scratch_dir: Path
) -> Path:
    """Write one attestation_client config backed by a provisioned software TPM."""
    config_path = scratch_dir / "agent_config.yaml"
    config = {
        "agent": {
            "listen_enabled": False,
            "listen_address": "127.0.0.1",
            "listen_port": 8088,
            "uuid": "e2e-node",
            "user_id": "e2e-user",
            "apikey": "e2e-api-key",
            "token_fmt": "eat",
            "uds": {"uds_enable": False},
        },
        "server": {"server_url": api.fake_gta.base_url, "tls": None},
        "plugins": [
            {
                "name": "tpm",
                "path": str(tpm_plugin),
                "policy_id": [],
                "enabled": True,
                "mode": "host",
                "params": {
                    "attester_type": "tpm",
                    "tcti_config": swtpm.tcti_config,
                    "ak_certs": [
                        {
                            "cert_type": "iak",
                            "ak_handle": swtpm.ak_handle,
                            "ak_nv_index": swtpm.ak_nv_index,
                        }
                    ],
                    "pcr_selections": {"banks": [0, 1, 2, 3, 4, 5, 6, 7], "hash_alg": "sha256"},
                    "quote_signature_scheme": {"signature_alg": "rsassa", "hash_alg": "sha256"},
                    "boot_log_file_path": str(swtpm.boot_log_path),
                    "ima_log_file_path": str(swtpm.ima_log_path),
                    "dim_log_file_path": str(swtpm.dim_log_path),
                },
            }
        ],
        "schedulers": [],
        "logging": {"level": "info", "file": str(scratch_dir / "agent.log")},
    }
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return config_path


@pytest.fixture(scope="session")
def swtpm_instance(repo_root: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[SwtpmServer]:
    """Run one provisioned software TPM for real unified TPM evidence collection."""
    missing = SwtpmServer.missing_tools()
    if missing:
        pytest.fail(f"Native-attestation E2E requires: {', '.join(missing)}", pytrace=False)
    evidence_fixture = (
        repo_root / "tests" / "fixtures" / "tpm_attester" / "data" / "tpm_evidence.json"
    )
    swtpm = SwtpmServer(tmp_path_factory.mktemp("e2e_swtpm"), evidence_fixture)
    try:
        swtpm.start()
        yield swtpm
    finally:
        swtpm.stop()


@pytest.fixture
def agent_config_path(
    rbs_api: RbsApi,
    tpm_plugin: Path,
    swtpm_instance: SwtpmServer,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    """Write an attestation_client config for the selected HTTP deployment."""
    return _write_agent_config(
        rbs_api, tpm_plugin, swtpm_instance, tmp_path_factory.mktemp("e2e_attestation_agent")
    )


@pytest.fixture
def https_agent_config_path(
    https_rbc_tools_environment: RbsApi,
    tpm_plugin: Path,
    swtpm_instance: SwtpmServer,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    """Write an attestation_client config for the HTTPS deployment's Fake GTA."""
    return _write_agent_config(
        https_rbc_tools_environment,
        tpm_plugin,
        swtpm_instance,
        tmp_path_factory.mktemp("e2e_https_attestation_agent"),
    )


@pytest.fixture
def rbc_config_path(
    rbs_api: RbsApi,
    agent_config_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    """Write the RBC YAML consumed by the C ABI lifecycle smoke test."""
    config_path = tmp_path_factory.mktemp("e2e_rbc_config") / "rbc.yaml"
    config = {
        "rbs": {"base_url": rbs_api.base_url, "timeout_secs": 30},
        "evidence_provider": [
            {"type": "native", "enabled": True, "config_path": str(agent_config_path)},
        ],
        "token_provider": [
            {"type": "rbs", "enabled": True, "config_path": str(agent_config_path)},
        ],
    }
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return config_path

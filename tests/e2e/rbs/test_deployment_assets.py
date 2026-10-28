# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
# PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

"""Static deployment-asset contract tests (no cluster, no binary, no fixtures).

Locks the k8s manifests, dockerfile, compose file and docs against drift from the
reviewed design (AR-002 module design, K1-K10). Runs in the regular pytest gate:
each test parses repo files only and finishes in milliseconds.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.e2e, pytest.mark.rbs]


def _read(repo_root: Path, rel: str) -> str:
    return (repo_root / rel).read_text(encoding="utf-8")


def _load_yaml(rel: str, repo_root: Path) -> dict:
    return yaml.safe_load(_read(repo_root, rel))


# ---------------------------------------------------------------------------
# TC7: dockerfile — self-contained image (SQL scripts inside, EXPOSE 6666/6667)
# ---------------------------------------------------------------------------


def test_dockerfile_self_contained_sql_and_expose(repo_root: Path) -> None:
    text = _read(repo_root, "deployment/docker/dockerfile")
    # SQL schema directory copied into the image (RPM layout precedent).
    assert "COPY rbs/rdb_sql /usr/share/rbs/" in text
    # The copy source actually exists in the repo (guard against silent COPY breakage).
    assert (repo_root / "rbs/rdb_sql/sqlite_rbs.sql").is_file()
    # Exposed ports match the real listeners: business HTTPS 6666, health 6667.
    assert "EXPOSE 6666 6667" in text
    # Build chain anchors unchanged: two-stage build, runtime user, entrypoint.
    assert "cargo build --release --bin rbs" in text
    assert "USER rbs" in text
    assert 'CMD ["rbs"]' in text
    assert text.count("COPY rbs/conf /etc/rbs/") == 1


# ---------------------------------------------------------------------------
# TC8: rbs-compose.yaml — repaired smoke stack (required sections, in-image SQL,
# local key pair mount, no broken SQL bind mount)
# ---------------------------------------------------------------------------


def _compose_embedded_config(repo_root: Path) -> dict:
    compose = _load_yaml("deployment/docker/rbs-compose.yaml", repo_root)
    content = compose["configs"]["rbs_runtime_yaml"]["content"]
    assert isinstance(content, str)
    cfg = yaml.safe_load(content)
    assert isinstance(cfg, dict)
    return cfg


def test_compose_embedded_config_has_required_sections(repo_root: Path) -> None:
    cfg = _compose_embedded_config(repo_root)
    # REST on 6666 (aligned with the EXPOSE/port family; the file was never runnable before).
    assert cfg["rest"]["listen_addr"] == "127.0.0.1:6666"
    # Attestation: builtin smoke mode (no GTA required for local smoke).
    assert cfg["attestation"]["default_as_provider"] == "gta"
    assert cfg["attestation"]["backends"]["gta"]["mode"] == "builtin"
    # Auth: attest token verified by the locally generated smoke public key.
    assert cfg["auth"]["attest_token"]["public_key_path"] == "/etc/rbs/keys/smoke_pub.pem"
    assert cfg["auth"]["attest_token"]["issuer"]
    assert cfg["auth"]["bearer_token"]["issuer"] == "rbs-cli"
    assert cfg["auth"]["bearer_token"]["audience"] == "globaltrustauthority-rbs"
    # Admin bootstrap verified by the same local smoke public key.
    assert cfg["admin"]["admin_key"]["public_key_path"] == "/etc/rbs/keys/smoke_pub.pem"
    # Storage: explicit sqlite, schema from the self-contained image.
    assert cfg["storage"]["db_type"] == "sqlite"
    assert cfg["storage"]["sql_file_path"] == "/usr/share/rbs/sqlite_rbs.sql"
    assert "mode=rwc" in cfg["storage"]["url"]


def test_compose_mounts_fixed(repo_root: Path) -> None:
    compose = _load_yaml("deployment/docker/rbs-compose.yaml", repo_root)
    volumes = compose["services"]["rbs"]["volumes"]
    # Local smoke key pair mounted read-only; data on the named volume.
    assert "./keys/smoke_pub.pem:/etc/rbs/keys/smoke_pub.pem:ro" in volumes
    assert "rbs-data:/var/lib/rbs" in volumes
    # The original defect (bind-mounting a non-existent SQL file) must stay removed.
    assert not any("sqlite_rbs.sql" in v for v in volumes), f"SQL bind mount must not exist: {volumes}"
    # Smoke key pair directory is git-ignored (generated locally, never committed).
    assert "deployment/docker/keys/" in _read(repo_root, ".gitignore")


# ---------------------------------------------------------------------------
# TC1-TC6: deployment/k8s manifests — file set, zero-plaintext, field contracts
# ---------------------------------------------------------------------------

K8S_DIR = "deployment/k8s"
EXPECTED_MANIFESTS = sorted([
    "namespace.yaml",
    "pvc.yaml",
    "deployment.yaml",
    "service.yaml",
])


def _k8s_yaml(repo_root: Path, name: str) -> dict:
    return _load_yaml(f"{K8S_DIR}/{name}", repo_root)


def _container(repo_root: Path) -> dict:
    doc = _k8s_yaml(repo_root, "deployment.yaml")
    return doc["spec"]["template"]["spec"]["containers"][0]


# TC1: exactly the four main manifests (directory apply covers these only); the optional
def test_k8s_manifest_set_and_naming(repo_root: Path) -> None:
    k8s = repo_root / K8S_DIR
    yaml_files = sorted(p.name for p in k8s.glob("*.yaml"))
    assert yaml_files == EXPECTED_MANIFESTS
    assert not (k8s / ".gitkeep").exists()
    assert not any("secret" in p.name.lower() for p in k8s.iterdir())
    # NetworkPolicy is in the optional/ subdirectory (NOT applied by directory apply).
    assert (k8s / "optional" / "networkpolicy.yaml").is_file()



# TC2: zero plaintext secrets in any manifest (SR TC-008 hard requirement).
def test_k8s_manifests_zero_plaintext_secrets(repo_root: Path) -> None:
    for name in EXPECTED_MANIFESTS + ["optional/networkpolicy.yaml"]:
        text = _read(repo_root, f"{K8S_DIR}/{name}")
        for pattern in ("PRIVATE KEY", "kind: Secret", "password:", "token:"):
            assert pattern not in text, f"{name} must not contain {pattern!r}"


# TC3: Deployment contract — probes, strategy, mounts, resources, labels.
def test_k8s_deployment_contract(repo_root: Path) -> None:
    doc = _k8s_yaml(repo_root, "deployment.yaml")
    assert doc["kind"] == "Deployment"
    assert doc["metadata"]["namespace"] == "rbs"
    assert doc["metadata"]["labels"] == {"app": "rbs"}
    assert doc["spec"]["replicas"] == 1
    assert doc["spec"]["strategy"]["type"] == "Recreate"
    assert doc["spec"]["selector"]["matchLabels"] == {"app": "rbs"}
    assert doc["spec"]["template"]["metadata"]["labels"] == {"app": "rbs"}

    c = _container(repo_root)
    assert c["image"] == "globaltrustauthority-rbs/rbs:latest"
    assert c["imagePullPolicy"] == "IfNotPresent"
    # Named ports: https 6666 (business), health 6667 (probes).
    ports = {p["name"]: p["containerPort"] for p in c["ports"]}
    assert ports == {"https": 6666, "health": 6667}

    # Probes point at the health port with the reviewed parameters
    # (timeoutSeconds 2 matches the server-side 2s probe timeout).
    for probe_name, path in (("livenessProbe", "/livez"), ("readinessProbe", "/readyz")):
        probe = c[probe_name]
        assert probe["httpGet"] == {"path": path, "port": "health", "scheme": "HTTP"}
        assert probe["initialDelaySeconds"] == 10
        assert probe["periodSeconds"] == 10
        assert probe["timeoutSeconds"] == 2
        assert probe["failureThreshold"] == 3

    # Volume mounts: config subPath-mounted over the image file, keys/tls read-only, data PVC.
    mounts = {m["name"]: m for m in c["volumeMounts"]}
    assert mounts["config"] == {
        "name": "config",
        "mountPath": "/etc/rbs/rbs.yaml",
        "subPath": "rbs.yaml",
        "readOnly": True,
    }
    assert mounts["data"]["mountPath"] == "/var/lib/rbs"
    assert mounts["keys"]["mountPath"] == "/etc/rbs/keys" and mounts["keys"]["readOnly"] is True
    assert mounts["tls"]["mountPath"] == "/etc/rbs/tls" and mounts["tls"]["readOnly"] is True

    # Volumes reference the PVC, the ConfigMap and the two command-line-created Secrets.
    pod_spec = doc["spec"]["template"]["spec"]
    volumes = {v["name"]: v for v in pod_spec["volumes"]}
    assert volumes["data"]["persistentVolumeClaim"]["claimName"] == "rbs-data"
    assert volumes["keys"]["configMap"]["name"] == "rbs-keys"
    assert volumes["tls"]["secret"]["secretName"] == "rbs-tls"
    assert volumes["config"]["secret"]["secretName"] == "rbs-config"

    # Resources and security context defaults.
    assert c["resources"]["requests"] == {"cpu": "100m", "memory": "256Mi"}
    assert c["resources"]["limits"] == {"cpu": "1", "memory": "512Mi"}
    assert c["securityContext"] == {"allowPrivilegeEscalation": False}


# TC4: Service — NodePort 30666 -> 6666, health port NOT exposed.
def test_k8s_service_nodeport_and_no_health_exposure(repo_root: Path) -> None:
    doc = _k8s_yaml(repo_root, "service.yaml")
    spec = doc["spec"]
    assert spec["type"] == "NodePort"
    assert spec["selector"] == {"app": "rbs"}
    ports = spec["ports"]
    assert len(ports) == 1
    assert ports[0]["port"] == 6666
    assert ports[0]["targetPort"] == "https"
    assert ports[0]["nodePort"] == 30666
    assert 6667 not in [p.get("port") for p in ports], "health port must not be exposed via Service"


# TC5: Namespace / PVC contracts; the rbs-keys ConfigMap is created via
# `kubectl create configmap` in the guide (no placeholder-paste manifest), so only its
# Deployment-side reference is asserted (see TC3 volumes).
def test_k8s_namespace_pvc_and_pod_fsgroup(repo_root: Path) -> None:
    ns = _k8s_yaml(repo_root, "namespace.yaml")
    assert ns["kind"] == "Namespace"
    assert ns["metadata"]["name"] == "rbs"

    doc = _k8s_yaml(repo_root, "deployment.yaml")
    # fsGroup makes any provisioner's PVC group-writable by the non-root rbs user.
    assert doc["spec"]["template"]["spec"]["securityContext"] == {"fsGroup": 999}

    pvc = _k8s_yaml(repo_root, "pvc.yaml")
    assert pvc["metadata"]["name"] == "rbs-data"
    spec = pvc["spec"]
    assert spec["accessModes"] == ["ReadWriteOnce"]
    assert spec["resources"]["requests"]["storage"] == "1Gi"
    assert "storageClassName" not in spec  # cluster default StorageClass


# TC6: NetworkPolicy — dual ingress rules (same-namespace pods + node CIDR), CNI note.
def test_k8s_networkpolicy_structure(repo_root: Path) -> None:
    doc = _k8s_yaml(repo_root, "optional/networkpolicy.yaml")
    spec = doc["spec"]
    assert spec["podSelector"]["matchLabels"] == {"app": "rbs"}
    assert spec["policyTypes"] == ["Ingress"]
    rules = spec["ingress"]
    assert len(rules) == 2
    # Rule 1: all pods from the same namespace.
    assert {"podSelector": {}} in rules[0]["from"]
    # Rule 2: node-network ipBlock with a replaceable CIDR placeholder.
    assert len(rules[1]["from"]) == 1
    ip_block = rules[1]["from"][0]["ipBlock"]
    assert isinstance(ip_block["cidr"], str) and ip_block["cidr"]
    for rule in rules:
        rule_ports = {p["port"] for p in rule["ports"]}
        assert rule_ports == {6666, 6667}
    text = _read(repo_root, f"{K8S_DIR}/optional/networkpolicy.yaml")
    assert "NetworkPolicy support" in text  # CNI dependency note
    assert "kubectl get nodes -o wide" in text  # CIDR replacement guidance


# ---------------------------------------------------------------------------
# TC9: docs — the k8s deployment guide exists and is cross-linked from README,
# and the embedded config template keeps its contract-critical keys.
# ---------------------------------------------------------------------------


def test_k8s_docs_exist_and_crosslinked(repo_root: Path) -> None:
    assert (repo_root / "docs/build/k8s.md").is_file()
    assert "docs/build/k8s.md" in _read(repo_root, "README.md")


def test_k8s_doc_template_contract_keys(repo_root: Path) -> None:
    text = _read(repo_root, "docs/build/k8s.md")
    # Template contract keys (K8) must not drift out of the guide.
    for key in (
        "db_type: sqlite",
        "0.0.0.0:6666",
        "0.0.0.0:6667",
        "/usr/share/rbs/sqlite_rbs.sql",
        "health:",
        "kubectl create secret generic rbs-config",
        "kubectl create configmap rbs-keys",
    ):
        assert key in text, f"k8s.md must contain {key!r}"

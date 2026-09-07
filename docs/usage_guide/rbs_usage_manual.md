# RBS Usage Manual

This manual walks you through obtaining, building, deploying, configuring, and verifying the
Resource Broker Service (RBS) from this repository — **execute the chapters in order**. After
finishing it you will be able to run a working RBS instance and drive it with the `rbs-cli`
command-line tool.

> Companion documents:
> [architecture.md](../design/architecture.md) · [rpm.md](../build/rpm.md) ·
> [build_and_install.md](../build/build_and_install.md) · [rbs_cli.md](rbs_cli.md) ·
> [Configuration reference](rbs_config_reference.md) ·
> [REST API reference](../api/rbs/html/rbs_rest_api.html)

## Table of contents

- [0. Environment requirements and self-check (read first)](#0-environment-requirements-and-self-check-read-first)
- [1. Download the repository](#1-download-the-repository)
- [2. Build the RPM packages](#2-build-the-rpm-packages)
- [3. Deploy the RPM packages](#3-deploy-the-rpm-packages)
- [4. Minimal configuration and startup](#4-minimal-configuration-and-startup)
- [5. Quick verification after deployment](#5-quick-verification-after-deployment)
- [6. Integrate with GTA](#6-integrate-with-gta)
- [7. Generate an attestation (Attest) token](#7-generate-an-attestation-attest-token)
- [8. Verify the attestation flow and manage attestation data](#8-verify-the-attestation-flow-and-manage-attestation-data)
- [9. Integrate the Vault resource backend (OpenBao)](#9-integrate-the-vault-resource-backend-openbao)
- [10. Integrate the HSM resource backend (SoftHSM2)](#10-integrate-the-hsm-resource-backend-softhsm2)
- [11. Integrate the CA resource backend (XiPKI)](#11-integrate-the-ca-resource-backend-xipki)

---

## 0. Environment requirements and self-check (read first)

### 0.1 Base requirements (chapters 1–5)

| Item | Requirement |
|---|---|
| OS | Only openEuler 24.03 LTS (`x86_64` / `aarch64`); other distributions and macOS / Windows are not supported |
| Privileges | The current user has `sudo` |
| Build tools | `git`, a Rust toolchain (`cargo`/`rustc`, rustup recommended for a recent version), `gcc`/`g++`, `make`, `rpmbuild` |
| Deployment host | `systemd` (the only external RPM dependency, normally present) |
| Verification tools | `curl`, `openssl`, `python3`, `ss` (iproute) |
| Disk | The first full build is slow and large; leave ≥ 10 GB each on the repo and `$HOME` filesystems |
| Ports | `6666` (RBS) and `8080` (GTA, chapter 6) free |

### 0.2 Per-chapter additional requirements (as needed)

| Chapter | Additional dependency |
|---|---|
| Chapters 6–8 (GTA) | A deployed GTA server (see chapter 6) |
| Chapter 9 (OpenBao) | `docker` (install steps in step 0 of 9.1), port `8200` free |
| Chapter 10 (SoftHSM2) | the `softhsm` package |
| Chapter 11 (XiPKI) | Java 11, the XiPKI installer ([releases](https://github.com/xipki/xipki)), ports `8082`/`8083`/`8444`/`9092` free |

### 0.3 One-shot self-check

```bash
# 1) Check the tools (expect all [OK])
for c in git cargo rustc gcc g++ make rpmbuild curl openssl python3 systemctl ss; do
  command -v "$c" >/dev/null 2>&1 && echo "[OK]      $c" || echo "[MISSING] $c"
done

# 2) Show the Rust version (if too old for Cargo.lock, reinstall via rustup per 0.4)
rustc --version

# 3) Check port usage ("all ports free" means pass)
ss -ltn | grep -E ':(6666|8080|8200|8082|8083|8444|9092) ' || echo "all ports free"
```

### 0.4 Installing what is missing

```bash
sudo dnf install -y git cargo rust rpm-build rpmdevtools gcc gcc-c++ make curl openssl python3
# If the distro cargo is too old for the workspace Cargo.lock, use rustup instead:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source "$HOME/.cargo/env"
```

---

## 1. Download the repository

```bash
git clone https://gitcode.com/openeuler/globaltrustauthority-rbs.git
cd globaltrustauthority-rbs
```

---

## 2. Build the RPM packages

```bash
sh scripts/build-rpm.sh
ls -1 ~/rpmbuild/RPMS/$(uname -m)/*.rpm     # list the outputs
```

The build produces three RPM packages:

| Package | Purpose |
|---|---|
| `rbs-0.1.0-1.*.rpm` | Service daemon |
| `rbc-0.1.0-1.*.rpm` | Client (installed binary name `rbc-cli`) |
| `rbs-cli-0.1.0-1.*.rpm` | Operator tool |

- The first build compiles the whole workspace and is slow — this is expected.

Optional customizations (usually unnecessary):

```bash
VERSION=1.0.0 RELEASE=2 sh scripts/build-rpm.sh                 # pin the package version / release
RPM_BUILD_DIR=/tmp/rbs-rpmbuild sh scripts/build-rpm.sh         # put the output elsewhere (default ~/rpmbuild)
RELEASE=$(date +%Y%m%d%H%M) sh scripts/build-rpm.sh             # unique release per build, so new packages never look identical to stale ones
```

---

## 3. Deploy the RPM packages

Deploy on openEuler 24.03 LTS (the only supported distribution). The default
package output directory is `~/rpmbuild/RPMS/$(uname -m)/` (same as section 2).

### 3.1 Install the RPM packages

```bash
ls -1 ~/rpmbuild/RPMS/$(uname -m)/          # confirm the directory holds only the three RBS packages
sudo rpm -ivh ~/rpmbuild/RPMS/$(uname -m)/*.rpm
```

> - `rpm -ivh` does not resolve dependencies; to resolve them automatically use
>   `sudo dnf install ~/rpmbuild/RPMS/$(uname -m)/*.rpm` instead.
> - If other RPMs (e.g. GTA's `ra-server-*.rpm`) live in that directory, the `*.rpm` glob matches
>   them too — install by explicit file name instead.

**If the install reports file conflicts or "already installed"**: a previous RBS release (e.g.
`globaltrustauthority-rbs-rbs-*`) or this very version is already installed. Old and new packages
share the same version-release (`0.1.0-1`), and `rpm -ivh` **silently skips** a package whose
exact version is already installed — leaving the old binaries in place. Always remove first, then
install:

```bash
# 1) List every installed RBS-related package
rpm -qa | grep -Ei 'rbs|rbc|globaltrustauthority'

# 2) Remove them (list exactly what step 1 printed; example:)
sudo rpm -e globaltrustauthority-rbs-rbs rbs rbc rbs-cli

# 3) Install again
sudo rpm -ivh ~/rpmbuild/RPMS/$(uname -m)/*.rpm

# 4) Confirm the fresh packages are in place (install time should be just now)
rpm -q --qf '%{INSTALLTIME:date}\n' rbs rbc rbs-cli
```

> Uninstalling the old package deletes its `/etc/rbs/rbs.yaml` (possibly keeping a `.rpmsave`
> copy); section 4 rewrites that file anyway, so nothing needs preserving.

### 3.2 Verify and start

```bash
rpm -q rbs rbc rbs-cli                    # packages installed
command -v rbs rbc-cli rbs-cli            # binaries on PATH
systemctl status rbs.service --no-pager   # service state (read-only)
```

> Seeing `activating (auto-restart)` / `status=101` here is **normal**: the bundled `rbs.yaml` has
> empty HTTPS cert paths, so the service refuses to start and keeps retrying. **Go straight to
> section 4** — it becomes `active` after the minimal config + `restart`:

```bash
curl -sS http://127.0.0.1:6666/rbs/version   # run after section 4; version JSON means success
```

### 3.3 Useful lifecycle commands

```bash
sudo systemctl start rbs.service     # start
sudo systemctl stop rbs.service      # stop
sudo systemctl restart rbs.service   # restart (after config changes)
sudo journalctl -u rbs.service -f    # follow logs
```

| Installed artifact | Path |
|---|---|
| Service config | `/etc/rbs/rbs.yaml` (override via `RBS_CONFIG` or `-c`) |
| Data / logs | `/var/lib/rbs`, `/var/log/rbs` |

---

## 4. Minimal configuration and startup

> This chapter has a single goal: **get the service running on a minimal configuration**. For the
> default, required-ness, and constraints of every config key, see the
> [configuration reference](rbs_config_reference.md).

### 4.1 Generate the key pairs

Generate two key pairs — one for the bootstrap administrator, one for local Attest-token
verification (in production the latter must be the key GTA's attest tokens are signed with):

```bash
openssl genpkey -algorithm Ed25519 -out admin_private.pem
openssl pkey -in admin_private.pem -pubout -out admin_public.pem

openssl genpkey -algorithm Ed25519 -out attest_private.pem
openssl pkey -in attest_private.pem -pubout -out attest_public.pem
```

### 4.2 Write the minimal configuration

Overwrite `/etc/rbs/rbs.yaml` with this HTTP + sqlite minimal config:

```yaml
rest:
  listen_addr: "127.0.0.1:6666"
  workers: 4
  https:
    enabled: false
    cert_file: ""
    key_file: ""
  rate_limit:
    enabled: false

logging:
  level: info
  format: text
  file_path: "/var/log/rbs/rbs.log"   # or "" to log to stderr only
  enable_rotation: false

storage:
  db_type: sqlite
  max_connections: 10
  timeout: 30
  url: "sqlite:///var/lib/rbs/rbs.db?mode=rwc"   # mode=rwc: auto-create the file if absent
  sql_file_path: "/usr/share/rbs/sqlite_rbs.sql"

auth:
  attest_token:
    public_key_path: "/etc/rbs/attest_public.pem"
    issuer: "Global Trust Authority"
  bearer_token:
    issuer: "rbs-cli"
    audience: "globaltrustauthority-rbs"

admin:
  max_users: 10
  admin_key:
    public_key_path: "/etc/rbs/admin_public.pem"

policy:
  max_per_user: 10

attestation:
  default_as_provider: gta
  backends:
    gta:
      mode: rest
      rest:
        base_url: "https://127.0.0.1:8080"   # GTA; set in section 6
        timeout_secs: 30
        retries: 3
        tls_verify: true
        credentials:
          user_id: "rbs-service"
          api_key_auth: false
```

### 4.3 Install the public keys, restart, and verify

```bash
sudo install -m 644 admin_public.pem /etc/rbs/admin_public.pem
sudo install -m 644 attest_public.pem /etc/rbs/attest_public.pem
sudo systemctl restart rbs.service
curl -sS http://127.0.0.1:6666/rbs/version   # a version response means success
```

---

## 5. Quick verification after deployment

Smoke test: issue an admin token, then create and query a user and a resource policy. Everything
runs through `rbs-cli` (global options: [rbs_cli.md](rbs_cli.md)); the minimal config uses HTTP, so
all commands pass `-b http://127.0.0.1:6666`.

### 5.1 Generate a bearer token

```bash
# Sign with the admin private key from section 4 (use an absolute path if you changed directory)
# The unset clears a stale empty value: an empty RBS_TOKEN makes rbs-cli fail with "value is empty"
unset RBS_TOKEN
export RBS_TOKEN="$(rbs-cli token gen --private-key-file admin_private.pem --role admin)"
```

> The token expires after 1 hour by default — just run it again. Other options: `rbs-cli token gen --help`.

### 5.2 Create and query users

```bash
# 1) Generate a key pair for the new user
openssl genpkey -algorithm Ed25519 -out alice_private.pem
openssl pkey -in alice_private.pem -pubout -out alice_public.pem

# 2) Create the user
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  user create \
  --username alice \
  --role user \
  --enabled true \
  --public-key @alice_public.pem

# 3) Query
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" user list --limit 20 --offset 0
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" user get --username alice
```

### 5.3 Create and query resource policies

```bash
# 1) Write a Rego policy
cat > policy.rego <<'EOF'
package rbs
default allow = false
allow {
    input.user == "alice"
}
EOF

# 2) Create
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res-policy create \
  --name allow-alice \
  --content @policy.rego

# 3) Query
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" res-policy list
```

### 5.4 Where to go next

| To verify | Where |
|---|---|
| Remote attestation | Chapters 6–8 (GTA integration, Attest token, attestation flow & data management) |
| Resource CRUD and retrieval, per backend | Chapter 9 Vault/OpenBao, chapter 10 HSM/SoftHSM2, chapter 11 CA/XiPKI |
| Other endpoints / `rbs-cli` subcommands | [REST API reference](../api/rbs/html/rbs_rest_api.html) · [rbs_cli.md](rbs_cli.md) |

---

## 6. Integrate with GTA

RBS forwards remote-attestation challenge/evidence and attestation-management CRUD to the Global
Trust Authority (GTA). Deploy GTA first. GTA repository and documentation:

- GTA repository: **https://atomgit.com/openeuler/global-trust-authority**
- GTA docs directory: **https://atomgit.com/openeuler/global-trust-authority/tree/master/docs**

To deploy the GTA server that RBS talks to, refer primarily to these docs (English `docs/en/`,
Chinese at `docs/zh/`):

| GTA doc | Purpose |
|---|---|
| [`GTA_Usage_Guidelines.md`](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs/en/GTA_Usage_Guidelines.md) | Overall install-and-use guide: clone, configure, build/install (RPM or Docker). |
| [`Attestation_Service_Image_Deployment_Guide.md`](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs/en/Attestation_Service_Image_Deployment_Guide.md) | From-scratch server image deployment through endpoint verification. |
| [`api_documentation.md`](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs/en/api_documentation.md) | GTA REST API (challenge/attest/ref-value/cert/policy, etc.) — the endpoints RBS proxies. |
| [`attestation_service.md`](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs/en/attestation_service.md) | Server component overview and development notes. |
| [`key_manager_install.md`](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs/en/key_manager_install.md) | Key manager (OpenBao/KMS) install; needed only with GTA's `service_derived` key mode. |
| [`Challenge_Request_Challenge_Response_Environment_Preparation.md`](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs/en/Challenge_Request_Challenge_Response_Environment_Preparation.md) | Sample policy/baseline data prep (sections 8.3–8.5's ref-value/policy content). |
| [`CLI_User_Guide.md`](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs/en/CLI_User_Guide.md) | `attestation_cli` command guide: baseline/policy/cert management plus nonce retrieval and evidence collection (`attestation_cli evidence get`; feeds the attestation flow in chapter 8). |

Then point RBS at the deployed GTA in `rbs.yaml`:

```yaml
attestation:
  default_as_provider: gta
  backends:
    gta:
      mode: rest
      rest:
        base_url: "https://<gta-host>:<gta-port>"   # GTA REST endpoint
        timeout_secs: 30
        retries: 3
        tls_verify: true
        ca_file: ""                # path to a custom CA bundle, or "" for system default
        credentials:
          user_id: "rbs-service"   # sent to GTA as User-Id
          api_key_auth: false      # set true and fill both API keys to enable API-Key auth
          main_api_key: ""
          sub_api_key: ""
```

The configuration above uses **one-way TLS** (the default): RBS verifies GTA's server
certificate — against `ca_file` when set, otherwise the system trust store — and sends no
client certificate. One-way TLS is the recommended production setup; `tls_verify: false`
(disable verification) is for sealed test environments only.

If GTA uses mutual TLS (mTLS), add the client certificate/key as well (the two must be configured
together):

```yaml
        client_cert_path: "/etc/rbs/gta-client.crt"
        client_key_path: "/etc/rbs/gta-client.key"
```

Additionally set `auth.attest_token` to GTA's token-signing verification key so RBS can verify the
attestation tokens GTA issues:

```yaml
auth:
  attest_token:
    public_key_path: "/etc/rbs/gta_attest_public.pem"   # or jwks_file
    issuer: "Global Trust Authority"
```

Restart and confirm connectivity:

```bash
sudo systemctl restart rbs.service
curl -sS http://127.0.0.1:6666/rbs/version
```

> The attestation-management commands in sections 8.3–8.5 are proxied by RBS to GTA. They add
> GTA's `User-Id` header, and (when `api_key_auth: true`) the `API-Key` headers, then return GTA's
> data through RBS's own endpoints.

---

## 7. Generate an attestation (Attest) token

Get the token with a single `rbs-cli client get-token` call — the CLI drives the attestation agent
through the whole challenge → collect-evidence → attest flow automatically (talking to GTA
directly; RBS is not in this path).

Prerequisites:

- GTA integration done (chapter 6)
- The attestation agent (a GTA-side component — see the
  [GTA docs](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs)) is installed
  locally, config defaulting to `/etc/attestation_agent/agent_config.yaml`
- An attester key pair exists (in production it comes from the real TEE; for local testing, create
  your own. Keep the private key — it decrypts JWE resource payloads later):

```bash
openssl genrsa -out attester_private.pem 4096
openssl rsa -in attester_private.pem -pubout -out attester_public.pem
```

Generate the attest token:

```bash
rbs-cli -b http://127.0.0.1:6666 \
  client get-token \
  --attester-pubkey @attester_public.pem \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/attest_token.jwt
```

- `--agent-config` can be omitted (default `/etc/attestation_agent/agent_config.yaml`).
- The attest token is then used against resource-bound endpoints.
- Manually collecting evidence and posting it to the `/attest` endpoint is covered in chapter 8.

**`--attester-pubkey` constraints**: accepts a PEM public key/certificate or a JWK JSON, but
**only RSA (≥ 4096 bits) and EC P-256/P-384/P-521 are supported** — Ed25519/Ed448, other curves,
and undersized keys are rejected client-side (e.g. `RSA key is 2048 bits, minimum required is
4096 bits`). The key is placed into `runtime_data.tee-pubkey` for RBS's JWE **encryption**
(not signing).

**JWK shapes for `tee-pubkey` / the Bearer token's `enc-pubkey`** (both feed the same
server-side JWE encryption path):

| Shape | Constraints |
|---|---|
| Bare public key (key parameters only — EC: `kty`/`crv`/`x`/`y`, RSA: `kty`/`n`/`e`) | Always accepted |
| With metadata | `use` must be `enc`; `alg` must exactly match the algorithm RBS encrypts with (EC: `ECDH-ES+A256KW`, RSA: `RSA-OAEP-256` — `RSA-OAEP-384`/`RSA-OAEP-512` are rejected); if `key_ops` is present, RSA must include `encrypt` and EC `deriveKey` |

Violations return `400 JWE encryption failed: ... Invalid key format: A parameter ...`.

---

## 8. Verify the attestation flow and manage attestation data

Prerequisite: the GTA integration from chapter 6 is done (RBS forwards challenge/attest to GTA).

| Sections | Content | Auth |
|---|---|---|
| 8.1 / 8.2 | Verifying the two public endpoints of the attestation flow | No token required |
| 8.3–8.5 | Attestation-data management (RBS proxies GTA's management APIs; each group exposes `list`/`get`/`create`/`update`/`delete`) | Admin bearer token |

### 8.1 Challenge (`GET /rbs/v0/challenge`)

Obtain an attestation challenge (nonce). The command prints the nonce string itself (a
Base64-encoded value; use it as-is later, without any transformation):

```bash
rbs-cli -b http://127.0.0.1:6666 client challenge -o /tmp/nonce.txt   # stored for reuse as --nonce @file
```

### 8.2 Attestation (`POST /rbs/v0/attest`)

Section 7's `get-token --attester-pubkey` already automates this whole flow — **manual steps are
normally unnecessary**. This section demonstrates the manual split: collect evidence first (nonce
from RBS's `/challenge`), then post it to `/attest` for a token (the attester key pair comes from
section 7):

```bash
# 1. Collect evidence (the nonce comes from 8.1's output; the attester key pair is
#    generated in section 7).
rbs-cli -b http://127.0.0.1:6666 \
  client collect-evidence \
  --nonce @/tmp/nonce.txt \
  --attester-pubkey @attester_public.pem \
  -o /tmp/evidence.json

# 2. Submit the evidence in exchange for an attest token.
rbs-cli -b http://127.0.0.1:6666 \
  client get-token \
  --evidence @/tmp/evidence.json \
  -o /tmp/token.jwt
```

Evidence collection requires a locally deployed attestation_agent (a GTA-side component — see the
prerequisites in section 7). The token is a JWT issued by GTA (`alg` is `PS256`); RBS later
verifies it with the `auth.attest_token.public_key_path` (or `jwks_file`) configured in section 6.

### 8.3 Reference-value baselines (`ref-value`)

```bash
# 1) Write the baseline JSON (fileName is the file name from the IMA measurement
#    log, sha256 its baseline hash)
cat > rv.json <<'EOF'
{
  "referenceValues": [
    {
      "fileName": "test.ima",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
EOF

# 2) Create the baseline (the CLI Base64-encodes the JSON file automatically)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  ref-value create \
  --name tpm-baseline \
  --attester-type tpm_ima \
  --content-type base64 \
  --content @rv.json

# 3) Query
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" ref-value list
```

`--attester-type` accepts `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca`.

### 8.4 Attestation policies (`policy`)

Attestation policies are **evaluated by GTA at creation time** and must follow the
`package verification` format (defining the `attestation_valid` and `result` rules). Do not
reuse the resource-policy file from §5.3 (`package rbs`) — GTA rejects it with
`Policy evaluation failed`:

```bash
# 1) Prepare a separate policy file
cat > attest_policy.rego <<'EOF'
package verification

default attestation_valid = false
attestation_valid {
    some i
    input.evidence.logs[i].log_type == "ima_log"
    input.evidence.logs[i].log_status == "replay_success"
}

result = { "policy_matched": attestation_valid }
EOF

# 2) Create the policy (text content is provided as raw text and Base64-encoded by the CLI)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  policy create \
  --name allow-tpm-ima \
  --attester-type tpm_ima \
  --content-type text \
  --content @attest_policy.rego

# 3) Query
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" policy list
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" policy get --id <ID>
```

Complete policy samples for each attester type (tpm/tpm_ima/virt_cca/…) are available in the
GTA document
[`Challenge_Request_Challenge_Response_Environment_Preparation.md`](https://atomgit.com/openeuler/global-trust-authority/tree/master/docs/en/Challenge_Request_Challenge_Response_Environment_Preparation.md).

### 8.5 Certificates and CRLs (`cert`)

```bash
# 0) Prepare the certificate: use the real TPM AK certificate in production;
#    a self-signed openssl certificate works for local testing
openssl req -new -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /dev/null -out ak-cert.pem -subj "/CN=test-ak"

# Upload a TPM certificate.
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  cert create \
  --name tpm-ak-cert \
  --type tpm \
  --content @ak-cert.pem

# Query certificates.
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" cert list
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" cert get --id <ID>
```

`cert`'s `--type` accepts `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `ascend_npu`, or
`crl`.

---

## 9. Integrate the Vault resource backend (OpenBao)

Uses OpenBao (the open-source implementation of Vault; fully HTTP-API compatible). One behavioral
rule to remember: **the Vault backend is read-only — the secret itself lives in OpenBao, and
`res create` only registers a reference, it writes nothing** — so the secret must be pre-created
in OpenBao first; update/delete only touch the RBS DB record and never the OpenBao content.
`resource_type` can only be `secret` or `cert`.

### 9.1 Start OpenBao and pre-create a secret

```bash
# 0) If docker is not installed, install and start it first (skip if already installed)
sudo dnf install -y docker
sudo systemctl enable --now docker
docker info | head -5                       # any output means the install succeeded
# If pulling images hangs, configure a registry mirror and retry:
# sudo mkdir -p /etc/docker
# sudo tee /etc/docker/daemon.json <<'EOF'
# {"registry-mirrors": ["https://docker.m.daocloud.io"]}
# EOF
# sudo systemctl restart docker

# 1) Start in dev mode (no init/unseal needed; data in memory only — for functional
#    verification, not for production)
sudo docker run -d --name rbs-openbao -p 8200:8200 \
  openbao/openbao server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200

# 2) Health check
sleep 3
curl -s -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/sys/health

# 3) Pre-create a secret (corresponds to RBS resource URI vault/default/secret/mykey;
#    the data field is the plaintext a later GET decrypts)
curl -s -X POST -H "X-Vault-Token: root" -H "Content-Type: application/json" \
  -d '{"data":{"myvalue":"hello-vault","num":42}}' \
  http://127.0.0.1:8200/v1/secret/data/default/secret/mykey
```

> For production use a persistent deployment (data on disk + `bao operator init`/`unseal` +
> a least-privilege dedicated token); see https://openbao.org.

### 9.2 Configure rbs.yaml for OpenBao

Append a `resource` section to the minimal config of chapter 4 (key reference:
[config reference](rbs_config_reference.md)):

```yaml
resource:
  backends:
    vault:
      type: vault
      url: "http://127.0.0.1:8200"
      token: "root"                    # use a dedicated token in production; no ${ENV} substitution — plaintext only
      mount_path: "secret"
      kv_version: "v2"
      verify_ssl: false                # dev has no TLS; keep true in production
      allowed_resource_types: ["secret", "cert"]
```

```bash
sudo systemctl restart rbs.service
sudo grep -i vault /var/log/rbs/rbs.log | tail -3   # logs go to the file (file_path from chapter 4)
# Expected: Registered resource backend 'vault' (type=vault, url=http://127.0.0.1:8200)
```

> **HTTPS (TLS-enabled OpenBao).** Point `url` at `https://...` and keep `verify_ssl: true`
> (default). Certificate verification uses the **system trust store** — the vault backend
> has no per-backend `ca_file` option (unlike the GTA and CA backends):
> - Public CA: nothing extra to configure.
> - Private CA: import the CA certificate into the system trust store first, e.g. copy it to
>   `/etc/pki/ca-trust/source/anchors/` and run `sudo update-ca-trust` (openEuler/CentOS),
>   or `/usr/local/share/ca-certificates/` + `sudo update-ca-certificates` (Debian).
> - `verify_ssl: false` skips certificate verification entirely — sealed test environments only.

### 9.3 Create a resource policy and register the resource

```bash
# 1) Create a resource policy
cat > vault_res_policy.rego <<'EOF'
package verification

default allow = false
allow { true }
result = {"policy_matched": allow}
EOF

rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res-policy create \
  --name vault-policy \
  --content @vault_res_policy.rego
export POLICY_ID="<the returned policy_id>"

# 2) Register the resource (RBS only checks the secret pre-created in 9.1 exists; writes nothing)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res create \
  --uri vault/default/secret/mykey \
  --policy-id "$POLICY_ID" \
  --content-type json

# 3) Query metadata (reads the RBS DB only; OpenBao is not contacted)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res get-res-info --uri vault/default/secret/mykey
```

### 9.4 Get the resource content (attest token + JWE)

GET content uses an attest token, same as the HSM backend (a Bearer token also works, but it must
carry an `enc-pubkey` claim — see the JWK constraints table in chapter 7). Reuse the attest token
from chapter 7 (it contains the `tee-pubkey`) together with the paired attester private key:

```bash
# 1) If /tmp/attest_token.jwt is missing or expired, regenerate it as in chapter 7
rbs-cli -b http://127.0.0.1:6666 \
  client get-token \
  --attester-pubkey @attester_public.pem \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/attest_token.jwt

# 2) Retrieve and decrypt: the CLI performs "GET + JWE decryption" in one step
rbs-cli -b http://127.0.0.1:6666 \
  client get-resource \
  --uri vault/default/secret/mykey \
  --attest-token @/tmp/attest_token.jwt \
  --private-key-file attester_private.pem
```

- Step 2 is expected to print the plaintext pre-created in 9.1:
  `{"myvalue":"hello-vault","num":42}`.
- The decryption private key must be the same key pair as the `--attester-pubkey` used in
  chapter 7 (the JWE is encrypted with that `tee-pubkey`).

### 9.5 Update and delete

```bash
# 1) Update: changes RBS DB metadata only (e.g. content_type); the secret in OpenBao
#    is untouched
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res update --uri vault/default/secret/mykey \
  --policy-id "$POLICY_ID" --content-type text

# 2) Delete: removes only the RBS DB record; the secret stays in OpenBao and can be
#    re-registered with another create
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res delete --uri vault/default/secret/mykey

# 3) Clean up the resource policy
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res-policy delete --id "$POLICY_ID"
```

> Inline-attestation retrieval (optional): `POST /rbs/v0/vault/{repo}/{type}/{name}/retrieve`
> requires no token (evidence in the body; RBS obtains an attest token via GTA and then
> retrieves); use `rbs-cli client get-resource --evidence @evidence.json --uri vault/...`. The
> GTA integration from chapter 6 is a prerequisite.

---

## 10. Integrate the HSM resource backend (SoftHSM2)

Uses SoftHSM2 (a PKCS#11 software implementation); a real hardware HSM only needs a different
module path and slot label. Opposite to the Vault backend, HSM is write-mostly: **create/update/
delete all actually operate the HSM** (write/overwrite/delete PKCS#11 objects), so create must
carry `--content` (without it only a DB record is created and later GETs fail with `400 backend
not found for resource`). `resource_type` can only be `key` or `secret`. GET content
**accepts attest tokens only** (Bearer GETs always return 404, to prevent enumeration).

### 10.1 Install SoftHSM2 and initialize a token

RBS reads/writes after logging into the token as the **regular user (User)** with a PIN, so three
things are needed: the module file, a token with the chosen label, and the User PIN:

```bash
# 1) Install
sudo dnf install -y softhsm

# 2) Initialize a token (the label must match slot.label in rbs.yaml; --free picks a free slot)
sudo softhsm2-util --init-token --free --label "rbs_slot" --pin 1234 --so-pin 5678

# 3) Verify: expect "Token label: rbs_slot"
softhsm2-util --show-slots | grep -i label
ls /usr/lib64/pkcs11/libsofthsm2.so   # exists -> this is the module_path value
```

> `--pin 1234` is the **User PIN** (what RBS logs in with); `--so-pin 5678` is the administrative
> SO PIN (not used by RBS). If a token with the same label already exists, pick another label.

### 10.2 Configure rbs.yaml for SoftHSM2

Append a `resource` section to the minimal config of chapter 4 (key reference:
[config reference](rbs_config_reference.md)):

```yaml
resource:
  backends:
    hsm:
      type: hsm
      module_path: "/usr/lib64/pkcs11/libsofthsm2.so"   # adjust to the actual path
      slot:
        label: "rbs_slot"                               # same as --init-token's --label
      credentials:
        pin_env: "RBS_HSM_PIN"                          # RBS reads the User PIN from this env var
      allowed_resource_types: ["key", "secret"]
```

**The PIN is injected via an environment variable, never written into the config.** A systemd
service does not inherit terminal `export`s, so use a drop-in:

```bash
# 1) Write the User PIN into a dedicated file (mode 600)
echo 'RBS_HSM_PIN=1234' | sudo tee /etc/rbs/rbs.env > /dev/null
sudo chmod 600 /etc/rbs/rbs.env

# 2) Create a systemd drop-in so rbs.service reads that file at startup
sudo mkdir -p /etc/systemd/system/rbs.service.d
cat <<'EOF' | sudo tee /etc/systemd/system/rbs.service.d/hsm-pin.conf > /dev/null
[Service]
EnvironmentFile=/etc/rbs/rbs.env
EOF

# 3) Reload, restart, and confirm registration
sudo systemctl daemon-reload
sudo systemctl restart rbs.service
sudo grep -iE 'hsm|slot' /var/log/rbs/rbs.log | tail -5
# Expected two lines:
#   HsmBackend: loaded module '/usr/lib64/pkcs11/libsofthsm2.so', found slot 'rbs_slot'
#   Registered resource backend 'hsm' (type=hsm)
```

> - After changing files under `rbs.service.d/` run `daemon-reload`; after changing only the
>   value in `/etc/rbs/rbs.env`, a plain `restart` suffices.
> - A successful start only proves module loading and slot lookup — **the PIN login is deferred
>   until the first HSM access**, so do the write verification in 10.3 (a 201 without
>   `C_Login failed` in the log is the real PIN test).

### 10.3 Create a resource policy and write key material

```bash
# 1) Create a resource policy (reuses RBS_TOKEN from chapter 5)
cat > hsm_res_policy.rego <<'EOF'
package verification

default allow = false
allow { true }
result = {"policy_matched": allow}
EOF

rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res-policy create \
  --name hsm-policy \
  --content @hsm_res_policy.rego
export POLICY_ID="<the returned policy_id>"

# 2) Generate 32 bytes of random key material
head -c 32 /dev/urandom | base64 > keymat.b64

# 3) Write into the HSM (creates a CKO_DATA object in the token, label default/key/mykey;
#    --content also accepts binary files - the CLI Base64-encodes them automatically)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res create \
  --uri hsm/default/key/mykey \
  --policy-id "$POLICY_ID" \
  --content-type binary \
  --content @keymat.b64

# 4) Query metadata (reads the RBS DB; the HSM is not contacted)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res get-res-info --uri hsm/default/key/mykey
```

### 10.4 Get HSM resource content (attest token + JWE)

HSM GET content **accepts attest tokens only** (Bearer GETs always return 404, to prevent
enumeration). Reuse the attest token from chapter 7 (it contains the `tee-pubkey`) together
with the paired attester private key:

```bash
# 1) If /tmp/attest_token.jwt is missing or expired, regenerate it as in chapter 7
rbs-cli -b http://127.0.0.1:6666 \
  client get-token \
  --attester-pubkey @attester_public.pem \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/attest_token.jwt

# 2) Retrieve and decrypt: the CLI performs "GET + JWE decryption" in one step
rbs-cli -b http://127.0.0.1:6666 \
  client get-resource \
  --uri hsm/default/key/mykey \
  --attest-token @/tmp/attest_token.jwt \
  --private-key-file attester_private.pem
```

- Key material is binary, so the CLI's text output is its Base64 encoding (use `-f json` for
  structured output); after `base64 -d` it matches the original material written in 10.3.
- The decryption private key must be the same key pair as the `--attester-pubkey` used in
  chapter 7 (the JWE is encrypted with that `tee-pubkey`).

### 10.5 Update and destroy

```bash
# 1) Generate new key material (for the overwrite)
head -c 32 /dev/urandom | base64 > newkeymat.b64

# 2) Update: with --content it overwrites the object value in the token; without it only
#    the RBS DB metadata changes
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res update --uri hsm/default/key/mykey \
  --content-type binary --content @newkeymat.b64

# 3) Destroy: actually deletes the PKCS#11 object (label default/key/mykey) in the token
#    and the RBS DB record; irreversible - double-check before deleting
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res delete --uri hsm/default/key/mykey

# 4) Clean up the resource policy
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res-policy delete --id "$POLICY_ID"
```

> Inline-attestation retrieval (optional): `POST /rbs/v0/hsm/{repo}/{type}/{name}/retrieve`
> requires no token (evidence in the body; RBS obtains an attest token via GTA and then
> retrieves); use `rbs-cli client get-resource --evidence @evidence.json --uri hsm/...`. The GTA
> integration from chapter 6 is a prerequisite.

---

## 11. Integrate the CA resource backend (XiPKI)

Uses XiPKI (an open-source PKI/CMPv2 implementation); any other CMPv2 CA just needs a different
endpoint and certificates. The CA backend is a **certificate-issuance proxy**: create/update/
delete are metadata-only (no requests to the CA), and only GET takes the CSR from the attest
token, **issues a certificate live from the CA**, and returns it JWE-encrypted — the token must
carry both `csr` (DER, Base64) and `tee-pubkey`; a missing `csr` yields `400 csr required for
this resource provider`. `resource_type` can only be `cert`.

### 11.1 Deploy XiPKI

Download `xipki-setup-6.7.0-bclts.tar.gz` from [XiPKI releases](https://github.com/xipki/xipki)
**and place it in `/opt`**; the demo deployment (CA/gateway/OCSP Tomcats + H2 database) is used
here.

> Port note: **the OCSP default 8080 conflicts with GTA — change it to 8083 before running
> `prepare.sh`**.

```bash
# 0) Confirm Java is 11 (if it is 1.8.x, install java-11-openjdk and switch with alternatives)
/usr/bin/java -version

# 1) Extract (the tarball must already be in /opt) and delete the stray fips bridge jar
#    (otherwise prepare.sh fails with a KeyUtil class conflict)
cd /opt && tar xzf xipki-setup-6.7.0-bclts.tar.gz
rm -f xipki-setup-6.7.0/setup/jars/xipki/bcbridge-fips-6.7.0.jar

# 2) Change the OCSP port 8080 to 8083 (must be done before prepare.sh)
sed -i 's/"ocsp.http.port": "8080"/"ocsp.http.port": "8083"/' xipki-setup-6.7.0/setup/conf.json
grep ocsp.http.port xipki-setup-6.7.0/setup/conf.json   # confirm it now shows 8083

# 3) Initialize
cd xipki-setup-6.7.0
./prepare.sh                    # expect no ERROR/Exception output, returns cleanly to the prompt
./demo.sh                       # downloads Tomcat and installs the three tomcats

# 4) Run H2 as an independent persistent process (in the demo script H2 is a child of the
#    mgmt shell - once the shell exits H2 dies, and the CA fails with "could not save
#    certificate")
mkdir -p /root/.xipki/db/h2
systemd-run --unit=h2-server \
  --working-directory=/opt/xipki-setup-6.7.0/xipki-mgmt-cli \
  -- java -cp lib/h2-2.4.240.jar org.h2.tools.Server \
     -tcp -tcpPort 9092 -tcpAllowOthers -ifNotExists

# 5) Initialize the CA (demo script; creates a CA named myca1)
#    First delete the line that starts its own H2 (line 6, start-h2-server) to avoid
#    fighting step 4 for port 9092
cd /opt/xipki-setup-6.7.0/xipki-mgmt-cli
sed -i '6d' demo/doDemo.script
printf 'source demo/demo.script DB PKCS12 RSA2048\nexit\n' | bin/xipki

# 6) Start the three tomcats as persistent processes (H2 before the CA tomcat), then verify
systemd-run --unit=ca-tomcat      --working-directory=/root/demo_xipki/ca-tomcat      -- bash -c 'exec /root/demo_xipki/ca-tomcat/bin/catalina.sh run'
systemd-run --unit=gateway-tomcat --working-directory=/root/demo_xipki/gateway-tomcat -- bash -c 'exec /root/demo_xipki/gateway-tomcat/bin/catalina.sh run'
systemd-run --unit=ocsp-tomcat    --working-directory=/root/demo_xipki/ocsp-tomcat    -- bash -c 'exec /root/demo_xipki/ocsp-tomcat/bin/catalina.sh run'
sleep 12
ss -ltn | grep -E ':8444|:8082|:8083'    # all three ports LISTEN
grep 'started CA system' /root/demo_xipki/ca-tomcat/logs/ca.*.log | tail -1
# Expected: started CA system with following CAs: myca1 (alias myca)
```

> `systemd-run` units are temporary and **lost on machine reboot**; for production write real
> systemd units and `systemctl enable` them (same approach as the drop-in in 10.2).

### 11.2 Prepare the CMP client certificate and trust anchors

RBS as a CMP client needs two files; missing either (or mismatched keys) makes RBS fail to
start. For the demo, reuse the bundled EC cmp-client (already registered in the gateway's
simple-requestors):

```bash
# 1) CMP client certificate/key (RBS signs CMP requests with it)
cp /opt/xipki-setup-6.7.0/xipki-cli/xipki/keycerts/cmp-client-cert.pem /etc/rbs/cmp-client.crt
cp /opt/xipki-setup-6.7.0/xipki-cli/xipki/keycerts/cmp-client.p12 /tmp/cmp-client.p12
openssl pkcs12 -in /tmp/cmp-client.p12 -nocerts -nodes \
  -passin pass:changeit-cmpclient -out /tmp/cmp-client.key.tmp
openssl pkey -in /tmp/cmp-client.key.tmp -out /etc/rbs/cmp-client.key    # clean PKCS#8 PEM
chmod 600 /etc/rbs/cmp-client.key && rm -f /tmp/cmp-client.key.tmp /tmp/cmp-client.p12

# 2) Trust anchor: the certificate the gateway actually uses to sign CMP responses
cp /root/demo_xipki/gateway-tomcat/xipki/keycerts/gateway-server-cert.pem /etc/rbs/ca-anchors.pem
```

### 11.3 Configure rbs.yaml for XiPKI

Append a `resource` section to the minimal config of chapter 4 (key reference:
[config reference](rbs_config_reference.md)):

```yaml
resource:
  backends:
    ca:
      type: ca
      url: "http://127.0.0.1:8082/gw/cmp/myca1"   # demo uses HTTP; HTTPS recommended in production
      https:
        verify: false                              # keep true when using HTTPS
      message_protection_cert_file: "/etc/rbs/cmp-client.crt"
      message_protection_key_file: "/etc/rbs/cmp-client.key"
      response_protection_trust_anchors_file: "/etc/rbs/ca-anchors.pem"
      cert_profile: "smime"                        # must be a profile that exists on the CA
      allowed_resource_types: ["cert"]
```

```bash
sudo systemctl restart rbs.service
sudo grep -i "CA backend" /var/log/rbs/rbs.log | tail -3
# Expected:
#   CA backend initialized: url='http://127.0.0.1:8082/gw/cmp/myca1', anchors=1
#   Registered resource backend 'ca' (type=ca)
```

### 11.4 Create a resource policy and register the CA resource

```bash
# 1) Create a resource policy (reuses RBS_TOKEN from chapter 5)
cat > ca_res_policy.rego <<'EOF'
package verification

default allow = false
allow { true }
result = {"policy_matched": allow}
EOF

rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res-policy create --name ca-policy --content @ca_res_policy.rego
export POLICY_ID="<the returned policy_id>"

# 2) Register the CA resource (metadata only; no request to the CA)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res create --uri ca/default/cert/mycert \
  --policy-id "$POLICY_ID" --content-type binary

# 3) Query metadata (reads the RBS DB; the CA is not contacted)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res get-res-info --uri ca/default/cert/mycert
```

### 11.5 Get a certificate (attest token + CSR)

CA GET **accepts attest tokens only** (Bearer GETs always return 404, to prevent enumeration),
and the token must carry both `csr` and `tee-pubkey`. Like 10.4, use `client get-token`, passing
the CSR into runtime_data via `--runtime-data csr=<value>` (GTA copies attester_data verbatim
into the issued token):

```bash
# 1) Generate a CSR (the subject must match cert_profile - the demo's smime requires an
#    email; a mismatch is rejected by the CA, surfacing as 502 on the RBS side)
openssl req -new -newkey rsa:2048 -nodes \
  -keyout csr-client.key -out client.csr \
  -subj "/C=DE/O=myorg/emailAddress=info@myorg.com/CN=workload"
export CSR_DER_B64=$(openssl req -in client.csr -outform DER | base64 -w0)

# 2) Issue an attest token carrying the csr (--runtime-data is repeatable key=value)
rbs-cli -b http://127.0.0.1:6666 \
  client get-token \
  --attester-pubkey @attester_public.pem \
  --runtime-data "csr=$CSR_DER_B64" \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/attest_token.jwt

# 3) Get the certificate: RBS issues it live from XiPKI with the CSR; the CLI decrypts
#    the JWE automatically
rbs-cli -b http://127.0.0.1:6666 \
  client get-resource \
  --uri ca/default/cert/mycert \
  --attest-token @/tmp/attest_token.jwt \
  --private-key-file attester_private.pem \
  -o issued-cert.b64

# 4) Restore and inspect the certificate
base64 -d issued-cert.b64 > issued-cert.der
openssl x509 -in issued-cert.der -inform der -noout -subject -issuer
# Expected: subject=C = DE, O = myorg, CN = workload
#           issuer=O = myorg, CN = myca1

# 5) Verify the certificate public key matches the CSR (the CA adopted the CSR's key)
diff <(openssl x509 -in issued-cert.der -inform der -noout -pubkey) \
     <(openssl req -in client.csr -noout -pubkey) && echo "public key matches the CSR"
```

- `issued-cert.der` and `csr-client.key` form the usable certificate/key pair; the decryption
  private key must be the same key pair as the `--attester-pubkey` used above (the JWE is
  encrypted with that `tee-pubkey`).
- **Idempotency cache**: within the TTL (default 300 s) a GET of the same resource with the same
  CSR returns the cached certificate; a different CSR counts as a new request.

### 11.6 Update and delete

```bash
# Update (DB metadata only; the CA is untouched)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res update --uri ca/default/cert/mycert \
  --policy-id "$POLICY_ID" --content-type text

# Delete (removes only the DB record; issued certificates remain on the CA - revoke through
# the CA's own process)
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res delete --uri ca/default/cert/mycert

# Clean up the resource policy
rbs-cli -b http://127.0.0.1:6666 -t "$RBS_TOKEN" \
  res-policy delete --id "$POLICY_ID"
```

> Inline-attestation retrieval (optional): `POST /rbs/v0/ca/{repo}/{type}/{name}/retrieve`
> requires no token (evidence in the body; RBS obtains an attest token via GTA and then issues);
> the evidence's `attester_data.runtime_data` must contain both `csr` and `tee-pubkey`. Use
> `rbs-cli client get-resource --evidence @evidence.json --uri ca/...`; a deployed GTA
> (chapter 6) is a prerequisite.

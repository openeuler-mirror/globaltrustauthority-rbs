# globaltrustauthority-rbs

**Resource Broker Service (RBS)** — distributes keys, certificates, and related resources using remote attestation with the [Global Trust Authority](https://gitcode.com/openeuler/global-trust-authority).

## Overview

This repository is a **Rust workspace** that implements policy-driven resource brokering for attested workloads. It ships:

- **`rbs`** — Long-running **broker daemon** (default **`rest`** build): **Actix** HTTP with **`GET /rbs/version`** (service metadata) and versioned REST under **`/rbs/v0/...`** (attestation and resource APIs; see OpenAPI under **`docs/proto/`**).
- **`rbc`** — **Resource Broker Client** library (and optional **`rbc`** binary): async **`Client`** / **`Session`** over HTTP to RBS, with pluggable **evidence** and **token** providers for attestation and resource retrieval.
- **`rbs-cli`** — Operator CLI: **admin** flows (users, policies, resources, certs, tokens, …) and a **`client`** mode that talks to a running broker using the same HTTP surface as **`rbc`**.

Runtime behaviour is configured with **YAML** (`rest`, TLS, storage, and optional features such as per-IP rate limiting when enabled at build time). The **OpenAPI** contract and rendered API documentation are checked in under **`docs/proto/`** and **`docs/api/`**; regenerate them with **`./scripts/build.sh docs`** (paths and tooling are listed under **Documentation** below).

**RPM** packages (with **systemd** and `rbs.service`), **Docker / Compose** files under **`deployment/docker/`**, and the **`./scripts/build.sh`** entry point cover release builds, container images, and generated docs.

For **build, install, RPM, container, and test** procedures, see [**docs/build/build_and_install.md**](docs/build/build_and_install.md). Its quick start matches **Quick start** in this file.

## Prerequisites

- **Rust** — a recent **stable** toolchain ([rustup](https://rustup.rs/) recommended).
- **OS** — **Linux** is the primary target; RPM-based packaging and paths are documented for openEuler-style systems.
- **Node.js** (required for REST API documentation generation via **`./scripts/build.sh docs`** or **`./scripts/generate-api-docs.sh`**) — **≥ 22.12** (see **`engines`** in [`scripts/conf/openapi-docs/package.json`](scripts/conf/openapi-docs/package.json)); **24** is a practical local target. Use [nvm](https://github.com/nvm-sh/nvm) or [fnm](https://github.com/Schniz/fnm) if your system Node is older. Optionally create a repo-root **`.nvmrc`** (for example the single line `24`) for `nvm use` / `fnm use`; that file is **not** tracked in git.

## Quick start

Execute the steps below in order from a POSIX shell. From step 2 onward, run commands from the **repository root** (the directory that contains `Cargo.toml`). This project does not provide **`make install`**; release binaries are produced under **`target/release/`**. Host installation using RPM packages is described in **[docs/build/rpm.md](docs/build/rpm.md)**.

```bash
# 1) Install build and runtime dependencies (choose one distribution block)
# openEuler / Fedora / RHEL
sudo dnf install -y git cargo rust rpm-build rpmdevtools gcc gcc-c++ make docker nodejs npm \
  && sudo systemctl enable --now docker
# Debian / Ubuntu (minimal for clone + build + tests + docs + Docker; omit `rpm` unless you run ./scripts/build.sh rpm)
sudo apt-get update && sudo apt-get install -y git build-essential pkg-config libssl-dev \
  docker.io docker-compose-v2 nodejs npm && sudo systemctl enable --now docker
# Optional — only when building RPMs on this host: sudo apt-get install -y rpm
# For ./scripts/build.sh docs: distro nodejs may be < 22.12 — check `node -v`; use nvm/fnm (optional local .nvmrc) if needed (see Prerequisites).
# Rust too old for Cargo.lock? Use rustup instead of the distro Rust:
# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source "$HOME/.cargo/env"

# 2) Obtain source code (choose one method)
git clone https://gitcode.com/openeuler/globaltrustauthority-rbs.git
cd globaltrustauthority-rbs
# Alternative: download a source tarball or zip from a release or mirror, unpack, and enter the tree:
# tar xf globaltrustauthority-rbs-*.tar.gz && cd globaltrustauthority-rbs-*
# unzip globaltrustauthority-rbs-*.zip && cd globaltrustauthority-rbs-*

# 3) Build (release) — binaries land under target/release/
./scripts/build.sh

# 4) Run the test suite
./tests/test_all.sh

# 5) Start the RBS service (foreground; interrupt with Ctrl-C).
# The sample configuration listens on 127.0.0.1:6666 and uses paths under /var/log/rbs and /root;
# run with elevated privileges or adjust rbs/conf/rbs.yaml (logging.file_path, storage.url) first.
sudo ./target/release/rbs -c rbs/conf/rbs.yaml

# 6) From a second terminal — verify the running service
curl -sS http://127.0.0.1:6666/rbs/version                        # REST: version JSON
# export RBS_BASE_URL=http://127.0.0.1:6666   # optional: then omit repeated -b on rbs-cli
./target/release/rbs-cli -b http://127.0.0.1:6666 version         # CLI: version subcommand
./target/release/rbs-cli -b http://127.0.0.1:6666 --help          # CLI: subcommand list
```

**Additional references**

- **Build script** — Run `./scripts/build.sh help` from the repository root for subcommands (`rpm`, `docker`, `docs`, `debug`, and `cargo` passthrough).
- **Container workflow** — `./scripts/build.sh docker` builds the image; `docker compose -f deployment/docker/rbs-compose.yaml up --build` builds (if needed) and runs the stack (alternative to local **`./scripts/build.sh`** + foreground **`rbs`** in **Quick start**). Port mapping and config: [Container: build, run, and test](docs/build/build_and_install.md#5-container-build-run-and-test-step-by-step).
- **Tests** — Layout, skips, and e2e driver: [tests/README.md](tests/README.md).
- **Tooling and docs** — E2e scripts, OpenAPI artefacts, Compose paths, optional `cargo deny`: [Further reading and tooling](docs/build/build_and_install.md#7-further-reading-and-tooling).
- **OS package installs from scripts** — Off by default. Set **`ENABLE_AUTO_INSTALL_DEPS=1`** to allow non-interactive **`apt`**/**`dnf`** installs on supported distros when a tool is missing. **`CI=true`** or **`DISABLE_AUTO_INSTALL_DEPS=1`** always forbids those installs. See [RPM](docs/build/build_and_install.md#4-rpm-build-install-run-and-test-step-by-step) and [container](docs/build/build_and_install.md#5-container-build-run-and-test-step-by-step) in **build_and_install.md**.

## Documentation

| Topic | Location |
|--------|----------|
| End-to-end build, run, and test (source, RPM, container, generated docs) | [**docs/build/build_and_install.md**](docs/build/build_and_install.md) |
| RPM install, upgrade, systemd, packaging details | [**docs/build/rpm.md**](docs/build/rpm.md) |
| Tests (Cargo, e2e, OpenAPI check) | [**tests/README.md**](tests/README.md) |
| Checked-in REST OpenAPI and rendered API (regenerate via `./scripts/build.sh docs`) | [`docs/proto/rbs_rest_api.yaml`](docs/proto/rbs_rest_api.yaml), [`docs/api/rbs/md/rbs_rest_api.md`](docs/api/rbs/md/rbs_rest_api.md) |
| Compose / image files | [`deployment/docker/`](deployment/docker/) |
| Optional: workspace clippy / `cargo-deny` | [`.cargo/config.toml`](.cargo/config.toml), [`deny.toml`](deny.toml) |

## License

Licensed under the **Mulan Public License, version 2** — see [LICENSE](LICENSE).

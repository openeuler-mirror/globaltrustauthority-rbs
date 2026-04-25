# Build and install

The procedures below are **sequential**: execute the commands in each block in order unless a step explicitly states otherwise. Each numbered section (2–5) defines **one** self-contained workflow. Select **one** row in the table; avoid mixing steps from §3, §4, and §5 in the same session unless there is a documented reason to switch between layouts.

| Section | When to use it | Outcome |
| -------- | ---------------- | -------- |
| **[§2 Quick start](#2-quick-start)** | Initial setup on a development host; minimal path from clone to HTTP and CLI verification | Release binaries under `target/release/`, service bound to **127.0.0.1:6666** with the sample configuration, automated tests executed once |
| **[§3 From source](#3-from-source-build-run-and-test-step-by-step)** | A local tree is already available; a **documented** source-only workflow is required (no RPM install, no container run) | Same end state as §2, with explicit verification between phases |
| **[§4 RPM](#4-rpm-build-install-run-and-test-step-by-step)** | Target host uses **RPM** and **systemd** (for example openEuler); system-wide installation is required | Installed `rbs`, `rbc`, and `rbs-cli` packages, `rbs.service` under systemd, verification against `/etc/rbs/rbs.yaml` |
| **[§5 Container](#5-container-build-run-and-test-step-by-step)** | Deployment uses **Docker** or **Podman**; local Compose binds **REST** to **127.0.0.1:8080** using **host network on Linux** (demo/test only, not production) | OCI image produced, Compose-based stack reachable at **127.0.0.1:8080**, optional **`docker compose ... run`** one-off |

**Conventions**

- **Repository root** — shell examples assume the working directory is the path that contains **`Cargo.toml`**, except where a `cd` command is shown.
- **Command lines** — examples omit a leading shell prompt (`$`); copy only the command text if your environment displays a prompt.
- **Multiple terminals** — use one session for a long-running server process (`rbs` or `docker compose up`) and a second session for `curl` and `rbs-cli`.

**Related documentation**

- **RPM lifecycle** (upgrade, `%config(noreplace)`, signing, local DNF repository, SELinux): **[rpm.md](rpm.md)**, in particular the **[Operator guide](rpm.md#operator-guide)**.
- **`./scripts/build.sh`**: subcommands and `cargo` argument forwarding are listed under **`./scripts/build.sh help`** (run from the repository root).
- **Tests** (end-to-end options, skip flags, `run_e2e.sh`): **[tests/README.md](../../tests/README.md)**.
- **OpenAPI regeneration**, checked-in contract paths, optional **`cargo clippy-all`** / **`cargo deny-all`**: **[§7 Further reading](#7-further-reading-and-tooling)**.

## 1. Prerequisites (Linux)

| Need | Why | Quick check (optional) |
| ---- | --- | ------------------------ |
| **Linux** `x86_64` or `aarch64` | Tier-1 build and test targets | `uname -m` |
| **Rust** (`cargo` / `rustc`) | Workspace is Rust; lockfile may need a **current** stable toolchain | `cargo --version` — if `cargo build` complains about **Cargo.lock**, install **[rustup](https://rustup.rs/)** and use stable |
| **Git** or a **tarball/zip** of the sources | Clone or unpack the tree | `git rev-parse --show-toplevel` when using git |
| **Disk** (~few GB) | `target/`, optional `rpm-build/`, Docker layers | `df -h .` |
| **Network** (unless fully offline) | Crates.io, `git` remotes, `npm` when you run **`docs`** | — |
| **Node.js** (only for **`./scripts/build.sh docs`**) | OpenAPI doc tooling needs **≥ 22.12** (`engines` in [`scripts/conf/openapi-docs/package.json`](../../scripts/conf/openapi-docs/package.json)); **24** is a practical local choice | `node -v` — if too old, use **nvm** / **fnm** at repo root; optional untracked **`.nvmrc`** (see **[§7](#7-further-reading-and-tooling)**) |

**Out of scope for this document:** macOS and Windows as primary build hosts. Use a Linux virtual machine, **WSL2**, or the container workflow in §5.

## 2. Quick start

**Objective:** install prerequisites, obtain sources, produce a **release** build, execute the **automated** test suite, start **`rbs`** in the foreground, then verify the deployment with **`curl`** and **`rbs-cli`**.

**Procedure (ordered steps):** (1) dependencies, (2) clone or unpack sources, (3) `./scripts/build.sh`, (4) `./tests/test_all.sh`, (5) `sudo ./target/release/rbs -c rbs/conf/rbs.yaml`, (6) verification commands from a **second** terminal session.

```bash
# 1) Install build and runtime dependencies (choose one distribution block)
# openEuler / Fedora / RHEL
sudo dnf install -y git cargo rust rpm-build rpmdevtools gcc gcc-c++ make docker nodejs npm \
  && sudo systemctl enable --now docker
# Debian / Ubuntu (minimal for clone + build + tests + docs + Docker; add `rpm` only if you run ./scripts/build.sh rpm)
sudo apt-get update && sudo apt-get install -y git build-essential pkg-config libssl-dev \
  docker.io docker-compose-v2 nodejs npm && sudo systemctl enable --now docker
# Optional — RPM builds on this host: sudo apt-get install -y rpm
# For ./scripts/build.sh docs: Debian/Ubuntu `nodejs` may be below 22.12 — run `node -v`; use nvm/fnm (optional local .nvmrc) if needed (see §1 table and §7).
# Rust too old for Cargo.lock? Use rustup instead of the distro Rust:
# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source "$HOME/.cargo/env"

# 2) Obtain source code (choose one method)
git clone https://gitcode.com/openeuler/globaltrustauthority-rbs.git
cd globaltrustauthority-rbs
# Alternative: unpack a release tarball or zip archive, then change into the project directory:
# tar xf globaltrustauthority-rbs-*.tar.gz && cd globaltrustauthority-rbs-*
# unzip globaltrustauthority-rbs-*.zip && cd globaltrustauthority-rbs-*

# 3) Build (release) — binaries under target/release/
./scripts/build.sh

# 4) Automated test suite (from repo root)
./tests/test_all.sh

# 5) Run RBS in the foreground (Ctrl-C to stop). Sample config listens on 127.0.0.1:6666
# and writes under /var/log/rbs and /root — use sudo or edit rbs/conf/rbs.yaml first.
sudo ./target/release/rbs -c rbs/conf/rbs.yaml

# 6) Second terminal — service verification
curl -sS http://127.0.0.1:6666/rbs/version
# export RBS_BASE_URL=http://127.0.0.1:6666   # optional: omit repeated -b on rbs-cli
./target/release/rbs-cli -b http://127.0.0.1:6666 version
./target/release/rbs-cli -b http://127.0.0.1:6666 --help
```

**After step 3 (build)** — confirm that the release binaries exist:

```bash
test -x target/release/rbs && test -x target/release/rbs-cli && echo 'release binaries OK'
```

**After step 4 (tests)** — `./tests/test_all.sh` must exit with status **0** (by default: workspace **`cargo test`**, then a check that **`docs/proto/rbs_rest_api.yaml`** matches **`cargo build -p rbs --features rest`**, then e2e). On failure, inspect the script output, then consult **[tests/README.md](../../tests/README.md)** for selective execution and skip flags.

**After step 5 (server)** — keep the server process in the foreground in that terminal. The sample **`rbs/conf/rbs.yaml`** binds **`127.0.0.1:6666`** and references paths including **`/var/log/rbs`** and a SQLite URL under **`/root`**; **`sudo`** is therefore used in the example. For an unprivileged run, adjust **`logging.file_path`**, **`storage.url`**, and **`storage.sql_file_path`** in the configuration file first.

**After step 6 (verification)** — `curl` should return **JSON** (version document); `rbs-cli … version` should print **text**. **`curl: Connection refused`** indicates a mismatch between the request URL and **`rest.listen_addr`** in the configuration supplied to **`rbs`** (see **[§6](#6-common-first-run-failures)**).

**Notes**

- There is **no** `make install`; **`cargo install`** is not the documented installation path. Release artifacts remain under **`target/release/`**. For **`/usr/bin`** layout and **systemd** integration, use **[§4](#4-rpm-build-install-run-and-test-step-by-step)** and **[rpm.md](rpm.md)**.
- If **`cargo build`** fails because of **`Cargo.lock`** or toolchain age, install **[rustup](https://rustup.rs/)** stable and repeat **`./scripts/build.sh`**.

## 3. From source: build, run, and test (step-by-step)

Use this section when the repository tree is already present and the same end state as §2 is required, with **explicit verification** between phases. It does **not** install RPM packages (**§4**) or start a container (**§5**) unless those sections are followed separately.

### Phase A — Confirm tree and toolchain

```bash
cd /path/to/globaltrustauthority-rbs
# Remain at the repository root (the directory that contains Cargo.toml).
# If the next phase fails on Cargo.lock / edition / MSRV:
# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source "$HOME/.cargo/env"
```

### Phase B — Release build

```bash
./scripts/build.sh
# Optional (faster iteration): ./scripts/build.sh debug --bin rbs
test -x target/release/rbs && test -x target/release/rbs-cli && echo 'build: OK'
```

### Phase C — Automated tests

```bash
./tests/test_all.sh
echo "tests exit code: $?"   # expect 0
```

### Phase D — Run server (foreground)

Use **either** `-c` **or** the env var (equivalent):

```bash
./target/release/rbs -c rbs/conf/rbs.yaml
# same: RBS_CONFIG=rbs/conf/rbs.yaml ./target/release/rbs
```

If the config still points logging or SQLite at privileged paths, use **`sudo`** with the same command, **or** edit paths in **`rbs/conf/rbs.yaml`** (or a copy) first.

### Phase E — Verification (second terminal)

Use the same host and port as **`rest.listen_addr`** in the YAML path passed to **`-c`** or **`RBS_CONFIG`** (the sample file uses **`127.0.0.1:6666`**):

```bash
curl -sS http://127.0.0.1:6666/rbs/version
# export RBS_BASE_URL=http://127.0.0.1:6666   # optional: omit repeated -b on rbs-cli
./target/release/rbs-cli -b http://127.0.0.1:6666 version
```

**Additional tooling:** **`./scripts/build.sh help`** documents **`cargo`** passthrough (for example **`release --bin rbs`**) and subcommands **`rpm`**, **`docker`**, **`docs`**, **`debug`**. Generated documentation, OpenAPI paths, **`cargo deny`**, and Compose references: **[§7](#7-further-reading-and-tooling)**.

## 4. RPM: build, install, run, and test (step-by-step)

**Goal:** from a clean checkout on an **RPM + systemd** host, produce **`rbs`**, **`rbc`**, and **`rbs-cli`** packages, install them, confirm **`rbs.service`**, then hit **`/rbs/version`** with **`curl`** and **`rbs-cli`**.

**Before you start**

- For upgrade behaviour, **`%config(noreplace)`**, package signing, local DNF repositories, and SELinux-related notes, refer to **[rpm.md](rpm.md#operator-guide)**. This section documents the **standard success path** only.
- Helper scripts **do not** auto-install distribution packages by default. Set **`ENABLE_AUTO_INSTALL_DEPS=1`** only if you want non-interactive installs on supported distros. **`CI=true`** or **`DISABLE_AUTO_INSTALL_DEPS=1`** always forbids **`sudo`** package installs from those helpers.

```bash
# 0) Repository root
cd /path/to/globaltrustauthority-rbs

# 1) Host toolchain (dnf example — align package names with your mirror)
sudo dnf install -y git cargo rust rpm-build rpmdevtools gcc gcc-c++ make
command -v rpmbuild && command -v cargo && echo 'host dependencies: OK'

# 2) Build all three RPMs (output under rpm-build/RPMS/<arch>/)
./scripts/build.sh rpm
# Optional: VERSION=1.0.0 RELEASE=2 ./scripts/build.sh rpm
# Optional: RPM_BUILD_DIR=/tmp/rbs-rpmbuild ./scripts/build.sh rpm

# 3) List what was produced (expect rbs, rbc, rbs-cli)
ARCH_DIR="rpm-build/RPMS/$(uname -m)"
ls -1 "$ARCH_DIR"/*.rpm

# 4) Install packages (choose one method)
# Preferred on hosts with dnf — dependency resolution and signature integration
sudo dnf install -y "$ARCH_DIR"/rbs-*.rpm "$ARCH_DIR"/rbc-*.rpm "$ARCH_DIR"/rbs-cli-*.rpm
# Alternate — plain rpm
# sudo rpm -ivh "$ARCH_DIR"/rbs-*.rpm "$ARCH_DIR"/rbc-*.rpm "$ARCH_DIR"/rbs-cli-*.rpm

# 5) Confirm the daemon — first install runs %post: chown dirs, daemon-reload, enable (every install/upgrade), start (first install only)
sudo systemctl status rbs.service --no-pager
# If you used rpm --noscripts or the unit did not start:
# sudo systemctl daemon-reload && sudo systemctl enable --now rbs.service

# 6) Verification — URL must match rest.listen_addr in /etc/rbs/rbs.yaml (sample often 127.0.0.1:6666)
grep -E '^\s*listen_addr:' /etc/rbs/rbs.yaml || true
curl -sS http://127.0.0.1:6666/rbs/version
rbs-cli -b http://127.0.0.1:6666 version

# 7) Optional — follow service logs while you exercise the API
# sudo journalctl -u rbs.service -f
```

**After install**

- **Config file:** **`/etc/rbs/rbs.yaml`** — edit, then **`sudo systemctl restart rbs.service`**. Packaged defaults that often need attention: **`storage.url`** and **`storage.sql_file_path`** (see [rpm.md#5-configure](rpm.md#5-configure)).
- **Upgrade:** `sudo dnf upgrade "$ARCH_DIR"/*.rpm` **or** `sudo rpm -Uvh "$ARCH_DIR"/*.rpm` — scriptlet behaviour is described in [rpm.md#7-upgrade](rpm.md#7-upgrade).
- **Troubleshooting:** [rpm.md#10-troubleshooting](rpm.md#10-troubleshooting).

## 5. Container: build, run, and test (step-by-step)

**Objective:** produce the **OCI image**, start the stack with **Docker Compose**, then invoke **`/rbs/version`** from the host on **port 8080**. Use **[`deployment/docker/rbs-compose.yaml`](../../deployment/docker/rbs-compose.yaml)**, which defines the service and embeds the RBS runtime config under **`configs.rbs_runtime_yaml.content`** (**`rest.listen_addr: "127.0.0.1:8080"`**) plus **`network_mode: host`** so that bind is reachable from the host on Linux. **`network_mode: host` here is for open-source demonstration or local testing only**—do not treat it as a production networking model; harden ports, networks, and secrets for real deployments. On Docker Desktop (macOS/Windows), host networking differs; switch to bridge mode by editing the embedded **`listen_addr`** to **`0.0.0.0:8080`**, removing **`network_mode: host`**, and adding **`ports: - "127.0.0.1:8080:8080"`** on the service.

**Container engine**

- **Docker** — **Buildx** is required (`docker buildx version`); **`./scripts/build.sh docker`** uses BuildKit.
- **Podman** — set **`CONTAINER_ENGINE=podman`** and invoke **`./scripts/build.sh docker`** (same script entry point).

**Package auto-install (scripts)** — By default helpers **do not** invoke **`sudo`** for missing packages. Set **`ENABLE_AUTO_INSTALL_DEPS=1`** to allow **non-interactive** **`apt-get`** / **`dnf`** installs on supported distros (for example **`docker.io`**, **`moby-engine`**, or **`podman-docker`**). That can conflict with **Docker CE** site standards or change-managed hosts; **production** hosts should install the engine through **your normal channel** first. **`CI=true`** or **`DISABLE_AUTO_INSTALL_DEPS=1`** always forbids auto-install (same as **[§4](#4-rpm-build-install-run-and-test-step-by-step)**).

**Before the first build**

```bash
cd /path/to/globaltrustauthority-rbs
docker buildx version    # required for the Docker code path
docker compose version   # Compose v2 plugin
# Rootful Docker: ensure the daemon is running (e.g. sudo systemctl enable --now docker)
```

**Execution (two terminal sessions)**

```bash
# Terminal A — repository root
./scripts/build.sh docker

# Terminal A (continued) — foreground stack (Ctrl-C terminates the stack)
docker compose -f deployment/docker/rbs-compose.yaml up --build

# Terminal B — Compose uses host networking; embedded config listens on 127.0.0.1:8080
curl -sS http://127.0.0.1:8080/rbs/version
# export RBS_BASE_URL=http://127.0.0.1:8080   # optional: omit -b on rbs-cli
./target/release/rbs-cli -b http://127.0.0.1:8080 version

# Optional — one-off container using the same service definition (host network; Linux; demo/test only)
docker compose -f deployment/docker/rbs-compose.yaml run --rm rbs
```

**Layout reference:** **[`deployment/docker/rbs-compose.yaml`](../../deployment/docker/rbs-compose.yaml)** (Compose stack + embedded **`rbs.yaml`** via **`configs`**, bind-mount **`sqlite_rbs.sql`**, named volume **`rbs-data`** → **`/var/lib/rbs`**). Image: **[`deployment/docker/dockerfile`](../../deployment/docker/dockerfile)**; wrapper: **[`./scripts/build-docker.sh`](../../scripts/build-docker.sh)**.

**Host `curl` to `127.0.0.1:8080`:** the embedded runtime block sets **`rest.listen_addr: "127.0.0.1:8080"`**. Compose uses **`network_mode: host`** so that address is the host loopback on Linux (again: **demo/test convenience**, not a production topology). For **bridge** networking instead, edit **`configs.rbs_runtime_yaml.content`**: set **`listen_addr`** to **`0.0.0.0:8080`**, remove **`network_mode: host`**, and add **`ports: - "127.0.0.1:8080:8080"`** if you only want localhost on the host side.

**After modifying Rust sources** — rebuild the image and, if the same automated coverage as §2 or §3 is required, execute **`./tests/test_all.sh`** on the host. Running the container does not substitute for that test suite.

## 6. Common first-run failures

| Symptom | Likely cause | What to do |
| ------- | ------------ | ----------- |
| **`cargo build` / linker / `cc` not found / OpenSSL** | Missing C toolchain or `-dev` headers | Debian/Ubuntu: **`sudo apt-get install -y build-essential pkg-config libssl-dev`**. dnf: **`sudo dnf install -y gcc gcc-c++ make`** (add **`openssl-devel`** if a crate still cannot find OpenSSL). |
| **`Cargo.lock` requires a newer Cargo** | Distro **`cargo`** older than the workspace lockfile | Install **[rustup](https://rustup.rs/)** stable, **`source ~/.cargo/env`**, re-run **`./scripts/build.sh`**. For Docker builds, the **builder stage** in **`deployment/docker/dockerfile`** must use a Rust/Cargo that accepts the workspace lock (**`Cargo.lock`** uses **`version = 4`**; **`FROM rust:1.88`** is the current baseline—raise the **`FROM`** tag if **`RUN cargo build`** fails in the image). |
| **`docker: command not found` / Buildx missing** | Engine not installed or plugin missing | Install Docker Engine + CLI + Compose v2 + **Buildx** ([install guide](https://docs.docker.com/build/buildx/install/)). Podman users set **`CONTAINER_ENGINE=podman`**. |
| **`curl: Connection refused`** | Host/port does not match **`rest.listen_addr`** | §2/§3 sample YAML → **`127.0.0.1:6666`**. §5 **`rbs-compose.yaml`** (embedded **`listen_addr`**) → **`127.0.0.1:8080`**. Inspect **`configs.rbs_runtime_yaml.content`** in **[`deployment/docker/rbs-compose.yaml`](../../deployment/docker/rbs-compose.yaml)**. |
| **`permission denied` writing logs or DB** | Sample **`rbs/conf/rbs.yaml`** uses privileged paths | Use **`sudo`** for the server **or** edit **`logging.file_path`**, **`storage.url`**, **`storage.sql_file_path`** to directories your user owns. |
| **Node / Redocly errors when running `docs`** | Node below the generator floor | Install **≥ 22.12** (see **`engines`** in [`scripts/conf/openapi-docs/package.json`](../../scripts/conf/openapi-docs/package.json)); use **`nvm`** / **`fnm`** with an optional repo-root **`.nvmrc`**, then **`./scripts/build.sh docs`**. |

## 7. Further reading and tooling

Consult this section when the procedures in §2–§5 are insufficient for your environment.

- **`./scripts/build.sh help`** — documents **`rpm`**, **`docker`**, **`docs`**, **`debug`**, and **`cargo`** argument forwarding (for example **`./scripts/build.sh release --bin rbs`**).
- **Tests** — full matrix, skip flags, and end-to-end driver: **[tests/README.md](../../tests/README.md)**.
- **RPM** — operator and packager reference: **[rpm.md](rpm.md)** (installation, upgrade, **systemd**, signing, **`createrepo_c`**).
- **Generated REST documentation** — **`./scripts/build.sh docs`** (Node.js **≥ 22.12** per **`scripts/conf/openapi-docs/package.json`**; **24** recommended; optional local **`.nvmrc`** is not tracked). Checked-in artefacts: **[`docs/proto/rbs_rest_api.yaml`](../../docs/proto/rbs_rest_api.yaml)** and Markdown/HTML under **`docs/api/rbs/`**.
- **Compose and image sources** — **[`deployment/docker/`](../../deployment/docker/)** (`rbs-compose.yaml`, `dockerfile`).
- **Optional quality gates** — workspace aliases in **[`.cargo/config.toml`](../../.cargo/config.toml)** (`cargo clippy-all`, **`cargo deny-all`**, …) and **[`deny.toml`](../../deny.toml)**; install **`cargo-deny`** before using **`cargo deny-all`**.

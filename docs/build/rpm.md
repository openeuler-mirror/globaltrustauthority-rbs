# globaltrustauthority-rbs RPM Package Guide

This guide covers installing, configuring, upgrading, and removing the workspace RPMs `rbs` (daemon), `rbc` (client), and `rbs-cli` (administration and client CLI), and documents how to build and self-host packages for downstream use. It assumes a systemd-based host with `dnf`. [openEuler 24.03 LTS](https://docs.openeuler.org/en/docs/24.03_LTS/) is the reference distribution: `x86_64` is the primary packaging target, and `aarch64` is supported and pinned by `ExclusiveArch` in each spec. For tarball builds, containers, and API doc generation, see [`build_and_install.md`](build_and_install.md); for a short product overview, see [`README.md`](../../README.md).

Example NEVRAs and file listings match the `Version` and `Release` defaults in [`rpm/`](../../rpm/) (currently `0.1.0` with release `1`). When those spec headers change, refresh the examples here so they stay accurate.

**Draft** — RPM layout, scriptlets, and operator-facing paths are still settling. Treat this as guidance, not a frozen runbook, until packaging is explicitly declared stable.

## Table of contents

- [Overview](#overview)
- [Operator guide](#operator-guide)
  - [1. Obtain packages](#1-obtain-packages)
  - [2. Install](#2-install)
  - [3. Verify](#3-verify)
  - [4. Filesystem layout](#4-filesystem-layout)
  - [5. Configure](#5-configure)
  - [6. Run and observe](#6-run-and-observe)
  - [7. Upgrade](#7-upgrade)
  - [8. Uninstall](#8-uninstall)
  - [9. Security posture](#9-security-posture)
  - [10. Troubleshooting](#10-troubleshooting)
- [Developer guide — building RPMs](#developer-guide--building-rpms)
- [Reference](#reference)
- [Document status](#document-status)

## Overview

Three RPM packages ship from this repository. They share the workspace build but install independently; only `rbs` ships a systemd unit and a runtime user.

### Package matrix

| Package | Binary | Config (`%config(noreplace)`) | systemd unit | `Requires` | Purpose |
| ---- | ---- | ---- | ---- | ---- | ---- |
| `rbs` | `/usr/bin/rbs` | `/etc/rbs/rbs.yaml` | `/usr/lib/systemd/system/rbs.service` | `systemd` | Resource Broker Service daemon |
| `rbc` | `/usr/bin/rbc` | `/etc/rbc/rbc.yaml` | — | — | Resource Broker Client |
| `rbs-cli` | `/usr/bin/rbs-cli` | — | — | — | Admin + client CLI (`rbs-cli admin`, `rbs-cli client`) |

Facts are taken verbatim from [`rpm/rbs.spec`](../../rpm/rbs.spec), [`rpm/rbc.spec`](../../rpm/rbc.spec), [`rpm/rbs-cli.spec`](../../rpm/rbs-cli.spec), and the unit [`service/rbs.service`](../../service/rbs.service).

### Supported platforms

| Arch | Distro | Support | Notes |
| ---- | ---- | ---- | ---- |
| `x86_64` | openEuler 24.03 LTS | **Tested** | Primary packaging target |
| `aarch64` | openEuler 24.03 LTS | **Supported** | Pinned by `ExclusiveArch` in every spec |
| `x86_64` / `aarch64` | Other dnf-based (RHEL 9, Fedora) | Community / untested | Expect to work; no guarantees |
| any | non-RPM distros | Out of scope | Use the container or from-source flow in [`build_and_install.md`](build_and_install.md) |

## Operator guide

Use this section when you **consume** the RPMs. If you need to **build** them, jump to the [Developer guide](#developer-guide--building-rpms).

### 1. Obtain packages

No public `dnf` repository is published yet. Two supported sources:

1. **Release artifacts** — download pre-built `rbs-*.rpm`, `rbc-*.rpm`, and `rbs-cli-*.rpm` from the project repository and copy them to the target host.
2. **Build locally** — see the [Developer guide](#developer-guide--building-rpms); outputs land under `rpm-build/RPMS/<arch>/`.

The commands below assume all three RPM files are in the current working directory.

### 2. Install

Prefer `dnf`: it resolves dependencies, integrates with GPG verification, and is the openEuler default.

```bash
# Recommended — dnf resolves Requires: systemd and handles signatures
sudo dnf install ./rbs-*.rpm ./rbc-*.rpm ./rbs-cli-*.rpm

# Alternate — plain rpm, all three at once
sudo rpm -ivh rbs-*.rpm rbc-*.rpm rbs-cli-*.rpm

# Subset — install only what you need
sudo dnf install ./rbs-*.rpm        # service only
sudo dnf install ./rbc-*.rpm        # client only
sudo dnf install ./rbs-cli-*.rpm    # CLI only
```

For upgrades, see [7. Upgrade](#7-upgrade). Installing the `rbs` package creates the `rbs` system user (`%pre`). In `%post` ([`rpm/rbs.spec`](../../rpm/rbs.spec)), `systemctl enable rbs.service` runs on **every** install or upgrade (idempotent); `systemctl start rbs.service` runs **only on first install** (`$1 -eq 1`).

### 3. Verify

```bash
# Installed NEVRA for each package (fails if any is missing)
rpm -q rbs rbc rbs-cli

# Packages registered in the RPM DB (^rbs matches rbs and rbs-cli; ^rbc matches rbc)
rpm -qa | grep -E '^(rbs|rbc)'

# Binaries on PATH
command -v rbs rbc rbs-cli

# Service active (rbs package only)
systemctl is-enabled rbs.service
systemctl is-active  rbs.service

# Config files present
test -f /etc/rbs/rbs.yaml && echo 'rbs.yaml OK'
test -f /etc/rbc/rbc.yaml && echo 'rbc.yaml OK'

# Runtime user created
id rbs
```

### 4. Filesystem layout

Every path below is created by the specs or by install-time scriptlets. Nothing else is written until the service runs.

| Path | Owner:Group | Mode | Managed by | Notes |
| ---- | ---- | ---- | ---- | ---- |
| `/usr/bin/rbs` | `root:root` | `0755` | `rbs` spec `%files` | Daemon binary |
| `/usr/bin/rbc` | `root:root` | `0755` | `rbc` spec `%files` | Client binary |
| `/usr/bin/rbs-cli` | `root:root` | `0755` | `rbs-cli` spec `%files` | Admin + client CLI |
| `/etc/rbs/rbs.yaml` | `root:root` | `0644` | `rbs` spec `%files %config(noreplace)` | Edits survive upgrade; see [7. Upgrade](#7-upgrade) |
| `/etc/rbc/rbc.yaml` | `root:root` | `0644` | `rbc` spec `%files %config(noreplace)` | Edits survive upgrade |
| `/usr/lib/systemd/system/rbs.service` | `root:root` | `0644` | `rbs` spec `%files` | Unit source of truth; do not edit in place |
| `/usr/share/rbs/sqlite_rbs.sql` | `root:root` | `0644` | `rbs` spec `%files` | SQLite bootstrap from `rbs/conf/sqlite_rbs.sql`; read at startup per `storage.sql_file_path` |
| `/var/lib/rbs` | `rbs:rbs` | `0755` | `rbs` spec `%files %dir`, chowned in `%post` | Service state; **not** removed on uninstall |
| `/var/log/rbs` | `rbs:rbs` | `0755` | `rbs` spec `%files %dir`, chowned in `%post` | Log directory; **not** removed on uninstall |
| `rbs` user / group | system account, shell `/sbin/nologin`, home `/var/lib/rbs` | — | `rbs` spec `%pre` | **Not** removed on uninstall |

### 5. Configure

The unit sets `Environment=RBS_CONFIG=/etc/rbs/rbs.yaml`, so `rbs` reads that path by default. `rbc` reads `/etc/rbc/rbc.yaml`. Both are declared `%config(noreplace)`, so your edits survive upgrades.

Keys that matter for a packaged install (full schema in the tree: [`rbs/conf/rbs.yaml`](../../rbs/conf/rbs.yaml)). Dot notation maps table keys to YAML: `rest.listen_addr` is `listen_addr` under `rest:`; `storage.url` and `storage.sql_file_path` are the `url` and `sql_file_path` keys under `storage:`.

The **`rbs` RPM** copies [`rbs/conf/rbs.yaml`](../../rbs/conf/rbs.yaml) into `/etc/rbs/rbs.yaml` at **package build time**, then applies two **`sed`** edits in [`rpm/rbs.spec`](../../rpm/rbs.spec) so a **fresh** install matches the packaged layout: **`storage.url`** becomes **`sqlite:///var/lib/rbs/rbs.db`** and **`storage.sql_file_path`** becomes **`/usr/share/rbs/sqlite_rbs.sql`**. The SQL file is installed from [`rbs/conf/sqlite_rbs.sql`](../../rbs/conf/sqlite_rbs.sql) as **`/usr/share/rbs/sqlite_rbs.sql`** (`root:root`, `0644`). If you keep an **older edited** `%config(noreplace)` file across upgrades, merge these keys from **`*.rpmnew`** or align them manually. If the **source** YAML changes the exact `storage.url` / `storage.sql_file_path` lines, update the **`sed`** patterns in the spec so the packaged file still transforms correctly.

| Key | Packaged default (fresh install) | Notes |
| ---- | ---- | ---- |
| `rest.listen_addr` | `127.0.0.1:6666` | Set to `0.0.0.0:<port>` to expose; update firewall too |
| `rest.https.enabled` | `false` | Flip to `true` plus `cert_file` / `key_file` before exposing |
| `logging.file_path` | `/var/log/rbs/rbs.log` | Directory is pre-created with the correct owner |
| `logging.enable_rotation` | `true` | See `rotation.*` block for caps |
| `storage.url` | `sqlite:///var/lib/rbs/rbs.db` | Set at **package build** from the tree default `sqlite:///root/rbs.db` |
| `storage.sql_file_path` | `/usr/share/rbs/sqlite_rbs.sql` | Schema shipped by the `rbs` RPM; override if you supply your own SQL bootstrap |

Apply changes:

```bash
sudo vi /etc/rbs/rbs.yaml
sudo systemctl restart rbs.service
```

The unit does not define `ExecReload`; use `restart` rather than `reload`.

### 6. Run and observe

| Operation | Command |
| ---- | ---- |
| Start | `sudo systemctl start rbs.service` |
| Stop | `sudo systemctl stop rbs.service` |
| Restart | `sudo systemctl restart rbs.service` |
| Try-restart (no-op if stopped) | `sudo systemctl try-restart rbs.service` |
| Enable at boot | `sudo systemctl enable rbs.service` |
| Disable at boot | `sudo systemctl disable rbs.service` |
| Status | `sudo systemctl status rbs.service --no-pager` |

Logs go to **journald** (`StandardOutput=journal`, `StandardError=journal`, `SyslogIdentifier=rbs`) and, in parallel, to the file path set by `logging.file_path`:

```bash
# Last 50 lines
sudo journalctl -u rbs.service -n 50

# Follow live
sudo journalctl -u rbs.service -f

# Errors only, since today
sudo journalctl -u rbs.service -p err --since today

# Tail the file logger
sudo tail -F /var/log/rbs/rbs.log
```

Smoke-test against the live service (match `rest.listen_addr`):

```bash
curl -sS http://127.0.0.1:6666/rbs/version
rbs-cli -b http://127.0.0.1:6666 version
```

### 7. Upgrade

```bash
sudo dnf upgrade ./rbs-*.rpm ./rbc-*.rpm ./rbs-cli-*.rpm
# or
sudo rpm -Uvh rbs-*.rpm rbc-*.rpm rbs-cli-*.rpm
```

What the scriptlets in [`rpm/rbs.spec`](../../rpm/rbs.spec) do:

- `%preun` is **not** triggered on upgrade (`if [ $1 -eq 0 ]`), so the service is **not** stopped or disabled mid-upgrade.
- `%postun` runs `systemctl daemon-reload` and then `systemctl try-restart rbs.service` when `$1 -ge 1`, so a running service picks up the new binary automatically.
- Both yaml configs are `%config(noreplace)`:
  - **Unedited** file → replaced with the new vendor default.
  - **Edited** file → your copy is kept; the new vendor default is written as `*.rpmnew` next to it. Diff and merge manually, then restart the service.

Look for pending merges after every upgrade:

```bash
sudo find /etc/rbs /etc/rbc \( -name '*.rpmnew' -o -name '*.rpmsave' -o -name '*.rpmorig' \) 2>/dev/null
```

### 8. Uninstall

```bash
# All packages
sudo dnf remove rbs rbc rbs-cli
# or
sudo rpm -e rbs rbc rbs-cli

# Just the service (leave rbc / rbs-cli alone)
sudo dnf remove rbs
```

What stays behind by design — uninstalling must not destroy data:

- `/var/lib/rbs` (database, state) and `/var/log/rbs` (history) remain on disk.
- The `rbs` user and group remain.
- An edited `rbs.yaml` / `rbc.yaml` is saved as `*.rpmsave` before removal (a side-effect of `%config(noreplace)` plus prior edits); an unedited config is removed cleanly.

Fully purge after `rpm -e`:

```bash
sudo rm -rf /var/lib/rbs /var/log/rbs
sudo userdel rbs && sudo groupdel rbs 2>/dev/null || true
sudo rm -f /etc/rbs/rbs.yaml.rpmsave /etc/rbc/rbc.yaml.rpmsave
```

### 9. Security posture

RBS runs as a dedicated system user with a hardened systemd unit.

**Runtime identity** (created in `%pre` of [`rpm/rbs.spec`](../../rpm/rbs.spec)):

- User `rbs` / group `rbs`, shell `/sbin/nologin`, home `/var/lib/rbs`, system account (no password, no login).

**Systemd hardening** from [`service/rbs.service`](../../service/rbs.service):

| Directive | Value | Effect |
| ---- | ---- | ---- |
| `User` / `Group` | `rbs` / `rbs` | Drops root before `ExecStart` |
| `UMask` | `0027` | New files default to `0640` (group-readable to `rbs` only) |
| `NoNewPrivileges` | `true` | `setuid` and file capabilities cannot escalate child processes |
| `PrivateTmp` | `true` | Per-invocation private `/tmp` and `/var/tmp` |
| `ProtectSystem` | `strict` | Whole filesystem mounted read-only except `ReadWritePaths` and `/dev` |
| `ProtectHome` | `true` | `/home`, `/root`, `/run/user` are invisible |
| `ReadWritePaths` | `/var/lib/rbs /var/log/rbs` | The only writable paths |
| `LimitNOFILE` | `65536` | File-descriptor ceiling |
| `Restart` / `RestartSec` | `always` / `10 s` | Crash-loop with back-off; pair with systemd `StartLimit*` if you need a cap |

**SELinux**: RBS ships **no custom SELinux policy**; on enforcing hosts it runs in the default service domain. If the daemon fails to write `/var/log/rbs` or bind a port, inspect `ausearch -m avc -ts recent` and run `restorecon -Rv /var/lib/rbs /var/log/rbs`. A restricted domain is future work.

**Network exposure**: the packaged default `rest.listen_addr` is `127.0.0.1:6666` (localhost only). Before exposing the service:

1. Set `rest.listen_addr: "0.0.0.0:<port>"` in `/etc/rbs/rbs.yaml`.
2. Enable TLS — set `rest.https.enabled: true` and point `cert_file` / `key_file` at PEM files.
3. Open the firewall — for example `sudo firewall-cmd --add-port=6666/tcp --permanent && sudo firewall-cmd --reload`.

### 10. Troubleshooting

| Symptom | First check | Fix |
| ---- | ---- | ---- |
| `Requires: systemd` not satisfied | `rpm -qpR rbs-*.rpm` | Install on a real systemd host; minimal container bases need `dnf install systemd` first |
| `Permission denied` during `rpm -ivh` | `whoami` | Re-run with `sudo` |
| `systemctl status rbs.service` shows `failed` | `sudo journalctl -u rbs.service -n 100 --no-pager` | Fix the path or value the log points at, then `sudo systemctl restart rbs.service` |
| `Unit rbs.service could not be found` | `rpm -ql rbs` | `sudo systemctl daemon-reload` (the `%post` scriptlet does this, but a manual file copy may have skipped it) |
| Service exits with `Permission denied` writing logs | `ls -ld /var/log/rbs` | `sudo chown -R rbs:rbs /var/log/rbs && sudo chmod 0755 /var/log/rbs` |
| `Address already in use` | `sudo ss -ltnp 'sport = :<port>'` | Change `rest.listen_addr` or free the port |
| Service flaps (restarts every 10 s) | `sudo journalctl -u rbs.service -p err -n 200` | Almost always a config error; validate YAML and the paths in `logging.file_path` / `storage.*` |
| Edited config seems ignored after upgrade | `ls /etc/rbs/*.rpmnew /etc/rbc/*.rpmnew` | Merge `*.rpmnew` back into the live config, then `sudo systemctl restart rbs.service` |
| `id rbs` prints nothing after install | `grep ^rbs: /etc/passwd` | `%pre` failed; inspect with `rpm -q --scripts rbs` and re-run the `groupadd`/`useradd` lines manually |

Canonical diagnostic commands — keep these bookmarked:

```bash
sudo journalctl -u rbs.service --since '15 min ago'   # recent service log
rpm -qi rbs                                           # installed package info
rpm -qlp rbs-*.rpm                                    # files a package would install
rpm -qpR rbs-*.rpm                                    # declared dependencies
rpm -V rbs                                            # verify installed files against the package
rpm -q --scripts rbs                                  # view %pre / %post / ... as installed
```

## Developer guide — building RPMs

This section is for contributors and downstream packagers. End users should read the [Operator guide](#operator-guide).

### 1. Prerequisites

Build host: any dnf-based Linux (openEuler 24.03 LTS is the primary target).

```bash
# RPM build toolchain + C toolchain
sudo dnf install -y rpm-build rpmdevtools gcc gcc-c++ make

# Rust (rustup recommended so the toolchain matches the workspace Cargo.lock)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version && cargo --version
```

The same package names apply on other dnf-based distros (RHEL 9, Fedora). Building RPMs does **not** need Node.js or npm; those are only for `./scripts/build.sh docs`, documented in [`build_and_install.md`](build_and_install.md).

### 2. Quick build

```bash
./scripts/build.sh rpm
# Equivalent:
./scripts/build-rpm.sh
```

What this does:
1. Ensures `cargo`, `rpmbuild`, and the C toolchain are present (auto-install is off by default; set `ENABLE_AUTO_INSTALL_DEPS=1` on supported distros to allow `sudo` installs when something is missing; `CI=true` or `DISABLE_AUTO_INSTALL_DEPS=1` always forbids).
2. Runs `cargo build --release` in the workspace.
3. Calls `rpmbuild -bb rpm/<pkg>.spec` for all three packages.
4. Writes outputs under `rpm-build/RPMS/<arch>/` — `<arch>` is `x86_64` or `aarch64`.

Expected output:

```
rpm-build/RPMS/x86_64/                # aarch64/ on ARM hosts
├── rbs-0.1.0-1.x86_64.rpm
├── rbc-0.1.0-1.x86_64.rpm
└── rbs-cli-0.1.0-1.x86_64.rpm
```

### 3. Versioning and release

Override the RPM `Version` / `Release` tags without editing specs:

```bash
VERSION=1.0.0 RELEASE=2 ./scripts/build.sh rpm
```

Defaults: `VERSION=0.1.0`, `RELEASE=1`. Use `RELEASE` to encode downstream rebuilds (`1.oe2403`, `2`), matching distro conventions. The specs read both via `%define` overrides in [`scripts/build-rpm.sh`](../../scripts/build-rpm.sh).

### 4. Manual rpmbuild

For packagers reproducing individual calls (for example in COPR or OBS):

```bash
cargo build --release

for spec in rbs rbc rbs-cli; do
  rpmbuild -bb rpm/${spec}.spec \
    --define "_topdir $(pwd)/rpm-build" \
    --define "_project_root $(pwd)" \
    --define "version 0.1.0" \
    --define "release 1" \
    --buildroot "$(pwd)/rpm-build/BUILDROOT"
done
```

`_project_root` is a project-local macro: the specs `cd %{_project_root}` in `%build` and `%install` because the source tree is used in place (no `%prep` tarball extraction). It must be an absolute path to the workspace root.

### 5. Source RPM (SRPM)

```bash
rpmbuild -bs rpm/rbs.spec \
  --define "_topdir $(pwd)/rpm-build" \
  --define "_project_root $(pwd)" \
  --define "version 0.1.0" \
  --define "release 1"
```

Use SRPMs when you need to rebuild on a different host (COPR, OBS, a chroot pipeline) without shipping the full source tree.

### 6. Cross-architecture builds

| Host arch | Target arch | Recommended method |
| ---- | ---- | ---- |
| `x86_64` | `x86_64` | Native `./scripts/build.sh rpm` |
| `aarch64` | `aarch64` | Native `./scripts/build.sh rpm` |
| `x86_64` | `aarch64` | Cross-compile Rust (`cargo build --target aarch64-unknown-linux-gnu --release`), then `rpmbuild` inside a `qemu-user-static` chroot — or use a native `aarch64` runner |
| `aarch64` | `x86_64` | Mirror of the row above |

Every spec pins `ExclusiveArch: x86_64 aarch64`; do not build for other architectures without updating the specs first.

### 7. Spec file reference

All three specs live under [`rpm/`](../../rpm/) and follow the same skeleton.

| Section | Behavior | Where to look |
| ---- | ---- | ---- |
| `%define` header | Version, release, name defaults (overridden by `--define`) | top of each spec |
| `ExclusiveArch` | `x86_64 aarch64` only | header |
| `%prep` | No-op; source is used in place via `_project_root` | `rpm/*.spec` |
| `%build` | `cd %{_project_root} && cargo build --release` | `rpm/*.spec` |
| `%install` | `install -D` for binaries / configs / unit / `%{_datadir}/rbs/sqlite_rbs.sql`; `sed` on packaged `/etc/rbs/rbs.yaml` for `storage.*`; `install -d` for state and log dirs | `rpm/rbs.spec` has the most lines |
| `%pre` (rbs only) | `groupadd -r rbs` + `useradd -r -g rbs -d /var/lib/rbs -s /sbin/nologin` | `rpm/rbs.spec` |
| `%post` (rbs only) | `chown` state and log dirs, `daemon-reload`, `enable` on every install/upgrade; `start` only on first install (`$1 -eq 1`) | `rpm/rbs.spec` |
| `%preun` (rbs only) | Stop + disable **only on uninstall** (`$1 -eq 0`); no-op on upgrade | `rpm/rbs.spec` |
| `%postun` (rbs only) | `daemon-reload` always; `try-restart` on upgrade (`$1 -ge 1`) | `rpm/rbs.spec` |
| `%files` | Marks `%config(noreplace)` for yaml configs; `%dir` for state and log dirs | `rpm/rbs.spec`, `rpm/rbc.spec` |
| `%changelog` | Manual RPM changelog entries | bottom of each spec |

### 8. Signing and local dnf repo distribution

**Sign** (optional but recommended for production):

1. Create or reuse a GPG key for RPM signing. Interactive: `gpg --full-generate-key`. Non-interactive / CI: use a parameter file with `gpg --batch --gen-key keygen-params.txt` (see `gpg(1)`); `gpg --batch --gen-key` alone is not reliable without that file.
2. Export the **public** key to a path you will publish and reference from `.repo` files, for example:

```bash
# Replace KEY_ID with the signing key fingerprint or UID string from gpg -K
gpg --armor --export KEY_ID | sudo tee /etc/pki/rpm-gpg/RBS-RELEASE-KEY.asc >/dev/null
sudo chmod 644 /etc/pki/rpm-gpg/RBS-RELEASE-KEY.asc
```

3. Point RPM at the key and sign the built packages:

```bash
echo '%_signature gpg'                         >> ~/.rpmmacros
echo '%_gpg_name Your Signing Key <you@example>' >> ~/.rpmmacros

rpm --addsign rpm-build/RPMS/*/*.rpm
rpm --checksig rpm-build/RPMS/*/rbs-*.rpm
```

**Publish** to a local dnf repository (covers air-gapped installs and mirrors):

```bash
sudo dnf install -y createrepo_c

REPO=/srv/rbs-repo
sudo mkdir -p "$REPO"
sudo cp rpm-build/RPMS/*/*.rpm "$REPO/"
sudo createrepo_c "$REPO"
# Re-run after every new upload: sudo createrepo_c --update "$REPO"
```

Consume on client hosts:

```bash
sudo tee /etc/yum.repos.d/rbs.repo <<'EOF'
[rbs]
name=globaltrustauthority-rbs
baseurl=file:///srv/rbs-repo           # or https://<host>/rbs-repo
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RBS-RELEASE-KEY.asc
EOF

sudo dnf install rbs rbc rbs-cli
```

No public upstream dnf repository exists yet; self-host until one is announced.

### 9. Reproducibility and CI notes

- Pin `VERSION` and `RELEASE` from CI metadata (git tag, build number) rather than leaving the defaults.
- Export `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)` before `rpmbuild` for reproducible mtimes.
- `Cargo.lock` is committed; `cargo build --release` must not regenerate it in CI.
- Keep the CI builder image pinned to the openEuler major listed in [Supported platforms](#supported-platforms) so `ExclusiveArch` and library versions stay aligned.

## Reference

### External references

- openEuler — [Building an RPM Package](https://docs.openeuler.org/en/docs/24.03_LTS/docs/ApplicationDev/building-an-rpm-package.html) (openEuler 24.03 LTS).
- openEuler — [Service Management](https://docs.openeuler.org/en/docs/24.03_LTS/docs/Administration/service-management.html) (systemd units, `systemctl`).
- rpm.org — [RPM Packaging Guide](https://rpm-software-management.github.io/rpm/manual/) and the spec-file [reference](https://rpm-software-management.github.io/rpm/manual/spec.html).
- Fedora — [Packaging Guidelines](https://docs.fedoraproject.org/en-US/packaging-guidelines/) and [Scriptlets](https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/).
- systemd — [`systemd.exec(5)`](https://www.freedesktop.org/software/systemd/man/systemd.exec.html) for hardening directives.
- Rust — [Cargo Book](https://doc.rust-lang.org/cargo/).

### In-tree files this guide points at

- [`rpm/rbs.spec`](../../rpm/rbs.spec), [`rpm/rbc.spec`](../../rpm/rbc.spec), [`rpm/rbs-cli.spec`](../../rpm/rbs-cli.spec) — package definitions.
- [`service/rbs.service`](../../service/rbs.service) — systemd unit.
- [`rbs/conf/rbs.yaml`](../../rbs/conf/rbs.yaml), [`rbc/conf/rbc.yaml`](../../rbc/conf/rbc.yaml) — default configs installed to `/etc`.
- [`scripts/build.sh`](../../scripts/build.sh), [`scripts/build-rpm.sh`](../../scripts/build-rpm.sh) — entry points for the RPM flow.

### Getting help

- **Issue tracker**: open the Issues tab from the repository home page you use (primary mirror: [GitCode — globaltrustauthority-rbs](https://gitcode.com/openeuler/globaltrustauthority-rbs)).
- **Companion docs**: [`build_and_install.md`](build_and_install.md) (from-source, container, docs) and [`README.md`](../../README.md) (project overview).

## Document status

Same **draft** stance as the [introduction](#globaltrustauthority-rbs-rpm-package-guide): scope and scriptlets may change before RPMs are declared stable for production. When releases ship, keep example NEVRAs and version mentions aligned with [`rpm/*.spec`](../../rpm/). A project-wide `CHANGELOG.md` does not yet exist; when it does, link it from this section.

---

**Status**: Draft (no formal document version or changelog yet)
